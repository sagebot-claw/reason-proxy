package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/elazarl/goproxy"
	_ "modernc.org/sqlite"
)

var (
	port     = flag.String("port", "8080", "Port to listen on")
	caCert   = flag.String("ca-cert", "ca.pem", "Path to CA certificate")
	caKey    = flag.String("ca-key", "ca.key", "Path to CA private key")
	dbPath   = flag.String("db", "audit.db", "Path to SQLite database")
	verbose  = flag.Bool("v", false, "Verbose logging to stdout")
)

var db *sql.DB

func main() {
	flag.Parse()

	// 1. Initialize SQLite
	initDB()
	defer db.Close()

	// 2. Setup MITM CA
	setCA(*caCert, *caKey)

	// 3. Configure Proxy
	proxy := goproxy.NewProxyHttpServer()
	proxy.Verbose = *verbose

	// Intercept all HTTPS traffic
	proxy.OnRequest().HandleConnect(goproxy.AlwaysMitm)

	// Intercept Requests (The "Reason" Check)
	proxy.OnRequest().DoFunc(func(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)
		reason := r.Header.Get("X-Reason")

		// Read Body (Nondestructively)
		var bodyBytes []byte
		if r.Body != nil {
			bodyBytes, _ = io.ReadAll(r.Body)
			r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		}

		// Log Request
		logID := logRequest(clientIP, r.Method, r.URL.String(), r.Host, reason, r.Header, bodyBytes)
		ctx.UserData = logID

		// Enforce Header
		if reason == "" {
			// We reject here.
			// Note: For HTTPS, this happens inside the tunnel.
			updateAction(logID, "DENY", "Missing X-Reason")
			return r, goproxy.NewResponse(r,
				goproxy.ContentTypeText, http.StatusBadRequest,
				"Proxy Error: Missing required 'X-Reason' header. Explain your intent.")
		}

		return r, nil
	})

	// Intercept Responses (Log payload)
	proxy.OnResponse().DoFunc(func(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
		if ctx.UserData != nil {
			logID := ctx.UserData.(int64)
			var bodyBytes []byte
			if resp.Body != nil {
				bodyBytes, _ = io.ReadAll(resp.Body)
				resp.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
			}
			logResponse(logID, resp.StatusCode, resp.Header, bodyBytes)
		}
		return resp
	})

	log.Printf("Reason Proxy (MITM) started on :%s", *port)
	log.Fatal(http.ListenAndServe(":"+*port, proxy))
}

// --- Database Logic ---

func initDB() {
	var err error
	db, err = sql.Open("sqlite", *dbPath)
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}

	schema := `
	CREATE TABLE IF NOT EXISTS audit_log (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
		client_ip TEXT,
		method TEXT,
		url TEXT,
		host TEXT,
		reason TEXT,
		req_headers TEXT,
		req_body BLOB,
		resp_status INTEGER,
		resp_headers TEXT,
		resp_body BLOB,
		action TEXT,
		error TEXT
	);
	`
	if _, err := db.Exec(schema); err != nil {
		log.Fatalf("Failed to create schema: %v", err)
	}
}

func logRequest(ip, method, url, host, reason string, headers http.Header, body []byte) int64 {
	// Truncate
	if len(body) > 4096 { body = body[:4096] }
	
	res, err := db.Exec(`
		INSERT INTO audit_log (client_ip, method, url, host, reason, req_headers, req_body, action)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`, ip, method, url, host, reason, fmt.Sprintf("%v", headers), body, "PENDING")

	if err != nil {
		log.Printf("DB Log Error: %v", err)
		return 0
	}
	id, _ := res.LastInsertId()
	return id
}

func logResponse(id int64, status int, headers http.Header, body []byte) {
	if len(body) > 4096 { body = body[:4096] }
	
	_, err := db.Exec(`
		UPDATE audit_log 
		SET resp_status = ?, resp_headers = ?, resp_body = ?, action = 'ALLOW'
		WHERE id = ?
	`, status, fmt.Sprintf("%v", headers), body, id)
	
	if err != nil {
		log.Printf("DB Update Error: %v", err)
	}
}

func updateAction(id int64, action, errorMsg string) {
	db.Exec("UPDATE audit_log SET action = ?, error = ? WHERE id = ?", action, errorMsg, id)
}

// --- CA / Certificate Logic ---

func setCA(certFile, keyFile string) {
	// Check if files exist
	if _, err := os.Stat(certFile); os.IsNotExist(err) {
		log.Printf("Generating new CA certificate: %s", certFile)
		genCA(certFile, keyFile)
	}

	// Load them into goproxy
	tlsCert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Fatalf("Failed to load CA: %v", err)
	}
	
	x509Cert, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		log.Fatalf("Failed to parse CA: %v", err)
	}

	goproxy.GoproxyCa = tlsCert
	goproxy.OkConnect = &goproxy.ConnectAction{Action: goproxy.ConnectMitm, TLSConfig: goproxy.TLSConfigFromCA(&tlsCert)}
	goproxy.MitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectMitm, TLSConfig: goproxy.TLSConfigFromCA(&tlsCert)}
	goproxy.HTTPMitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectMitm, TLSConfig: goproxy.TLSConfigFromCA(&tlsCert)}
	goproxy.RejectConnect = &goproxy.ConnectAction{Action: goproxy.ConnectReject, TLSConfig: goproxy.TLSConfigFromCA(&tlsCert)}
}

func genCA(certFile, keyFile string) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Reason Proxy CA"},
			CommonName:   "Reason Proxy Root CA",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(365 * 24 * 10 * time.Hour), // 10 years

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		log.Fatal(err)
	}

	certOut, _ := os.Create(certFile)
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	certOut.Close()

	keyOut, _ := os.Create(keyFile)
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	keyOut.Close()
}
