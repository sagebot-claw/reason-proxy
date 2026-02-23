package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// LogEntry structure for structured JSON output
type LogEntry struct {
	Time   string `json:"time"`
	SrcIP  string `json:"src_ip,omitempty"`
	Method string `json:"method"`
	URL    string `json:"url"`
	Reason string `json:"reason,omitempty"`
	Action string `json:"action"` // "ALLOW" or "DENY"
	Error  string `json:"error,omitempty"`
}

var (
	port = flag.String("port", "8080", "Port to listen on")
)

func main() {
	flag.Parse()

	// Logger setup
	log.SetOutput(os.Stdout)

	server := &http.Server{
		Addr:    ":" + *port,
		Handler: http.HandlerFunc(handleRequest),
	}

	fmt.Printf("Reason Proxy started on :%s\n", *port)
	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

func handleRequest(w http.ResponseWriter, r *http.Request) {
	clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)

	// 1. Extract Reason
	reason := r.Header.Get("X-Reason")

	// 2. Validate Reason
	if reason == "" {
		logJSON(clientIP, r.Method, r.URL.String(), "", "DENY", "Missing X-Reason header")
		http.Error(w, "Proxy Error: Missing required 'X-Reason' header. Explain your intent.", http.StatusBadRequest)
		return
	}

	// 3. Log Intent (ALLOW)
	logJSON(clientIP, r.Method, r.URL.String(), reason, "ALLOW", "")

	// 4. Handle Tunnel (CONNECT) vs Standard Proxy
	if r.Method == http.MethodConnect {
		handleTunnel(w, r)
	} else {
		handleHTTP(w, r)
	}
}

func handleTunnel(w http.ResponseWriter, r *http.Request) {
	destConn, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
	if err != nil {
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
		return
	}
	
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		destConn.Close()
		return
	}
	
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, "Hijacking failed", http.StatusServiceUnavailable)
		destConn.Close()
		return
	}

	// Send 200 Connection Established to client
	// Note: We write directly to the connection because we hijacked it
	_, err = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	if err != nil {
		clientConn.Close()
		destConn.Close()
		return
	}

	// Bidirectional copy
	go transfer(destConn, clientConn)
	go transfer(clientConn, destConn)
}

func handleHTTP(w http.ResponseWriter, r *http.Request) {
	// Standard HTTP Proxying
	// Create a new request to the target
	
	// r.RequestURI is raw. r.URL is parsed.
	// For proxy requests, r.URL.Scheme and r.URL.Host should be set.
	targetURL := r.URL.String()
	if !strings.HasPrefix(targetURL, "http") {
		// If it's just a path, it might be a direct request to the proxy (not proxying)
		// Or it could be malformed. Assume HTTP if scheme missing.
		targetURL = "http://" + r.Host + r.URL.Path
	}

	req, err := http.NewRequest(r.Method, targetURL, r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Copy headers
	for k, vv := range r.Header {
		if k == "Proxy-Connection" { continue } // Strip hop-by-hop
		for _, v := range vv {
			req.Header.Add(k, v)
		}
	}

	// Forward Request
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: 30 * time.Second,
	}
	
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Copy response headers
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	
	// Copy response body
	io.Copy(w, resp.Body)
}

func transfer(destination io.WriteCloser, source io.ReadCloser) {
	defer destination.Close()
	defer source.Close()
	io.Copy(destination, source)
}

func logJSON(src, method, url, reason, action, errorMsg string) {
	entry := LogEntry{
		Time:   time.Now().Format(time.RFC3339),
		SrcIP:  src,
		Method: method,
		URL:    url,
		Reason: reason,
		Action: action,
		Error:  errorMsg,
	}
	b, _ := json.Marshal(entry)
	fmt.Println(string(b))
}
