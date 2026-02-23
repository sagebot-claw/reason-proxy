package proxy

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"

	"github.com/elazarl/goproxy"
	"github.com/sagebot-claw/reason-proxy/db"
	"github.com/sagebot-claw/reason-proxy/policy"
)

// Server encapsulates the proxy server logic
type Server struct {
	*goproxy.ProxyHttpServer
	DB     *db.DB
	Config *policy.Config // Renamed from Policy to match struct
}

// New creates a new Proxy Server instance
func New(database *db.DB, cfg *policy.Config, caCertPath, caKeyPath string, verbose bool) (*Server, error) {
	// CA handling
	var ca tls.Certificate
	var err error

	// Check if cert/key exist, if not generate
	if _, err := os.Stat(caCertPath); os.IsNotExist(err) {
		if err := GenerateCA(caCertPath, caKeyPath); err != nil {
			return nil, fmt.Errorf("failed to generate CA: %w", err)
		}
	}
	
	ca, err = tls.LoadX509KeyPair(caCertPath, caKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load CA: %w", err)
	}
	
	// Just verify the cert parses
	if _, err := x509.ParseCertificate(ca.Certificate[0]); err != nil {
		return nil, err
	}

	p := goproxy.NewProxyHttpServer()
	p.Verbose = verbose

	// MITM Config
	goproxy.GoproxyCa = ca
	goproxy.OkConnect = &goproxy.ConnectAction{Action: goproxy.ConnectMitm, TLSConfig: goproxy.TLSConfigFromCA(&ca)}
	goproxy.MitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectMitm, TLSConfig: goproxy.TLSConfigFromCA(&ca)}
	goproxy.HTTPMitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectMitm, TLSConfig: goproxy.TLSConfigFromCA(&ca)}
	goproxy.RejectConnect = &goproxy.ConnectAction{Action: goproxy.ConnectReject, TLSConfig: goproxy.TLSConfigFromCA(&ca)}

	// Handle all HTTPS
	p.OnRequest().HandleConnect(goproxy.AlwaysMitm)

	srv := &Server{
		ProxyHttpServer: p,
		DB:              database,
		Config:          cfg,
	}

	p.OnRequest().DoFunc(srv.handleRequest)
	p.OnResponse().DoFunc(srv.handleResponse)

	return srv, nil
}

func (s *Server) handleRequest(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)
	reason := r.Header.Get("X-Reason")

	// Read Body
	var bodyBytes []byte
	if r.Body != nil {
		bodyBytes, _ = io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
	}

	// 1. Policy Check (Host)
	class := s.Config.Classify(r.URL.Host)
	action := s.Config.Decide(class)
	
	// If DENY, reject immediately
	if action == policy.ActionDeny {
		return r, goproxy.NewResponse(r,
			goproxy.ContentTypeText, http.StatusForbidden,
			"Proxy Policy: Host is DENIED by configuration.")
	}

	// 2. Log Intent
	logID, _ := s.DB.LogRequest(clientIP, r.Method, r.URL.String(), r.Host, reason, fmt.Sprintf("%v", r.Header), bodyBytes)
	ctx.UserData = map[string]interface{}{
		"logID":  logID,
		"action": action, // Pass ActionEvaluate or ActionAllow
	}

	// 3. Enforce X-Reason
	if reason == "" {
		s.DB.UpdateAction(logID, "DENY", "Missing X-Reason")
		return r, goproxy.NewResponse(r,
			goproxy.ContentTypeText, http.StatusBadRequest,
			"Proxy Error: Missing required 'X-Reason' header. Explain your intent.")
	}

	return r, nil
}

func (s *Server) handleResponse(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
	if ctx.UserData == nil {
		return resp
	}
	
	data := ctx.UserData.(map[string]interface{})
	logID := data["logID"].(int64)
	policyAction := data["action"].(policy.Action)

	var bodyBytes []byte
	if resp.Body != nil {
		bodyBytes, _ = io.ReadAll(resp.Body)
		resp.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
	}

	// 4. Keyword Check (if ActionEvaluate)
	if policyAction == policy.ActionEvaluate {
		safe, keyword := s.Config.EvaluateResponse(bodyBytes)
		if !safe {
			s.DB.UpdateAction(logID, "BLOCK", fmt.Sprintf("Keyword Violation: %s", keyword))
			return goproxy.NewResponse(resp.Request,
				goproxy.ContentTypeText, http.StatusForbidden,
				fmt.Sprintf("Proxy Policy: Response blocked due to sensitive keyword: %s", keyword))
		}
	}

	// Log Success
	s.DB.LogResponse(logID, resp.StatusCode, fmt.Sprintf("%v", resp.Header), bodyBytes)
	
	return resp
}
