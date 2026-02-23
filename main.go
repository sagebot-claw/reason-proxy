package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/sagebot-claw/reason-proxy/admin"
	"github.com/sagebot-claw/reason-proxy/db"
	"github.com/sagebot-claw/reason-proxy/policy"
	"github.com/sagebot-claw/reason-proxy/proxy"
)

var (
	port      = flag.String("port", "8080", "Port to listen on")
	adminPort = flag.String("admin-port", "8081", "Port for admin interface")
	caCert    = flag.String("ca-cert", "ca.pem", "Path to CA certificate")
	caKey     = flag.String("ca-key", "ca.key", "Path to CA private key")
	dbPath    = flag.String("db", "audit.db", "Path to SQLite database")
	config    = flag.String("config", "policy.yaml", "Path to policy configuration file")
	verbose   = flag.Bool("v", false, "Verbose logging to stdout")
)

func main() {
	flag.Parse()

	// Setup Graceful Shutdown Context
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Initialize DB
	log.Printf("Initializing database: %s", *dbPath)
	database, err := db.Init(*dbPath)
	if err != nil {
		log.Fatalf("Failed to init DB: %v", err)
	}
	defer database.Close()

	// Load Policy
	var pol *policy.Config
	if _, err := os.Stat(*config); err == nil {
		log.Printf("Loading policy from %s", *config)
		pol, err = policy.LoadConfig(*config)
		if err != nil {
			log.Fatalf("Failed to load policy: %v", err)
		}
	} else {
		log.Printf("No policy file found at %s. Using default (OPEN) policy.", *config)
		pol = policy.DefaultConfig()
	}

	// Setup Proxy
	p, err := proxy.New(database, pol, *caCert, *caKey, *verbose)
	if err != nil {
		log.Fatalf("Failed to create proxy: %v", err)
	}
	
	srv := &http.Server{
		Addr:    ":" + *port,
		Handler: p,
	}

	// Start Proxy Server
	go func() {
		log.Printf("Reason Proxy started on :%s", *port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Proxy Server error: %v", err)
		}
	}()

	// Start Admin Server
	adminSrv := admin.New(database, pol, *adminPort)
	go func() {
		if err := adminSrv.Start(); err != nil && err != http.ErrServerClosed {
			log.Printf("Admin Server error: %v", err)
		}
	}()

	// Wait for Shutdown Signal
	<-ctx.Done()
	log.Println("\nReceived shutdown signal. Closing connections...")

	// Create a timeout context for shutdown
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("Proxy Shutdown error: %v", err)
	}
	
	// Admin server doesn't have a Shutdown handle exposed easily in this quick implementation,
	// but context cancellation kills the process anyway.
	
	log.Println("Shutdown complete. Bye! 👋")
}
