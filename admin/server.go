package admin

import (
	"embed"
	"html/template"
	"log"
	"net/http"
	"time"

	"github.com/sagebot-claw/reason-proxy/db"
	"github.com/sagebot-claw/reason-proxy/policy"
)

//go:embed templates/*
var templatesFS embed.FS

type Server struct {
	DB     *db.DB
	Config *policy.Config // Pointer to allow hot reloads (careful with concurrency!)
	Port   string
	Tmpl   *template.Template
}

func New(database *db.DB, cfg *policy.Config, port string) *Server {
	tmpl, err := template.ParseFS(templatesFS, "templates/*.html")
	if err != nil {
		log.Printf("Warning: Failed to parse embedded templates: %v", err)
		tmpl = template.New("empty")
	}

	return &Server{
		DB:     database,
		Config: cfg,
		Port:   port,
		Tmpl:   tmpl,
	}
}

func (s *Server) Start() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleDashboard)
	// mux.HandleFunc("/logs", s.handleLogs)
	// mux.HandleFunc("/api/policy/reload", s.handlePolicyReload)

	srv := &http.Server{
		Addr:         ":" + s.Port,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	log.Printf("Admin Interface started on :%s", s.Port)
	return srv.ListenAndServe()
}

type DashboardData struct {
	Config  *policy.Config
	Stats   Stats
	Logs    []db.LogEntry
}

type Stats struct {
	Allowed int
	Denied  int
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	allowed, denied, err := s.DB.GetStats()
	if err != nil {
		http.Error(w, "Failed to get stats: "+err.Error(), http.StatusInternalServerError)
		return
	}

	logs, err := s.DB.GetRecentLogs(10)
	if err != nil {
		http.Error(w, "Failed to get logs: "+err.Error(), http.StatusInternalServerError)
		return
	}

	data := DashboardData{
		Config: s.Config,
		Stats: Stats{
			Allowed: allowed,
			Denied:  denied,
		},
		Logs: logs,
	}

	if err := s.Tmpl.ExecuteTemplate(w, "layout.html", data); err != nil {
		log.Printf("Template error: %v", err)
		http.Error(w, "Template error", http.StatusInternalServerError)
	}
}
