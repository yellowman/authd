package web

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/yellowman/authd/internal/config"
	"github.com/yellowman/authd/internal/cryptoutil"
	"github.com/yellowman/authd/internal/oidc"
)

//go:embed templates/*.html static/*
var assets embed.FS

type Server struct {
	cfg       config.Config
	db        *pgxpool.Pool
	templates *template.Template
	oidc      *oidc.HTTP
}

type pageData struct {
	Title       string
	Issuer      string
	Development bool
	Section     string
}

func New(cfg config.Config, pool *pgxpool.Pool) (*Server, error) {
	templates, err := template.ParseFS(assets, "templates/*.html")
	if err != nil {
		return nil, fmt.Errorf("parse web templates: %w", err)
	}
	return &Server{
		cfg:       cfg,
		db:        pool,
		templates: templates,
		oidc:      oidc.NewHTTP(cfg.Issuer),
	}, nil
}

func (s *Server) Handler() (http.Handler, error) {
	mux := http.NewServeMux()
	s.oidc.Register(mux)

	staticFS, err := fs.Sub(assets, "static")
	if err != nil {
		return nil, err
	}
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticFS))))
	mux.HandleFunc("GET /healthz", s.health)
	mux.HandleFunc("GET /login", s.login)
	mux.HandleFunc("POST /login", s.loginPost)
	mux.HandleFunc("GET /account", s.account)
	mux.HandleFunc("GET /admin", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/admin/", http.StatusFound) })
	mux.HandleFunc("GET /admin/", s.admin)
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		http.Redirect(w, r, "/admin/", http.StatusFound)
	})

	return s.securityHeaders(s.requestLog(mux)), nil
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := s.db.Ping(ctx); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "unavailable"})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (s *Server) login(w http.ResponseWriter, _ *http.Request) {
	s.render(w, http.StatusOK, "login.html", pageData{Title: "Sign in", Issuer: s.cfg.Issuer, Development: s.cfg.Development})
}

func (s *Server) loginPost(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	http.Error(w, "password authentication is not implemented in the initial scaffold", http.StatusNotImplemented)
}

func (s *Server) account(w http.ResponseWriter, _ *http.Request) {
	s.render(w, http.StatusOK, "account.html", pageData{Title: "Account", Issuer: s.cfg.Issuer, Development: s.cfg.Development, Section: "account"})
}

func (s *Server) admin(w http.ResponseWriter, _ *http.Request) {
	// The scaffold has no live admin data or mutations. Before those are added,
	// this route MUST be wrapped by the session + system.admin middleware.
	s.render(w, http.StatusOK, "admin.html", pageData{Title: "Administration", Issuer: s.cfg.Issuer, Development: s.cfg.Development, Section: "overview"})
}

func (s *Server) render(w http.ResponseWriter, status int, name string, data pageData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if err := s.templates.ExecuteTemplate(w, name, data); err != nil {
		slog.Error("render template", "template", name, "error", err)
	}
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
		if !s.cfg.Development {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) requestLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID, err := cryptoutil.RandomToken(12)
		if err != nil {
			requestID = "unavailable"
		}
		w.Header().Set("X-Request-ID", requestID)
		start := time.Now()
		next.ServeHTTP(w, r)
		// Deliberately log the escaped path only, never the query string: OAuth
		// requests may carry state, code, login_hint, or other sensitive values.
		slog.Info("request",
			"id", requestID,
			"method", r.Method,
			"path", strings.TrimSpace(r.URL.EscapedPath()),
			"duration_ms", time.Since(start).Milliseconds(),
		)
	})
}
