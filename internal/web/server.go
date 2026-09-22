package web

import (
	"bytes"
	"context"
	"crypto/hmac"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/yellowman/authd/internal/config"
	"github.com/yellowman/authd/internal/cryptoutil"
	"github.com/yellowman/authd/internal/identity"
	"github.com/yellowman/authd/internal/oidc"
)

//go:embed templates/*.html static/*
var assets embed.FS

type Server struct {
	cfg         config.Config
	auth        *identity.Service
	healthCheck func(context.Context) error
	templates   *template.Template
	oidc        *oidc.HTTP
}
type pageData struct {
	Title, Issuer, Section, View, CSRF, Error, Notice, ReturnTo, Secret, URI string
	Development                                                              bool
	Session                                                                  identity.Session
	Admin                                                                    identity.AdminData
	Sessions                                                                 []identity.Session
	SelectedUser                                                             *identity.User
	SelectedRole                                                             *identity.Role
	RecoveryCodes                                                            []string
}

func New(cfg config.Config, auth *identity.Service, health func(context.Context) error) (*Server, error) {
	if auth == nil || health == nil {
		return nil, errors.New("identity service and health check are required")
	}
	tmpl, err := template.New("").Funcs(template.FuncMap{
		"join": strings.Join, "selected": func(ids []string, id string) bool {
			for _, x := range ids {
				if x == id {
					return true
				}
			}
			return false
		},
		"when": func(t time.Time) string { return t.UTC().Format("2006-01-02 15:04 UTC") },
	}).ParseFS(assets, "templates/*.html")
	if err != nil {
		return nil, fmt.Errorf("parse templates: %w", err)
	}
	return &Server{cfg: cfg, auth: auth, healthCheck: health, templates: tmpl, oidc: oidc.NewHTTP(cfg.Issuer)}, nil
}
func (s *Server) Handler() (http.Handler, error) {
	mux := http.NewServeMux()
	s.oidc.Register(mux)
	static, err := fs.Sub(assets, "static")
	if err != nil {
		return nil, err
	}
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.FS(static))))
	mux.HandleFunc("GET /healthz", s.health)
	mux.HandleFunc("GET /setup", s.setup)
	mux.HandleFunc("POST /setup", s.setupPost)
	mux.HandleFunc("GET /login", s.login)
	mux.HandleFunc("POST /login", s.loginPost)
	mux.HandleFunc("POST /session/logout", s.logout)
	mux.HandleFunc("GET /account", s.account)
	mux.HandleFunc("POST /account/password", s.changePassword)
	mux.HandleFunc("POST /account/sessions/revoke", s.revokeSession)
	mux.HandleFunc("POST /account/mfa/begin", s.beginTOTP)
	mux.HandleFunc("POST /account/mfa/confirm", s.confirmTOTP)
	mux.HandleFunc("POST /account/mfa/remove", s.removeTOTP)
	mux.HandleFunc("GET /admin", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/admin/", http.StatusSeeOther) })
	mux.HandleFunc("GET /admin/{$}", s.admin)
	mux.HandleFunc("POST /admin/users/create", s.createUser)
	mux.HandleFunc("POST /admin/users/save", s.editUser)
	mux.HandleFunc("POST /admin/users/password", s.resetPassword)
	mux.HandleFunc("POST /admin/roles/save", s.saveRole)
	mux.HandleFunc("POST /admin/permissions/create", s.createPermission)
	mux.HandleFunc("POST /admin/sessions/revoke", s.revokeSession)
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/account", http.StatusSeeOther) })
	return s.securityHeaders(s.requestLog(mux)), nil
}
func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	status := "ok"
	if s.healthCheck(ctx) != nil {
		status = "unavailable"
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	_ = json.NewEncoder(w).Encode(map[string]string{"status": status})
}
func (s *Server) data(title string) pageData {
	return pageData{Title: title, Issuer: s.cfg.Issuer, Development: s.cfg.Development}
}
func (s *Server) render(w http.ResponseWriter, status int, name string, data pageData) {
	var b bytes.Buffer
	if err := s.templates.ExecuteTemplate(&b, name, data); err != nil {
		slog.Error("template rendering failed", "template", name)
		http.Error(w, "Unable to render page", 500)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(b.Bytes())
}
func (s *Server) failure(w http.ResponseWriter, r *http.Request, err error) {
	status := http.StatusInternalServerError
	message := "The request could not be completed. No success is assumed."
	switch {
	case errors.Is(err, identity.ErrCredentials):
		status = 401
		message = "Invalid credentials. Check your password and authenticator or recovery code."
	case errors.Is(err, identity.ErrSession):
		status = 401
		message = "Your session has expired or was revoked. Sign in again."
	case errors.Is(err, identity.ErrForbidden):
		status = 403
		message = "Permission denied. Sensitive administration and MFA changes also require a sign-in within the last 10 minutes."
	case errors.Is(err, identity.ErrBootstrapClosed):
		status = 404
		message = "Initial setup is closed."
	case errors.Is(err, identity.ErrConflict):
		status = 409
		message = "The record changed, already exists, or references an unavailable assignment. Reload before trying again."
	case errors.Is(err, identity.ErrLastAdmin):
		status = 409
		message = err.Error()
	case errors.Is(err, identity.ErrRateLimited):
		status = 429
		message = err.Error()
		w.Header().Set("Retry-After", "30")
	case errors.Is(err, identity.ErrUnavailable):
		status = 503
		message = "Authentication is temporarily unavailable."
	default:
		var input *identity.InputError
		if errors.As(err, &input) {
			status = 400
			message = input.Message
		}
	}
	if status >= 500 {
		slog.Error("request failed", "request_id", w.Header().Get("X-Request-ID"))
	} // Never log raw driver/credential errors.
	d := s.data("Request not completed")
	d.Error = message
	s.render(w, status, "message.html", d)
}
func (s *Server) cookieName(kind string) string {
	if s.cfg.Development {
		return "authd_dev_" + kind
	}
	return "__Host-authd_" + kind
}
func (s *Server) cookie(r *http.Request, kind string) string {
	name := s.cookieName(kind)
	value := ""
	count := 0
	for _, c := range r.Cookies() {
		if c.Name == name {
			value = c.Value
			count++
		}
	}
	if count != 1 || !cryptoutil.ValidToken(value) {
		return ""
	}
	return value
}
func (s *Server) setCookie(w http.ResponseWriter, kind, value string, ttl time.Duration) {
	maxAge := int(ttl.Seconds())
	if value == "" {
		maxAge = -1
	}
	http.SetCookie(w, &http.Cookie{Name: s.cookieName(kind), Value: value, Path: "/", Secure: !s.cfg.Development, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: maxAge})
}
func (s *Server) browserCSRF(w http.ResponseWriter, r *http.Request) (string, error) {
	raw := s.cookie(r, "browser")
	if raw == "" {
		var err error
		raw, err = cryptoutil.RandomToken(32)
		if err != nil {
			return "", err
		}
		s.setCookie(w, "browser", raw, 30*time.Minute)
	}
	return s.auth.CSRF(raw, "browser"), nil
}
func (s *Server) parseForm(w http.ResponseWriter, r *http.Request) error {
	if r.URL.RawQuery != "" {
		return identity.Invalid("form actions do not accept query parameters")
	}
	if site := r.Header.Get("Sec-Fetch-Site"); site == "cross-site" {
		return identity.ErrForbidden
	}
	if origin := r.Header.Get("Origin"); origin != "" && origin != s.cfg.Issuer {
		return identity.ErrForbidden
	}
	kind, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || kind != "application/x-www-form-urlencoded" {
		return identity.Invalid("expected an HTML form")
	}
	r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
	if err = r.ParseForm(); err != nil {
		return identity.Invalid("invalid or oversized form")
	}
	for name, values := range r.PostForm {
		if name != "roles" && name != "permissions" && len(values) != 1 {
			return identity.Invalid("duplicate form field")
		}
	}
	return nil
}
func (s *Server) anonForm(w http.ResponseWriter, r *http.Request) error {
	if err := s.parseForm(w, r); err != nil {
		return err
	}
	raw := s.cookie(r, "browser")
	token := r.PostForm.Get("csrf_token")
	if raw == "" || !cryptoutil.ValidToken(token) || !hmac.Equal([]byte(token), []byte(s.auth.CSRF(raw, "browser"))) {
		return identity.ErrForbidden
	}
	return nil
}
func (s *Server) user(w http.ResponseWriter, r *http.Request, admin, allowForced bool) (identity.Session, string, bool) {
	raw := s.cookie(r, "session")
	session, err := s.auth.Session(r.Context(), raw)
	if err != nil {
		if errors.Is(err, identity.ErrSession) && r.Method == http.MethodGet {
			http.Redirect(w, r, "/login?return_to="+safeReturn(r.URL.Path), http.StatusSeeOther)
		} else {
			s.failure(w, r, err)
		}
		return session, raw, false
	}
	if session.User.ForcePasswordChange && !allowForced {
		if r.Method == http.MethodGet {
			http.Redirect(w, r, "/account", http.StatusSeeOther)
		} else {
			s.failure(w, r, identity.ErrForbidden)
		}
		return session, raw, false
	}
	if admin && (!session.Has("system.admin") || (r.Method == http.MethodPost && time.Since(session.AuthTime) > 10*time.Minute)) {
		s.failure(w, r, identity.ErrForbidden)
		return session, raw, false
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		err = s.parseForm(w, r)
		if err == nil && !s.auth.ValidCSRF(session, raw, r.PostForm.Get("csrf_token")) {
			err = identity.ErrForbidden
		}
		if err != nil {
			s.failure(w, r, err)
			return session, raw, false
		}
	}
	return session, raw, true
}
func safeReturn(path string) string {
	if path == "/admin/" {
		return "/admin/"
	}
	return "/account"
}
func auditInfo(w http.ResponseWriter, r *http.Request) identity.Audit {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if net.ParseIP(host) == nil {
		host = ""
	}
	return identity.Audit{IP: host, RequestID: w.Header().Get("X-Request-ID")}
}
func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
		w.Header().Set("Cache-Control", "no-store")
		if !s.cfg.Development {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		}
		next.ServeHTTP(w, r)
	})
}
func (s *Server) requestLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, err := cryptoutil.RandomToken(16)
		if err != nil {
			http.Error(w, "Service unavailable", 503)
			return
		}
		w.Header().Set("X-Request-ID", id)
		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		defer cancel()
		start := time.Now()
		next.ServeHTTP(w, r.WithContext(ctx))
		// No URLs, queries, headers, user input or credentials; even an unknown path
		// could have been filled with a secret by a caller.
		slog.Info("request", "id", id, "method", r.Method, "duration_ms", time.Since(start).Milliseconds())
	})
}
