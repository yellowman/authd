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
	"net/netip"
	"strings"
	"time"

	manual "github.com/yellowman/authd"
	"github.com/yellowman/authd/internal/config"
	"github.com/yellowman/authd/internal/cryptoutil"
	"github.com/yellowman/authd/internal/docsite"
	"github.com/yellowman/authd/internal/identity"
	"github.com/yellowman/authd/internal/oidc"
	"github.com/yellowman/authd/internal/requestid"
)

//go:embed templates/*.html static/*
var assets embed.FS

type Server struct {
	cfg         config.Config
	auth        *identity.Service
	healthCheck func(context.Context) error
	templates   *template.Template
	oidc        *oidc.HTTP
	docs        *docsite.Library
}

// Form failures remain forbidden, but the HTML response should tell the user
// whether to reload the form or check the configured public/proxy address.
var (
	errFormOrigin = fmt.Errorf("%w: form origin mismatch", identity.ErrForbidden)
	errFormCSRF   = fmt.Errorf("%w: form session mismatch", identity.ErrForbidden)
)

type clientIPContextKey struct{}
type pageData struct {
	Document                                                                                                                     *docsite.Document
	DocumentGroups                                                                                                               []docsite.Group
	DocumentQuery                                                                                                                string
	DocumentCount                                                                                                                int
	Title, Issuer, Section, View, CSRF, Error, ErrorReference, Notice, ReturnTo, Secret, URI, ClientName, LoginHint, OIDCRequest string
	Development                                                                                                                  bool
	Session                                                                                                                      identity.Session
	Admin                                                                                                                        identity.AdminData
	Sessions                                                                                                                     []identity.Session
	SelectedUser                                                                                                                 *identity.User
	SelectedRole                                                                                                                 *identity.Role
	SelectedGroup                                                                                                                *identity.Group
	SelectedPermission                                                                                                           *identity.Permission
	OIDCClients                                                                                                                  []oidc.Client
	SelectedClient                                                                                                               *oidc.Client
	SigningKeys                                                                                                                  []oidc.SigningKey
	ClientSecret                                                                                                                 string
	RecoveryCodes                                                                                                                []string
	DefaultAccessTokenTTL                                                                                                        int64
}

func New(cfg config.Config, auth *identity.Service, health func(context.Context) error, providers ...*oidc.HTTP) (*Server, error) {
	if auth == nil || health == nil {
		return nil, errors.New("identity service and health check are required")
	}
	tmpl, err := template.New("").Funcs(template.FuncMap{
		"scopeHelp":       oidc.ScopeDescription,
		"adminNavigation": adminNavigation,
		"join":            strings.Join, "selected": func(ids []string, id string) bool {
			for _, x := range ids {
				if x == id {
					return true
				}
			}
			return false
		},
		"when":    func(t time.Time) string { return t.UTC().Format("2006-01-02 15:04 UTC") },
		"version": func(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) },
		"list":    func(values ...string) []string { return values },
	}).ParseFS(assets, "templates/*.html")
	if err != nil {
		return nil, fmt.Errorf("parse templates: %w", err)
	}
	var provider *oidc.HTTP
	if len(providers) > 0 {
		provider = providers[0]
	}
	if provider == nil {
		provider = oidc.NewHTTP(nil, cfg.Issuer, cfg.Development)
	}
	docs, err := manual.Load()
	if err != nil {
		return nil, fmt.Errorf("load documentation: %w", err)
	}
	if _, ok := docs.Document(docsite.StartDocument); !ok {
		return nil, errors.New("missing getting-started documentation")
	}
	return &Server{docs: docs, cfg: cfg, auth: auth, healthCheck: health, templates: tmpl, oidc: provider}, nil
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
	mux.HandleFunc("POST /account/profile", s.editOwnProfile)
	mux.HandleFunc("POST /account/password", s.changePassword)
	mux.HandleFunc("POST /account/sessions/revoke", s.revokeSession)
	mux.HandleFunc("POST /account/mfa/begin", s.beginTOTP)
	mux.HandleFunc("POST /account/mfa/confirm", s.confirmTOTP)
	mux.HandleFunc("POST /account/mfa/remove", s.removeTOTP)
	mux.HandleFunc("POST /account/mfa/recovery", s.regenerateRecoveryCodes)
	mux.HandleFunc("GET /admin", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/admin/", http.StatusSeeOther) })
	mux.HandleFunc("GET /admin/{$}", s.admin)
	mux.HandleFunc("GET /admin/docs", s.documents)
	mux.HandleFunc("GET /admin/docs/raw", s.documentSource)
	mux.HandleFunc("POST /admin/users/create", s.createUser)
	mux.HandleFunc("POST /admin/users/save", s.editUser)
	mux.HandleFunc("POST /admin/users/password", s.resetPassword)
	mux.HandleFunc("POST /admin/users/mfa-reset", s.resetUserMFA)
	mux.HandleFunc("POST /admin/users/delete", s.deleteUser)
	mux.HandleFunc("POST /admin/roles/save", s.saveRole)
	mux.HandleFunc("POST /admin/roles/delete", s.deleteRole)
	mux.HandleFunc("POST /admin/groups/save", s.saveGroup)
	mux.HandleFunc("POST /admin/groups/delete", s.deleteGroup)
	mux.HandleFunc("POST /admin/permissions/create", s.createPermission)
	mux.HandleFunc("POST /admin/permissions/save", s.savePermission)
	mux.HandleFunc("POST /admin/permissions/delete", s.deletePermission)
	mux.HandleFunc("POST /admin/clients/create", s.createClient)
	mux.HandleFunc("POST /admin/clients/save", s.saveClient)
	mux.HandleFunc("POST /admin/clients/secret", s.rotateClientSecret)
	mux.HandleFunc("POST /admin/clients/delete", s.deleteClient)
	mux.HandleFunc("POST /admin/keys/rotate", s.rotateSigningKey)
	mux.HandleFunc("POST /admin/sessions/revoke", s.revokeSession)
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/account", http.StatusSeeOther) })
	return s.securityHeaders(s.requestLog(s.clientAddress(mux))), nil
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
	ttl := s.cfg.AccessTokenTTL
	if ttl < 30*time.Second || ttl > time.Hour {
		ttl = 5 * time.Minute
	}
	return pageData{Title: title, Issuer: s.cfg.Issuer, Development: s.cfg.Development, DefaultAccessTokenTTL: int64(ttl.Seconds())}
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
	errorClass := "internal"
	switch {
	case errors.Is(err, identity.ErrCredentials):
		status = 401
		message = "Invalid credentials. Check your password and authenticator or recovery code."
	case errors.Is(err, identity.ErrSession):
		status = 401
		message = "Your session has expired or was revoked. Sign in again."
	case errors.Is(err, errFormOrigin):
		status = 403
		message = "This form did not come from the configured authd address. Open authd at its public address, reload the form, and try again. If this repeats, ask the server administrator to check the issuer, proxy, and Referrer-Policy settings."
	case errors.Is(err, errFormCSRF):
		status = 403
		message = "This form expired or no longer matches your browser session. Reload the page before submitting again; another sign-in or sign-out may have changed the session."
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
		errorClass = "dependency_unavailable"
	case errors.Is(err, context.DeadlineExceeded):
		status = 503
		message = "The operation timed out before it could complete."
		errorClass = "deadline"
	default:
		var input *identity.InputError
		if errors.As(err, &input) {
			status = 400
			message = input.Message
		}
	}
	requestID := requestid.From(r.Context())
	if requestID == "" {
		requestID = w.Header().Get("X-Request-ID")
	}
	if status >= 500 {
		// Never log raw driver/credential errors. The bounded class plus request ID
		// is sufficient for operator correlation without leaking DSNs, SQL, or secrets.
		slog.Error("request failed", "request_id", requestID, "error_class", errorClass)
	}
	d := s.data("Request not completed")
	d.Error = message
	if status >= 500 {
		d.ErrorReference = requestID
	}
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
		return errFormOrigin
	}
	if origin := r.Header.Get("Origin"); origin != "" && origin != s.cfg.Issuer {
		return errFormOrigin
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
		if name != "roles" && name != "users" && name != "permissions" && name != "identity_scopes" && len(values) != 1 {
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
		return errFormCSRF
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
			err = errFormCSRF
		}
		if err != nil {
			s.failure(w, r, err)
			return session, raw, false
		}
	}
	return session, raw, true
}
func safeReturn(path string) string {
	switch path {
	case "/admin/", "/authorize", "/admin/docs":
		return path
	default:
		return "/account"
	}
}
func auditInfo(w http.ResponseWriter, r *http.Request) identity.Audit {
	host, _ := r.Context().Value(clientIPContextKey{}).(string)
	id := requestid.From(r.Context())
	if id == "" {
		id = w.Header().Get("X-Request-ID")
	}
	return identity.Audit{IP: host, RequestID: id}
}
func trustedAddress(addr netip.Addr, trusted []netip.Prefix) bool {
	for _, prefix := range trusted {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}
func peerAddress(remote string) (netip.Addr, bool) {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		host = remote
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(host))
	return addr.Unmap(), err == nil && addr.Zone() == ""
}
func resolvedClientIP(r *http.Request, trusted []netip.Prefix, trustUnix bool) string {
	// Transport comes from net/http's accepted connection, never request headers
	// or a peer-controlled Unix filename that happens to resemble an IP address.
	_, unixPeer := r.Context().Value(http.LocalAddrContextKey).(*net.UnixAddr)
	fallback := ""
	var peer netip.Addr
	if unixPeer {
		if !trustUnix {
			return ""
		}
	} else {
		var ok bool
		peer, ok = peerAddress(r.RemoteAddr)
		if !ok {
			return ""
		}
		fallback = peer.String()
		if !trustedAddress(peer, trusted) {
			return fallback
		}
	}
	fields := r.Header.Values("X-Forwarded-For")
	if len(fields) != 1 || len(fields[0]) > 2048 {
		return fallback
	}
	parts := strings.Split(fields[0], ",")
	if len(parts) > 32 {
		return fallback
	}
	chain := make([]netip.Addr, 0, len(parts))
	for _, part := range parts {
		addr, err := netip.ParseAddr(strings.TrimSpace(part))
		if err != nil || addr.Zone() != "" {
			return fallback
		}
		chain = append(chain, addr.Unmap())
	}
	candidate := peer
	last := len(chain) - 1
	if unixPeer {
		// The filesystem access policy and explicit flag trust this one hop only.
		candidate = chain[last]
		last--
	}
	for i := last; i >= 0 && trustedAddress(candidate, trusted); i-- {
		candidate = chain[i]
	}
	return candidate.String()
}
func (s *Server) clientAddress(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := resolvedClientIP(r, s.cfg.TrustedProxies, s.cfg.TrustUnixProxy)
		next.ServeHTTP(w, r.WithContext(requestid.WithClientIP(context.WithValue(r.Context(), clientIPContextKey{}, ip), ip)))
	})
}
func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		// A no-referrer policy makes browsers serialize the Origin header as
		// "null" for native form navigations. Keep paths out of Referer while
		// preserving the origin needed by parseForm's same-origin check.
		w.Header().Set("Referrer-Policy", "origin")
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
		ctx := requestid.With(r.Context(), id)
		ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		start := time.Now()
		next.ServeHTTP(w, r.WithContext(ctx))
		// No URLs, queries, headers, user input or credentials; even an unknown path
		// could have been filled with a secret by a caller.
		slog.Info("request", "id", id, "method", r.Method, "duration_ms", time.Since(start).Milliseconds())
	})
}
