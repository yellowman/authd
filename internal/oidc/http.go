package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/yellowman/authd/internal/cryptoutil"
	"github.com/yellowman/authd/internal/identity"
	"github.com/yellowman/authd/internal/requestid"
)

type HTTP struct {
	metadata    Metadata
	service     *Service
	development bool
}

func NewHTTP(service *Service, issuer string, development bool) *HTTP {
	return &HTTP{metadata: NewMetadata(issuer), service: service, development: development}
}

func (h *HTTP) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /.well-known/openid-configuration", h.discovery)
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", h.discovery)
	mux.HandleFunc("GET /jwks.json", h.jwks)
	mux.HandleFunc("GET /authorize", h.authorize)
	mux.HandleFunc("POST /token", h.token)
	mux.HandleFunc("GET /userinfo", h.userinfo)
	mux.HandleFunc("POST /userinfo", h.userinfo)
	mux.HandleFunc("POST /revoke", h.revoke)
	mux.HandleFunc("OPTIONS /token", h.preflight("POST"))
	mux.HandleFunc("OPTIONS /userinfo", h.preflight("GET, POST"))
	mux.HandleFunc("OPTIONS /revoke", h.preflight("POST"))
	mux.HandleFunc("GET /logout", h.logout)
	mux.HandleFunc("POST /logout", h.logout)
}

func (h *HTTP) Pending(ctx context.Context, raw string) (clientName, loginHint string, ok bool) {
	if h == nil || h.service == nil || !cryptoutil.ValidToken(raw) {
		return "", "", false
	}
	req, client, err := h.service.Store.AuthorizationRequest(ctx, identity.Hash(raw))
	if err != nil || !time.Now().UTC().Before(req.ExpiresAt) {
		return "", "", false
	}
	return client.Name, req.LoginHint, true
}

func (h *HTTP) discovery(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_ = json.NewEncoder(w).Encode(h.metadata)
}

func (h *HTTP) jwks(w http.ResponseWriter, r *http.Request) {
	if h.service == nil {
		h.oauthError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "OIDC is unavailable")
		return
	}
	body, err := h.service.PublicJWKS(r.Context())
	if err != nil {
		h.oauthError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "signing keys are unavailable")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=60")
	_, _ = w.Write(body)
}

func (h *HTTP) cookieName(kind string) string {
	if h.development {
		return "authd_dev_" + kind
	}
	return "__Host-authd_" + kind
}
func (h *HTTP) readCookie(r *http.Request, kind string) string {
	name := h.cookieName(kind)
	var value string
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
func (h *HTTP) setCookie(w http.ResponseWriter, kind, value string, ttl time.Duration) {
	maxAge := int(ttl.Seconds())
	if value == "" {
		maxAge = -1
	}
	http.SetCookie(w, &http.Cookie{Name: h.cookieName(kind), Value: value, Path: "/", Secure: !h.development, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: maxAge})
}

func (h *HTTP) authorize(w http.ResponseWriter, r *http.Request) {
	if h.service == nil {
		h.oauthError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "OIDC is unavailable")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	values := r.URL.Query()
	requestRaw := ""
	if handles, ok := values["request"]; ok {
		if len(values) != 1 || len(handles) != 1 || !cryptoutil.ValidToken(handles[0]) {
			h.oauthError(w, 400, "invalid_request", "authorization continuation is invalid")
			return
		}
		requestRaw = handles[0]
	} else {
		raw, req, _, err := h.service.BeginAuthorization(r.Context(), values, time.Now().UTC())
		if err != nil {
			if req.RedirectURI != "" {
				state := ""
				if v := values["state"]; len(v) == 1 && len(v[0]) <= 2048 {
					state = v[0]
				}
				req.State = state
				location := h.service.authRedirect(req, "", authorizationError(err))
				if location != "" {
					http.Redirect(w, r, location, http.StatusFound)
					return
				}
			}
			h.oauthError(w, http.StatusBadRequest, authorizationError(err), "authorization request was rejected")
			return
		}
		requestRaw = raw
	}
	location, interaction, err := h.service.ContinueAuthorization(r.Context(), requestRaw, h.readCookie(r, "session"), time.Now().UTC())
	if interaction {
		http.Redirect(w, r, "/login?oidc="+url.QueryEscape(requestRaw), http.StatusSeeOther)
		return
	}
	if location != "" {
		http.Redirect(w, r, location, http.StatusFound)
		return
	}
	if err != nil {
		h.oauthError(w, 400, authorizationError(err), "authorization could not be completed")
		return
	}
	h.oauthError(w, 500, "server_error", "authorization could not be completed")
}

func (h *HTTP) parseProtocolForm(w http.ResponseWriter, r *http.Request) (url.Values, error) {
	if r.URL.RawQuery != "" {
		return nil, ErrInvalidRequest
	}
	kind, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || kind != "application/x-www-form-urlencoded" {
		return nil, ErrInvalidRequest
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err = r.ParseForm(); err != nil {
		return nil, ErrInvalidRequest
	}
	for _, values := range r.PostForm {
		if len(values) != 1 {
			return nil, ErrInvalidRequest
		}
	}
	return r.PostForm, nil
}

func (h *HTTP) authenticateClient(r *http.Request, form url.Values) (Client, error) {
	var clientID, secret string
	authHeaders := r.Header.Values("Authorization")
	if len(authHeaders) > 1 {
		return Client{}, ErrInvalidClient
	}
	basicID, basicSecret, basic := r.BasicAuth()
	if len(authHeaders) == 1 && !basic {
		return Client{}, ErrInvalidClient
	}
	postedSecret := form.Get("client_secret")
	postedID := form.Get("client_id")
	if basic && postedSecret != "" {
		return Client{}, ErrInvalidClient
	}
	if basic {
		clientID, secret = basicID, basicSecret
		if postedID != "" && postedID != clientID {
			return Client{}, ErrInvalidClient
		}
	} else {
		clientID, secret = postedID, postedSecret
	}
	if clientID == "" || len(clientID) > 256 {
		return Client{}, ErrInvalidClient
	}
	client, err := h.service.Store.Client(r.Context(), clientID)
	if err != nil || !client.Enabled {
		return Client{}, ErrInvalidClient
	}
	if client.Type == "public" {
		_, postedSecretPresent := form["client_secret"]
		if basic || postedSecretPresent || secret != "" {
			return Client{}, ErrInvalidClient
		}
	} else if !h.service.VerifyClientSecret(client, secret) {
		return Client{}, ErrInvalidClient
	}
	return client, nil
}

func (h *HTTP) corsOrigin(w http.ResponseWriter, r *http.Request) (string, bool) {
	raw := strings.TrimSpace(r.Header.Get("Origin"))
	if raw == "" {
		return "", true
	}
	origin, ok := canonicalOrigin(raw)
	if !ok || h.service == nil || !h.service.PublicOriginAllowed(r.Context(), origin) {
		return "", false
	}
	w.Header().Set("Access-Control-Allow-Origin", origin)
	w.Header().Add("Vary", "Origin")
	return origin, true
}

func (h *HTTP) preflight(methods string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		origin, ok := h.corsOrigin(w, r)
		if !ok || origin == "" {
			h.oauthError(w, http.StatusForbidden, "invalid_request", "origin is not registered for a public client")
			return
		}
		requested := strings.ToUpper(strings.TrimSpace(r.Header.Get("Access-Control-Request-Method")))
		methodOK := false
		for _, method := range strings.Split(methods, ",") {
			if strings.TrimSpace(method) == requested {
				methodOK = true
				break
			}
		}
		if !methodOK {
			h.oauthError(w, http.StatusForbidden, "invalid_request", "CORS method is not allowed")
			return
		}
		for _, rawHeader := range strings.Split(r.Header.Get("Access-Control-Request-Headers"), ",") {
			header := strings.ToLower(strings.TrimSpace(rawHeader))
			if header != "" && header != "authorization" && header != "content-type" {
				h.oauthError(w, http.StatusForbidden, "invalid_request", "CORS header is not allowed")
				return
			}
		}
		w.Header().Set("Access-Control-Allow-Methods", methods)
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		w.Header().Set("Access-Control-Max-Age", "300")
		w.Header().Add("Vary", "Access-Control-Request-Method")
		w.Header().Add("Vary", "Access-Control-Request-Headers")
		w.WriteHeader(http.StatusNoContent)
	}
}

func (h *HTTP) requireClientOrigin(w http.ResponseWriter, origin string, client Client) bool {
	if origin == "" {
		return true
	}
	if !clientOriginAllowed(client, origin) {
		h.oauthError(w, http.StatusForbidden, "invalid_request", "origin is not registered for this public client")
		return false
	}
	return true
}

func (h *HTTP) token(w http.ResponseWriter, r *http.Request) {
	if h.service == nil {
		h.oauthError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "OIDC is unavailable")
		return
	}
	origin, ok := h.corsOrigin(w, r)
	if !ok {
		h.oauthError(w, http.StatusForbidden, "invalid_request", "origin is not registered for a public client")
		return
	}
	form, err := h.parseProtocolForm(w, r)
	if err != nil {
		h.oauthError(w, 400, "invalid_request", "invalid token request")
		return
	}
	client, err := h.authenticateClient(r, form)
	if err != nil {
		w.Header().Set("WWW-Authenticate", `Basic realm="authd"`)
		h.oauthError(w, 401, "invalid_client", "client authentication failed")
		return
	}
	if !h.requireClientOrigin(w, origin, client) {
		return
	}
	grantType := form.Get("grant_type")
	var response TokenResponse
	switch grantType {
	case "authorization_code":
		if form.Get("code") == "" || form.Get("redirect_uri") == "" || form.Get("code_verifier") == "" {
			h.oauthError(w, 400, "invalid_request", "authorization code exchange is incomplete")
			return
		}
		response, err = h.service.ExchangeCode(r.Context(), client, form.Get("code"), form.Get("redirect_uri"), form.Get("code_verifier"), time.Now().UTC())
	case "refresh_token":
		if form.Get("refresh_token") == "" {
			h.oauthError(w, 400, "invalid_request", "refresh token is required")
			return
		}
		response, err = h.service.Refresh(r.Context(), client, form.Get("refresh_token"), form.Get("scope"), time.Now().UTC(), auditFromRequest(r))
	default:
		h.oauthError(w, 400, "unsupported_grant_type", "grant type is not supported")
		return
	}
	if err != nil {
		code := "invalid_grant"
		if errors.Is(err, ErrInvalidScope) {
			code = "invalid_scope"
		}
		h.oauthError(w, 400, code, "token request was rejected")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	_ = json.NewEncoder(w).Encode(response)
}

func bearer(r *http.Request) (string, bool) {
	values := r.Header.Values("Authorization")
	if len(values) != 1 {
		return "", false
	}
	parts := strings.SplitN(values[0], " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || parts[1] == "" || len(parts[1]) > 8192 {
		return "", false
	}
	return parts[1], true
}
func (h *HTTP) userinfo(w http.ResponseWriter, r *http.Request) {
	if h.service == nil {
		h.oauthError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "OIDC is unavailable")
		return
	}
	origin, corsOK := h.corsOrigin(w, r)
	if !corsOK {
		h.oauthError(w, http.StatusForbidden, "invalid_request", "origin is not registered for a public client")
		return
	}
	raw, ok := bearer(r)
	if !ok {
		h.bearerError(w)
		return
	}
	now := time.Now().UTC()
	claims, err := h.service.VerifyAccessToken(r.Context(), raw, now)
	if err != nil {
		h.bearerError(w)
		return
	}
	if origin != "" {
		client, e := h.service.Store.Client(r.Context(), claims.ClientID)
		if e != nil || !h.requireClientOrigin(w, origin, client) {
			return
		}
	}
	info, err := h.service.UserInfo(r.Context(), raw, now)
	if err != nil {
		h.bearerError(w)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(info)
}
func (h *HTTP) bearerError(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
	h.oauthError(w, 401, "invalid_token", "access token is invalid or expired")
}

func (h *HTTP) revoke(w http.ResponseWriter, r *http.Request) {
	if h.service == nil {
		h.oauthError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "OIDC is unavailable")
		return
	}
	origin, ok := h.corsOrigin(w, r)
	if !ok {
		h.oauthError(w, http.StatusForbidden, "invalid_request", "origin is not registered for a public client")
		return
	}
	form, err := h.parseProtocolForm(w, r)
	if err != nil {
		h.oauthError(w, 400, "invalid_request", "invalid revocation request")
		return
	}
	client, err := h.authenticateClient(r, form)
	if err != nil {
		w.Header().Set("WWW-Authenticate", `Basic realm="authd"`)
		h.oauthError(w, 401, "invalid_client", "client authentication failed")
		return
	}
	if !h.requireClientOrigin(w, origin, client) {
		return
	}
	if form.Get("token") == "" {
		h.oauthError(w, 400, "invalid_request", "token is required")
		return
	}
	_ = h.service.Revoke(r.Context(), form.Get("token"), client.ClientID, auditFromRequest(r))
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
}

func (h *HTTP) logout(w http.ResponseWriter, r *http.Request) {
	if h.service == nil {
		h.oauthError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "OIDC is unavailable")
		return
	}
	values := r.URL.Query()
	if r.Method == http.MethodPost {
		var err error
		values, err = h.parseProtocolForm(w, r)
		if err != nil {
			h.oauthError(w, 400, "invalid_request", "invalid logout request")
			return
		}
	}
	hint, err := single(values, "id_token_hint", false, 16<<10)
	if err != nil {
		h.oauthError(w, 400, "invalid_request", "invalid logout request")
		return
	}
	post, err := single(values, "post_logout_redirect_uri", false, 4096)
	if err != nil {
		h.oauthError(w, 400, "invalid_request", "invalid logout request")
		return
	}
	state, err := single(values, "state", false, 2048)
	if err != nil {
		h.oauthError(w, 400, "invalid_request", "invalid logout request")
		return
	}
	var client Client
	var hintedSubject string
	var trusted bool
	if hint != "" {
		if c, subject, e := h.service.LogoutClient(r.Context(), hint, time.Now().UTC()); e == nil {
			client = c
			hintedSubject = subject
			trusted = true
		}
	}

	// A bare cross-site navigation to /logout must not terminate an OP
	// session. Automatic RP-initiated logout is accepted only when a signed
	// ID-token hint identifies the same subject as the current provider
	// session. A valid hint remains useful when the provider session is already
	// gone, preserving idempotent post-logout redirection.
	ended := false
	if raw := h.readCookie(r, "session"); raw != "" {
		if session, e := h.service.Sessions.Session(r.Context(), raw); e == nil {
			if trusted && session.User.ID == hintedSubject {
				if e = h.service.Sessions.EndSession(r.Context(), raw, auditFromRequest(r)); e == nil {
					ended = true
				}
			} else if trusted {
				// A valid token for another subject does not authorize ending this
				// browser's session or redirecting it to that RP.
				trusted = false
			}
		} else if errors.Is(e, identity.ErrSession) {
			// Clear only a locally-invalid/stale session cookie.
			ended = true
		}
	}
	if ended {
		h.setCookie(w, "session", "", 0)
	}
	if post != "" && trusted && contains(client.LogoutURIs, post) {
		u, err := url.Parse(post)
		if err == nil {
			q := u.Query()
			if state != "" {
				q.Set("state", state)
			}
			u.RawQuery = q.Encode()
			http.Redirect(w, r, u.String(), http.StatusSeeOther)
			return
		}
	}
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func auditFromRequest(r *http.Request) identity.Audit {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if net.ParseIP(host) == nil {
		host = ""
	}
	return identity.Audit{IP: host, RequestID: requestid.From(r.Context())}
}

func (h *HTTP) oauthError(w http.ResponseWriter, status int, code, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code, "error_description": description})
}
