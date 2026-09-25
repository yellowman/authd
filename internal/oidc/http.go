package oidc

import (
	"context"
	"crypto/hmac"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
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
	limiter     *identity.Limiter
}

func NewHTTP(service *Service, issuer string, development bool) *HTTP {
	return &HTTP{metadata: NewMetadata(issuer), service: service, development: development, limiter: identity.NewLimiter(4096)}
}

func (h *HTTP) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /.well-known/openid-configuration", h.discovery)
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", h.discovery)
	mux.HandleFunc("GET /jwks.json", h.jwks)
	mux.HandleFunc("GET /authorize", h.authorize)
	mux.HandleFunc("POST /authorize", h.authorize)
	mux.HandleFunc("GET /authorize/resume", h.resume)
	mux.HandleFunc("POST /authorize/consent", h.consent)
	mux.HandleFunc("POST /token", h.token)
	mux.HandleFunc("GET /userinfo", h.userinfo)
	mux.HandleFunc("POST /userinfo", h.userinfo)
	mux.HandleFunc("POST /revoke", h.revoke)
	mux.HandleFunc("POST /register", h.register)
	mux.HandleFunc("GET /register/{client_id}", h.manageRegistration)
	mux.HandleFunc("PUT /register/{client_id}", h.manageRegistration)
	mux.HandleFunc("OPTIONS /token", h.preflight("POST"))
	mux.HandleFunc("OPTIONS /userinfo", h.preflight("GET, POST"))
	mux.HandleFunc("OPTIONS /revoke", h.preflight("POST"))
	mux.HandleFunc("GET /logout", h.logout)
	mux.HandleFunc("POST /logout", h.logout)
}

func (h *HTTP) manageRegistration(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if h.service == nil {
		h.oauthError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "registration unavailable")
		return
	}
	if !h.limiter.Allow("registration-management:"+auditFromRequest(r).IP, 30, time.Minute) {
		h.oauthError(w, http.StatusTooManyRequests, "invalid_request", "registration management rate limited")
		return
	}
	scheme, token, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || !cryptoutil.ValidToken(token) {
		w.Header().Set("WWW-Authenticate", "Bearer")
		h.oauthError(w, http.StatusUnauthorized, "invalid_token", "registration management token required")
		return
	}
	clientID := r.PathValue("client_id")
	var response RegistrationResponse
	var err error
	if r.Method == http.MethodGet {
		response, err = h.service.ManagedRegistration(r.Context(), clientID, token)
	} else {
		mediaType, _, mediaErr := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if mediaErr != nil || mediaType != "application/json" {
			h.oauthError(w, http.StatusUnsupportedMediaType, "invalid_client_metadata", "application/json required")
			return
		}
		var req RegistrationRequest
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
		if decoder.Decode(&req) != nil {
			h.oauthError(w, http.StatusBadRequest, "invalid_client_metadata", "invalid registration JSON")
			return
		}
		var extra any
		if decoder.Decode(&extra) != io.EOF {
			h.oauthError(w, http.StatusBadRequest, "invalid_client_metadata", "registration must be one JSON object")
			return
		}
		response, err = h.service.UpdateManagedRegistration(r.Context(), clientID, token, req, auditFromRequest(r))
	}
	if err != nil {
		if errors.Is(err, ErrInvalidClient) {
			w.Header().Set("WWW-Authenticate", "Bearer")
			h.oauthError(w, http.StatusUnauthorized, "invalid_token", "registration credential or client is invalid")
			return
		}
		var inputErr *identity.InputError
		if errors.As(err, &inputErr) {
			h.oauthError(w, http.StatusBadRequest, "invalid_client_metadata", inputErr.Error())
			return
		}
		h.oauthError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "registration management unavailable")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}

func (h *HTTP) register(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if h.service == nil {
		h.oauthError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "registration unavailable")
		return
	}
	if !h.limiter.Allow("register:"+auditFromRequest(r).IP, 10, time.Minute) {
		h.oauthError(w, http.StatusTooManyRequests, "invalid_request", "registration rate limited")
		return
	}
	authorization := r.Header.Get("Authorization")
	scheme, token, ok := strings.Cut(authorization, " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || token == "" || strings.ContainsAny(token, " \t\r\n") {
		w.Header().Set("WWW-Authenticate", "Bearer")
		h.oauthError(w, http.StatusUnauthorized, "invalid_token", "initial registration token required")
		return
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		h.oauthError(w, http.StatusUnsupportedMediaType, "invalid_client_metadata", "application/json required")
		return
	}
	var request RegistrationRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
	if err := decoder.Decode(&request); err != nil {
		h.oauthError(w, http.StatusBadRequest, "invalid_client_metadata", "invalid registration JSON")
		return
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		h.oauthError(w, http.StatusBadRequest, "invalid_client_metadata", "registration must be one JSON object")
		return
	}
	response, err := h.service.RegisterDynamicClient(r.Context(), token, request, auditFromRequest(r))
	if err != nil {
		if errors.Is(err, ErrRegistrationTokenUsed) || errors.Is(err, ErrInvalidClient) {
			w.Header().Set("WWW-Authenticate", "Bearer")
			h.oauthError(w, http.StatusUnauthorized, "invalid_token", "initial registration token is invalid")
			return
		}
		if errors.Is(err, ErrRegistrationNotSupported) {
			h.oauthError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "registration unavailable")
			return
		}
		if errors.Is(err, identity.ErrForbidden) || errors.Is(err, identity.ErrConflict) {
			h.oauthError(w, http.StatusBadRequest, "invalid_client_metadata", "registration rejected")
			return
		}
		var inputErr *identity.InputError
		if errors.As(err, &inputErr) {
			h.oauthError(w, http.StatusBadRequest, "invalid_client_metadata", inputErr.Error())
			return
		}
		h.oauthError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "registration unavailable")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(response)
}

func (h *HTTP) Pending(ctx context.Context, raw, browserRaw string) (clientName, loginHint string, ok bool) {
	if h == nil || h.service == nil || !cryptoutil.ValidToken(raw) || !cryptoutil.ValidToken(browserRaw) {
		return "", "", false
	}
	req, client, err := h.service.Store.AuthorizationRequest(ctx, identity.Hash(raw))
	if err != nil || !time.Now().UTC().Before(req.ExpiresAt) || !hmac.Equal(req.BrowserHash, identity.Hash(browserRaw)) || !client.Enabled || !contains(client.RedirectURIs, req.RedirectURI) {
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

func (h *HTTP) authorizationValues(w http.ResponseWriter, r *http.Request) (url.Values, error) {
	if r.Method == http.MethodPost {
		return h.parseProtocolForm(w, r)
	}
	if len(r.URL.RawQuery) > 32<<10 {
		return nil, ErrInvalidRequest
	}
	values, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return nil, ErrInvalidRequest
	}
	for _, v := range values {
		if len(v) != 1 {
			return nil, ErrInvalidRequest
		}
	}
	return values, nil
}
func (h *HTTP) authorize(w http.ResponseWriter, r *http.Request) {
	if h.service == nil {
		h.transient(w, r)
		return
	}
	if !h.limiter.Allow("authorize:"+auditFromRequest(r).IP, 120, time.Second) {
		w.Header().Set("Retry-After", "1")
		h.oauthError(w, 429, "temporarily_unavailable", "authorization rate exceeded")
		return
	}
	values, err := h.authorizationValues(w, r)
	if err != nil {
		h.oauthError(w, 400, "invalid_request", "malformed authorization parameters")
		return
	}
	browser := h.readCookie(r, "oidc_browser")
	if browser == "" {
		browser, err = cryptoutil.RandomToken(32)
		if err != nil {
			h.transient(w, r)
			return
		}
		h.setCookie(w, "oidc_browser", browser, 30*time.Minute)
	}
	raw, req, _, err := h.service.BeginAuthorization(r.Context(), values, browser, time.Now().UTC())
	if err != nil {
		if req.RedirectURI != "" && authorizationError(err) != "server_error" {
			http.Redirect(w, r, h.service.authRedirect(req, "", authorizationError(err)), http.StatusFound)
			return
		}
		if authorizationError(err) == "server_error" {
			h.transient(w, r)
			return
		}
		h.oauthError(w, 400, authorizationError(err), "authorization request was rejected")
		return
	}
	h.continueAuthorization(w, r, raw, browser)
}
func (h *HTTP) resume(w http.ResponseWriter, r *http.Request) {
	if h.service == nil {
		h.transient(w, r)
		return
	}
	values, err := h.authorizationValues(w, r)
	if err != nil || len(values) != 1 || !cryptoutil.ValidToken(values.Get("flow")) {
		h.oauthError(w, 400, "invalid_request", "invalid authorization continuation")
		return
	}
	h.continueAuthorization(w, r, values.Get("flow"), h.readCookie(r, "oidc_browser"))
}
func (h *HTTP) continueAuthorization(w http.ResponseWriter, r *http.Request, raw, browser string) {
	w.Header().Set("Cache-Control", "no-store")
	location, interaction, err := h.service.ContinueAuthorization(r.Context(), raw, browser, h.readCookie(r, "session"), time.Now().UTC())
	if interaction {
		http.Redirect(w, r, "/login?oidc="+url.QueryEscape(raw), http.StatusSeeOther)
		return
	}
	if errors.Is(err, ErrConsentRequired) {
		h.renderConsent(w, r, raw, browser)
		return
	}
	if location != "" {
		http.Redirect(w, r, location, http.StatusFound)
		return
	}
	if err != nil && authorizationError(err) != "server_error" {
		h.oauthError(w, 400, authorizationError(err), "authorization could not be completed")
		return
	}
	h.transient(w, r)
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
	if _, present := form["client_secret"]; basic && present {
		return Client{}, ErrInvalidClient
	}
	if basic {
		var err error
		clientID, err = url.QueryUnescape(basicID)
		if err != nil {
			return Client{}, ErrInvalidClient
		}
		secret, err = url.QueryUnescape(basicSecret)
		if err != nil {
			return Client{}, ErrInvalidClient
		}
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
	if err != nil {
		return Client{}, err
	}
	if !client.Enabled {
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
	w.Header().Add("Vary", "Origin")
	headers := r.Header.Values("Origin")
	if len(headers) == 0 {
		return "", true
	}
	if len(headers) != 1 {
		h.oauthError(w, 403, "invalid_request", "ambiguous Origin header")
		return "", false
	}
	origin, valid := canonicalOrigin(headers[0])
	if !valid {
		h.oauthError(w, 403, "invalid_request", "invalid origin")
		return "", false
	}
	if h.service == nil {
		h.transient(w, r)
		return "", false
	}
	allowed, err := h.service.PublicOriginAllowed(r.Context(), origin)
	if err != nil {
		h.transient(w, r)
		return "", false
	}
	if !allowed {
		h.oauthError(w, 403, "invalid_request", "origin is not registered for a public client")
		return "", false
	}
	w.Header().Set("Access-Control-Allow-Origin", origin)
	return origin, true
}

func (h *HTTP) preflight(methods string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		origin, ok := h.corsOrigin(w, r)
		if !ok {
			return
		}
		if origin == "" {
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
		return
	}
	form, err := h.parseProtocolForm(w, r)
	if err != nil {
		h.oauthError(w, 400, "invalid_request", "invalid token request")
		return
	}
	client, err := h.authenticateClient(r, form)
	if err != nil {
		if !errors.Is(err, ErrInvalidClient) {
			h.transient(w, r)
			return
		}
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
		response, err = h.service.ExchangeCode(r.Context(), client, form.Get("code"), form.Get("redirect_uri"), form.Get("code_verifier"), time.Now().UTC(), auditFromRequest(r))
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
		if !errors.Is(err, ErrInvalidGrant) && !errors.Is(err, ErrRefreshReuse) && !errors.Is(err, ErrCodeReuse) && !errors.Is(err, ErrInvalidScope) && !errors.Is(err, ErrInvalidClient) {
			h.transient(w, r)
			return
		}
		code := "invalid_grant"
		if errors.Is(err, ErrInvalidScope) {
			code = "invalid_scope"
		}
		if errors.Is(err, ErrInvalidClient) {
			w.Header().Set("WWW-Authenticate", `Basic realm="authd"`)
			h.oauthError(w, 401, "invalid_client", "client authentication failed")
			return
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
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || parts[1] == "" || len(parts[1]) > maxJWTBytes {
		return "", false
	}
	return parts[1], true
}
func (h *HTTP) userinfo(w http.ResponseWriter, r *http.Request) {
	if h.service == nil {
		h.transient(w, r)
		return
	}
	origin, ok := h.corsOrigin(w, r)
	if !ok {
		return
	}
	if r.URL.RawQuery != "" {
		h.oauthError(w, 400, "invalid_request", "query credentials are not accepted")
		return
	}
	raw, headerOK := bearer(r)
	if r.Method == http.MethodPost && (r.ContentLength != 0 || r.Header.Get("Content-Type") != "") {
		form, err := h.parseProtocolForm(w, r)
		if err != nil {
			h.oauthError(w, 400, "invalid_request", "invalid UserInfo form")
			return
		}
		if value, present := form["access_token"]; present {
			if len(r.Header.Values("Authorization")) > 0 {
				h.oauthError(w, 400, "invalid_request", "multiple access-token transports")
				return
			}
			raw = value[0]
			headerOK = raw != "" && len(raw) <= maxJWTBytes
		}
	}
	if !headerOK {
		h.bearerError(w)
		return
	}
	claims, err := h.service.VerifyAccessToken(r.Context(), raw, time.Now().UTC())
	if err != nil {
		if !errors.Is(err, ErrInvalidGrant) {
			h.transient(w, r)
		} else {
			h.bearerError(w)
		}
		return
	}
	if origin != "" {
		client, e := h.service.Store.Client(r.Context(), claims.ClientID)
		if e != nil {
			if errors.Is(e, ErrInvalidClient) {
				h.bearerError(w)
			} else {
				h.transient(w, r)
			}
			return
		}
		if !h.requireClientOrigin(w, origin, client) {
			return
		}
	}
	// Verification happened exactly once. Projection cannot reopen a database
	// dependency or substitute different claims between signature checks.
	info, err := userInfoClaims(claims)
	if errors.Is(err, ErrInsufficientScope) {
		w.Header().Set("WWW-Authenticate", `Bearer error="insufficient_scope", scope="openid"`)
		h.oauthError(w, 403, "insufficient_scope", "openid scope is required")
		return
	}
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
		return
	}
	form, err := h.parseProtocolForm(w, r)
	if err != nil {
		h.oauthError(w, 400, "invalid_request", "invalid revocation request")
		return
	}
	client, err := h.authenticateClient(r, form)
	if err != nil {
		if !errors.Is(err, ErrInvalidClient) {
			h.transient(w, r)
			return
		}
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
	if err = h.service.Revoke(r.Context(), form.Get("token"), client, auditFromRequest(r)); err != nil {
		if errors.Is(err, ErrInvalidClient) {
			w.Header().Set("WWW-Authenticate", `Basic realm="authd"`)
			h.oauthError(w, 401, "invalid_client", "client authentication failed")
			return
		}
		h.transient(w, r)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
}

func auditFromRequest(r *http.Request) identity.Audit {
	if ip, resolved := requestid.ClientIPValue(r.Context()); resolved {
		return identity.Audit{IP: ip, RequestID: requestid.From(r.Context())}
	}
	if _, unixPeer := r.Context().Value(http.LocalAddrContextKey).(*net.UnixAddr); unixPeer {
		return identity.Audit{RequestID: requestid.From(r.Context())}
	}
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

func (h *HTTP) transient(w http.ResponseWriter, r *http.Request) {
	slog.Warn("OIDC operation unavailable", "request_id", requestid.From(r.Context()))
	w.Header().Set("Retry-After", "1")
	h.oauthError(w, http.StatusServiceUnavailable, "server_error", "operation temporarily unavailable")
}
