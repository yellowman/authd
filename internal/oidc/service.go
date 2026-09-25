package oidc

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/yellowman/authd/internal/cryptoutil"
	"github.com/yellowman/authd/internal/identity"
)

type Service struct {
	keyMu               sync.Mutex
	cachedPrivate       *rsa.PrivateKey
	cachedPrivateDigest [32]byte
	publicKeys          map[string]cachedPublicKey

	Store              Store
	Sessions           Sessions
	issuer             string
	masterKey          []byte
	authCodeTTL        time.Duration
	refreshIdleTTL     time.Duration
	refreshAbsoluteTTL time.Duration
}

func NewService(store Store, sessions Sessions, issuer string, masterKey []byte, authCodeTTL, refreshIdleTTL, refreshAbsoluteTTL time.Duration) (*Service, error) {
	if store == nil || sessions == nil || issuer == "" || len(masterKey) != 32 {
		return nil, errors.New("OIDC service requires store, sessions, issuer, and 32-byte master key")
	}
	if authCodeTTL <= 0 || authCodeTTL > time.Minute || refreshIdleTTL <= 0 || refreshAbsoluteTTL <= 0 || refreshIdleTTL > refreshAbsoluteTTL {
		return nil, errors.New("invalid OIDC token lifetimes")
	}
	return &Service{Store: store, Sessions: sessions, issuer: strings.TrimRight(issuer, "/"), masterKey: append([]byte(nil), masterKey...), authCodeTTL: authCodeTTL, refreshIdleTTL: refreshIdleTTL, refreshAbsoluteTTL: refreshAbsoluteTTL}, nil
}

func (s *Service) EnsureSigningKey(ctx context.Context) error {
	if record, err := s.Store.ActiveSigningKey(ctx); err == nil {
		_, err = s.cachedPrivateKey(record)
		return err
	} else if !errors.Is(err, ErrSigningKeyNotFound) {
		return err
	}
	generated, err := generateSigningKey(s.masterKey)
	if err != nil {
		return err
	}
	installed, err := s.Store.InstallSigningKey(ctx, generated, false)
	if err != nil {
		return err
	}
	_, err = s.cachedPrivateKey(installed)
	return err
}

func generateSigningKey(master []byte) (SigningKey, error) {
	private, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return SigningKey{}, err
	}
	kidToken, err := cryptoutil.RandomToken(16)
	if err != nil {
		return SigningKey{}, err
	}
	kid := time.Now().UTC().Format("20060102") + "-" + kidToken
	plain, err := marshalPrivateKey(private)
	if err != nil {
		return SigningKey{}, err
	}
	defer clear(plain)
	cipher, err := cryptoutil.Seal(master, plain, []byte("oidc-signing-key:"+kid))
	if err != nil {
		return SigningKey{}, err
	}
	public, err := publicJWK(kid, &private.PublicKey)
	if err != nil {
		return SigningKey{}, err
	}
	return SigningKey{KID: kid, Algorithm: "RS256", Ciphertext: cipher, PublicJWK: public, Active: true, CreatedAt: time.Now().UTC()}, nil
}

func (s *Service) PublicJWKS(ctx context.Context) ([]byte, error) {
	keys, err := s.Store.SigningKeys(ctx)
	if err != nil {
		return nil, err
	}
	items := make([]json.RawMessage, 0, len(keys))
	for _, record := range keys {
		pub, err := s.cachedPublic(record)
		if err != nil {
			return nil, err
		}
		body, err := publicJWK(record.KID, pub)
		if err != nil {
			return nil, err
		}
		items = append(items, json.RawMessage(body))
	}
	return json.Marshal(map[string]any{"keys": items})
}

// BeginAuthorization validates the trusted redirect before returning redirectable
// errors. The browser binding is independent of the short-lived request handle.
func (s *Service) BeginAuthorization(ctx context.Context, values map[string][]string, browserRaw string, now time.Time) (string, AuthorizationRequest, Client, error) {
	req := AuthorizationRequest{}
	client := Client{}
	fail := func(err error) (string, AuthorizationRequest, Client, error) { return "", req, client, err }
	if !cryptoutil.ValidToken(browserRaw) {
		return fail(ErrInvalidRequest)
	}
	clientID, err := single(values, "client_id", true, 256)
	if err != nil {
		return fail(err)
	}
	client, err = s.Store.Client(ctx, clientID)
	if err != nil {
		return fail(err)
	}
	if !client.Enabled {
		return fail(ErrInvalidClient)
	}
	redirect, err := single(values, "redirect_uri", true, 4096)
	if err != nil || !contains(client.RedirectURIs, redirect) {
		return fail(ErrInvalidRequest)
	}
	req.ClientID = clientID
	req.RedirectURI = redirect
	for _, v := range values {
		if len(v) != 1 {
			return fail(ErrInvalidRequest)
		}
	}
	if req.State, err = single(values, "state", false, 2048); err != nil {
		return fail(err)
	}
	for _, unsupported := range []struct {
		name string
		err  error
	}{{"request", ErrRequestNotSupported}, {"request_uri", ErrRequestURINotSupported}, {"registration", ErrRegistrationNotSupported}} {
		if _, ok := values[unsupported.name]; ok {
			return fail(unsupported.err)
		}
	}
	responseType, err := single(values, "response_type", true, 32)
	if err != nil {
		return fail(err)
	}
	if responseType != "code" {
		return fail(ErrUnsupportedResponse)
	}
	mode, err := single(values, "response_mode", false, 32)
	if err != nil || (mode != "" && mode != "query") {
		return fail(ErrInvalidRequest)
	}
	rawScope, err := single(values, "scope", true, 4096)
	if err != nil {
		return fail(ErrInvalidScope)
	}
	req.Scopes, err = parseScopes(rawScope)
	if err != nil {
		return fail(err)
	}
	if err = scopeAllowed(client, req.Scopes); err != nil {
		return fail(err)
	}
	req.CodeChallenge, err = single(values, "code_challenge", true, 128)
	if err != nil || !validPKCEChallenge(req.CodeChallenge) {
		return fail(ErrInvalidRequest)
	}
	method, err := single(values, "code_challenge_method", true, 16)
	if err != nil || method != "S256" {
		return fail(ErrInvalidRequest)
	}
	if req.Nonce, err = single(values, "nonce", false, 2048); err != nil {
		return fail(err)
	}
	if req.LoginHint, err = single(values, "login_hint", false, 512); err != nil {
		return fail(err)
	}
	prompt, err := single(values, "prompt", false, 128)
	if err != nil {
		return fail(err)
	}
	if req.Prompt, err = parsePrompt(prompt); err != nil {
		return fail(err)
	}
	maxRaw, err := single(values, "max_age", false, 16)
	if err != nil {
		return fail(err)
	}
	if req.MaxAgeSeconds, err = parseMaxAge(maxRaw); err != nil {
		return fail(err)
	}
	acr, err := single(values, "acr_values", false, 1024)
	if err != nil {
		return fail(err)
	}
	if req.PreferredACR, err = parseACRValues(acr, client, req.Scopes); err != nil {
		return fail(err)
	}
	minimum := ""
	if client.RequireMFA {
		minimum = ACRMFA
	}
	claims, err := single(values, "claims", false, 8192)
	if err != nil {
		return fail(err)
	}
	if req.RequiredACR, req.ExpectedSubjects, err = authenticationClaims(claims, minimum); err != nil {
		return fail(err)
	}
	if claims != "" && !contains(req.Scopes, "openid") {
		return fail(ErrInvalidRequest)
	}
	if preferred, e := voluntaryClaimACR(claims); e != nil {
		return fail(e)
	} else if preferred != "" {
		req.PreferredACR = preferred
	}
	if req.Claims, err = identityClaimSelection(claims, client); err != nil {
		return fail(err)
	}
	if hint, err := single(values, "id_token_hint", false, maxJWTBytes); err != nil {
		return fail(err)
	} else if hint != "" {
		hc, subject, _, err := s.LogoutClient(ctx, hint, now)
		if err != nil {
			return fail(err)
		}
		if hc.ClientID != clientID || !SubjectMatches(req, subject) {
			return fail(ErrInvalidRequest)
		}
		req.ExpectedSubjects = []string{subject}
	}
	// No blanket administrative-consent fiction for offline access. Without an
	// explicit consent prompt this request is ignored as OIDC Core 11 requires.
	if contains(req.Scopes, "offline_access") && (!hasPrompt(req, "consent") || !contains(req.Scopes, "openid") || !client.RefreshTokensEnabled) {
		filtered := make([]string, 0, len(req.Scopes))
		for _, v := range req.Scopes {
			if v != "offline_access" {
				filtered = append(filtered, v)
			}
		}
		req.Scopes = filtered
	}
	if len(req.Scopes) == 0 {
		return fail(ErrInvalidScope)
	}
	req.BrowserHash = identity.Hash(browserRaw)
	req.CreatedAt = now.UTC()
	req.ExpiresAt = now.Add(10 * time.Minute).UTC()
	raw, err := cryptoutil.RandomToken(32)
	if err != nil {
		return fail(err)
	}
	if err = s.Store.CreateAuthorizationRequest(ctx, identity.Hash(raw), req); err != nil {
		return fail(err)
	}
	return raw, req, client, nil
}

func (s *Service) ContinueAuthorization(ctx context.Context, requestRaw, browserRaw, sessionRaw string, now time.Time) (redirect string, interaction bool, err error) {
	if !cryptoutil.ValidToken(requestRaw) || !cryptoutil.ValidToken(browserRaw) {
		return "", false, ErrInvalidRequest
	}
	req, client, err := s.Store.AuthorizationRequest(ctx, identity.Hash(requestRaw))
	if err != nil {
		return "", false, err
	}
	if !hmac.Equal(req.BrowserHash, identity.Hash(browserRaw)) {
		return "", false, ErrInvalidRequest
	}
	// Redirect removal takes effect before ANY response, including an OAuth error.
	if !client.Enabled || !contains(client.RedirectURIs, req.RedirectURI) {
		return "", false, ErrInvalidRequest
	}
	if !now.Before(req.ExpiresAt) {
		return s.authRedirect(req, "", "invalid_request"), false, ErrInvalidRequest
	}
	session, sessionErr := s.Sessions.Session(ctx, sessionRaw)
	if sessionErr != nil && !errors.Is(sessionErr, identity.ErrSession) {
		return "", false, sessionErr
	}
	needLogin := sessionErr != nil || !session.User.Enabled || session.User.ForcePasswordChange
	if !needLogin && (!SubjectMatches(req, session.User.ID) || !AuthenticationFresh(req, session.AuthTime, now)) {
		needLogin = true
	}
	required := req.RequiredACR
	if client.RequireMFA {
		required = ACRMFA
	}
	if !needLogin && !meetsACR(session.AuthMethods, required) {
		needLogin = true
	}
	// A supported voluntary preference is attempted when interaction is allowed
	// and a factor exists; it cannot turn an unknown ACR into a hard denial.
	if !needLogin && req.PreferredACR == ACRMFA && !meetsACR(session.AuthMethods, ACRMFA) && session.User.MFAEnabled && !hasPrompt(req, "none") {
		needLogin = true
	}
	if needLogin {
		if hasPrompt(req, "none") {
			return s.authRedirect(req, "", "login_required"), false, ErrLoginRequired
		}
		if sessionErr == nil && required == ACRMFA && !session.User.MFAEnabled {
			return s.authRedirect(req, "", "unmet_authentication_requirements"), false, ErrUnmetAuthn
		}
		return "", true, nil
	}
	if !subjectCanGrant(session, client, req.Scopes) || scopeAllowed(client, req.Scopes) != nil || !ClientAllowsClaims(client, req.Claims) {
		return s.authRedirect(req, "", "access_denied"), false, ErrAccessDenied
	}
	if ConsentNeeded(req, session.ID) {
		return "", false, ErrConsentRequired
	}
	code, err := cryptoutil.RandomToken(32)
	if err != nil {
		return "", false, err
	}
	_, err = s.Store.IssueAuthorizationCode(ctx, identity.Hash(requestRaw), identity.Hash(browserRaw), identity.Hash(sessionRaw), identity.Hash(code), now.Add(s.authCodeTTL))
	if err != nil {
		if errors.Is(err, ErrAccessDenied) || errors.Is(err, ErrUnmetAuthn) || errors.Is(err, ErrLoginRequired) {
			return s.authRedirect(req, "", authorizationError(err)), false, err
		}
		return "", false, err
	}
	return s.authRedirect(req, code, ""), false, nil
}

func subjectCanGrant(session identity.Session, client Client, scopes []string) bool {
	if client.RequireMFA && !meetsACR(session.AuthMethods, ACRMFA) {
		return false
	}
	if client.DynamicRegistration {
		// The code transaction intersects requested capabilities with live role
		// permissions; registration never grants a capability to a user.
		return true
	}
	perm := make(map[string]bool, len(session.Permissions))
	for _, p := range session.Permissions {
		perm[p] = true
	}
	for _, scope := range scopes {
		if identityScopes[scope] {
			continue
		}
		if !perm[scope] {
			return false
		}
	}
	return true
}

func (s *Service) ExchangeCode(ctx context.Context, client Client, code, redirectURI, verifier string, now time.Time, a identity.Audit) (TokenResponse, error) {
	if !cryptoutil.ValidToken(code) || !validVerifier(verifier) {
		return TokenResponse{}, ErrInvalidGrant
	}
	challenge := sha256.Sum256([]byte(verifier))
	return s.Store.RedeemCode(ctx, client, identity.Hash(code), redirectURI, base64.RawURLEncoding.EncodeToString(challenge[:]), now, a,
		func(grant CodeGrant, key SigningKey, issuedAt time.Time) (TokenMaterial, error) {
			return s.issueTokens(grant, key, issuedAt, contains(grant.Scopes, "offline_access") && grant.Client.RefreshTokensEnabled)
		})
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// tokensForGrant is a side-effect-free encoder used by tests and internal callers.
// Live exchanges MUST enter through RedeemCode/RedeemRefresh, never this helper.
func (s *Service) tokensForGrant(ctx context.Context, grant CodeGrant, now time.Time, refresh bool) (TokenResponse, error) {
	key, err := s.Store.ActiveSigningKey(ctx)
	if err != nil {
		return TokenResponse{}, err
	}
	material, err := s.issueTokens(grant, key, now, refresh)
	return material.Response, err
}
func (s *Service) issueTokens(grant CodeGrant, keyRecord SigningKey, now time.Time, refresh bool) (TokenMaterial, error) {
	private, err := s.cachedPrivateKey(keyRecord)
	if err != nil {
		return TokenMaterial{}, err
	}
	ttl := grant.Client.AccessTokenTTL
	if ttl < 30*time.Second || ttl > time.Hour {
		return TokenMaterial{}, errors.New("invalid stored token lifetime")
	}
	expires := now.Add(ttl)
	jti, err := cryptoutil.RandomToken(16)
	if err != nil {
		return TokenMaterial{}, err
	}
	scopeString := strings.Join(grant.Scopes, " ")
	base := tokenClaims{Issuer: s.issuer, Subject: grant.Subject.ID, Audience: grant.Client.ClientID, ClientID: grant.Client.ClientID, IssuedAt: now.Unix(), ExpiresAt: expires.Unix(), JWTID: jti, Scope: scopeString}
	access, err := signJWT(keyRecord.KID, private, constrainIdentityClaims(withIdentityClaims(base, grant.Subject, grant.Scopes, false, grant.Claims.UserInfo), grant.Claims.UserInfoValues))
	if err != nil {
		return TokenMaterial{}, err
	}
	response := TokenResponse{AccessToken: access, TokenType: "Bearer", ExpiresIn: int64(ttl.Seconds()), Scope: scopeString}
	if contains(grant.Scopes, "openid") {
		acr := grant.Subject.ACR
		if acr == "" {
			acr = acrForMethods(grant.Subject.AuthMethods)
		}
		if !meetsACR(grant.Subject.AuthMethods, acr) || acr == "" {
			return TokenMaterial{}, errors.New("invalid stored authentication context")
		}
		digest := sha256.Sum256([]byte(access))
		claims := tokenClaims{Issuer: s.issuer, Subject: grant.Subject.ID, Audience: grant.Client.ClientID, IssuedAt: now.Unix(), ExpiresAt: expires.Unix(), AuthTime: grant.Subject.AuthTime.Unix(), ACR: acr, Nonce: grant.Nonce, AMR: append([]string(nil), grant.Subject.AuthMethods...), SID: grant.Subject.SessionID, AccessTokenHash: base64.RawURLEncoding.EncodeToString(digest[:16])}
		response.IDToken, err = signJWT(keyRecord.KID, private, constrainIdentityClaims(withIdentityClaims(claims, grant.Subject, grant.Scopes, true, grant.Claims.IDToken), grant.Claims.IDTokenValues))
		if err != nil {
			return TokenMaterial{}, err
		}
	}
	material := TokenMaterial{Response: response}
	if refresh {
		raw, err := cryptoutil.RandomToken(32)
		if err != nil {
			return TokenMaterial{}, err
		}
		material.Response.RefreshToken = raw
		material.RefreshHash = identity.Hash(raw)
		material.IdleExpiresAt = now.Add(s.refreshIdleTTL)
		material.AbsoluteExpiresAt = now.Add(s.refreshAbsoluteTTL)
	}
	return material, nil
}

func withIdentityClaims(c tokenClaims, subject Subject, scopes []string, includeAMR bool, selected []string) tokenClaims {
	if contains(scopes, "profile") || contains(selected, "preferred_username") {
		c.Username = subject.Username
	}
	if contains(scopes, "profile") || contains(selected, "name") {
		c.Name = subject.DisplayName
	}
	if subject.Email != "" {
		if contains(scopes, "email") || contains(selected, "email") {
			c.Email = subject.Email
		}
		if contains(scopes, "email") || contains(selected, "email_verified") {
			v := subject.EmailVerified
			c.EmailVerified = &v
		}
	}
	if contains(scopes, "groups") {
		roles := append([]string{}, subject.Roles...)
		c.Groups = &roles
	}
	if contains(scopes, "roles") {
		roles := append([]string{}, subject.Roles...)
		c.Roles = &roles
	}
	if includeAMR {
		c.AMR = append([]string(nil), subject.AuthMethods...)
	}
	return c
}

func (s *Service) privateKey(ctx context.Context) (SigningKey, *rsa.PrivateKey, error) {
	record, err := s.Store.ActiveSigningKey(ctx)
	if err != nil {
		return record, nil, err
	}
	key, err := s.cachedPrivateKey(record)
	return record, key, err
}

func (s *Service) VerifyAccessToken(ctx context.Context, raw string, now time.Time) (tokenClaims, error) {
	kid, err := tokenHeader(raw)
	if err != nil {
		return tokenClaims{}, ErrInvalidGrant
	}
	record, err := s.Store.SigningKey(ctx, kid)
	if errors.Is(err, ErrSigningKeyNotFound) {
		return tokenClaims{}, ErrInvalidGrant
	}
	if err != nil {
		return tokenClaims{}, err
	}
	public, err := s.cachedPublic(record)
	if err != nil {
		return tokenClaims{}, err
	}
	claims, err := verifyJWT(raw, public, s.issuer, now, true)
	if err != nil || claims.ClientID == "" || claims.JWTID == "" || claims.Scope == "" || claims.Audience != claims.ClientID {
		return tokenClaims{}, ErrInvalidGrant
	}
	return claims, nil
}

func (s *Service) UserInfo(ctx context.Context, raw string, now time.Time) (map[string]any, error) {
	claims, err := s.VerifyAccessToken(ctx, raw, now)
	if err != nil {
		return nil, err
	}
	return userInfoClaims(claims)
}

func userInfoClaims(claims tokenClaims) (map[string]any, error) {
	out := map[string]any{"sub": claims.Subject}
	scopes, err := parseScopes(claims.Scope)
	if err != nil {
		return nil, ErrInvalidGrant
	}
	if !contains(scopes, "openid") {
		return nil, ErrInsufficientScope
	}
	// The signed access token contains only the UserInfo-scoped/selected claims.
	// Do not infer a second authorization model from mutable local role data here.
	if claims.Username != "" {
		out["preferred_username"] = claims.Username
	}
	if claims.Name != "" {
		out["name"] = claims.Name
	}
	if claims.Email != "" {
		out["email"] = claims.Email
	}
	if claims.EmailVerified != nil {
		out["email_verified"] = *claims.EmailVerified
	}
	if claims.Groups != nil {
		out["groups"] = append([]string{}, (*claims.Groups)...)
	}
	if claims.Roles != nil {
		out["roles"] = append([]string{}, (*claims.Roles)...)
	}
	return out, nil
}

func (s *Service) Refresh(ctx context.Context, client Client, raw, requestedScope string, now time.Time, a identity.Audit) (TokenResponse, error) {
	if !cryptoutil.ValidToken(raw) {
		return TokenResponse{}, ErrInvalidGrant
	}
	var requested []string
	var err error
	if requestedScope != "" {
		requested, err = parseScopes(requestedScope)
		if err != nil {
			return TokenResponse{}, err
		}
	}
	return s.Store.RedeemRefresh(ctx, client, identity.Hash(raw), requested, now, a, func(grant CodeGrant, key SigningKey, issuedAt time.Time) (TokenMaterial, error) {
		return s.issueTokens(grant, key, issuedAt, true)
	})
}

func subset(a, b []string) bool {
	set := map[string]bool{}
	for _, v := range b {
		set[v] = true
	}
	for _, v := range a {
		if !set[v] {
			return false
		}
	}
	return true
}

func (s *Service) VerifyClientSecret(client Client, supplied string) bool {
	if client.Type == "public" {
		return supplied == ""
	}
	if supplied == "" || len(supplied) > 1024 {
		return false
	}
	return hmac.Equal(client.SecretHash, identity.Hash(supplied))
}

func (s *Service) Revoke(ctx context.Context, token string, client Client, a identity.Audit) error {
	if token == "" || len(token) > 2048 {
		return nil
	}
	return s.Store.RevokeRefreshToken(ctx, identity.Hash(token), client, a)
}

func (s *Service) LogoutClient(ctx context.Context, idTokenHint string, now time.Time) (Client, string, string, error) {
	kid, err := tokenHeader(idTokenHint)
	if err != nil {
		return Client{}, "", "", ErrInvalidGrant
	}
	record, err := s.Store.SigningKey(ctx, kid)
	if errors.Is(err, ErrSigningKeyNotFound) {
		return Client{}, "", "", ErrInvalidGrant
	}
	if err != nil {
		return Client{}, "", "", err
	}
	public, err := s.cachedPublic(record)
	if err != nil {
		return Client{}, "", "", err
	}
	// RP-Initiated Logout recommends accepting an otherwise-valid ID Token
	// hint for a current/recent OP session even after exp. Signature, issuer,
	// audience, subject and token shape still have to validate.
	claims, err := verifyJWT(idTokenHint, public, s.issuer, now, false)
	if err != nil || claims.Audience == "" || claims.Subject == "" || claims.AuthTime == 0 || claims.ClientID != "" {
		return Client{}, "", "", ErrInvalidGrant
	}
	client, err := s.Store.Client(ctx, claims.Audience)
	if errors.Is(err, ErrInvalidClient) || err == nil && !client.Enabled {
		return Client{}, "", "", ErrInvalidGrant
	}
	if err != nil {
		return Client{}, "", "", err
	}
	return client, claims.Subject, claims.SID, nil
}

func authorizationRedirectWithIssuer(issuer string, req AuthorizationRequest, code, oauthErr string) string {
	u, err := url.Parse(req.RedirectURI)
	if err != nil {
		return ""
	}
	q := u.Query()
	if code != "" {
		q.Set("code", code)
	}
	if oauthErr != "" {
		q.Set("error", oauthErr)
	}
	if req.State != "" {
		q.Set("state", req.State)
	}
	q.Set("iss", issuer)
	u.RawQuery = q.Encode()
	return u.String()
}

func (s *Service) authRedirect(req AuthorizationRequest, code, oauthErr string) string {
	return authorizationRedirectWithIssuer(s.issuer, req, code, oauthErr)
}

func (s *Service) PublicOriginAllowed(ctx context.Context, origin string) (bool, error) {
	want, ok := canonicalOrigin(origin)
	if !ok {
		return false, ErrInvalidRequest
	}
	return s.Store.PublicOriginAllowed(ctx, want)
}

// An equality-constrained optional claim that does not match is omitted, not
// fabricated and not widened into its whole scope (OIDC Core 5.5.1).
func constrainIdentityClaims(c tokenClaims, filters map[string][]json.RawMessage) tokenClaims {
	matches := func(name string, value any) bool {
		candidates, ok := filters[name]
		if !ok {
			return true
		}
		actual, _ := json.Marshal(value)
		for _, candidate := range candidates {
			var v any
			if json.Unmarshal(candidate, &v) == nil {
				canonical, _ := json.Marshal(v)
				if string(canonical) == string(actual) {
					return true
				}
			}
		}
		return false
	}
	if !matches("name", c.Name) {
		c.Name = ""
	}
	if !matches("preferred_username", c.Username) {
		c.Username = ""
	}
	if !matches("email", c.Email) {
		c.Email = ""
	}
	if c.EmailVerified != nil && !matches("email_verified", *c.EmailVerified) {
		c.EmailVerified = nil
	}
	return c
}
