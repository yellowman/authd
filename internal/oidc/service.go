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
	"time"

	"github.com/yellowman/authd/internal/cryptoutil"
	"github.com/yellowman/authd/internal/identity"
)

type Service struct {
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
	if _, err := s.Store.ActiveSigningKey(ctx); err == nil {
		return nil
	} else if !errors.Is(err, ErrSigningKeyNotFound) {
		return err
	}
	generated, err := generateSigningKey(s.masterKey)
	if err != nil {
		return err
	}
	_, err = s.Store.InstallSigningKey(ctx, generated, false)
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
	for _, key := range keys {
		if key.Algorithm != "RS256" || len(key.PublicJWK) == 0 {
			continue
		}
		items = append(items, json.RawMessage(key.PublicJWK))
	}
	return json.Marshal(map[string]any{"keys": items})
}

func (s *Service) BeginAuthorization(ctx context.Context, values map[string][]string, now time.Time) (string, AuthorizationRequest, Client, error) {
	clientID, err := single(values, "client_id", true, 256)
	if err != nil {
		return "", AuthorizationRequest{}, Client{}, err
	}
	client, err := s.Store.Client(ctx, clientID)
	if err != nil || !client.Enabled {
		return "", AuthorizationRequest{}, Client{}, ErrInvalidClient
	}
	redirect, err := single(values, "redirect_uri", true, 4096)
	if err != nil || !contains(client.RedirectURIs, redirect) {
		return "", AuthorizationRequest{}, Client{}, ErrInvalidRequest
	}
	responseType, err := single(values, "response_type", true, 32)
	if err != nil || responseType != "code" {
		return "", AuthorizationRequest{ClientID: clientID, RedirectURI: redirect}, client, ErrInvalidRequest
	}
	rawScope, err := single(values, "scope", true, 4096)
	if err != nil {
		return "", AuthorizationRequest{ClientID: clientID, RedirectURI: redirect}, client, ErrInvalidScope
	}
	scopes, err := parseScopes(rawScope)
	if err != nil || scopeAllowed(client, scopes) != nil {
		return "", AuthorizationRequest{ClientID: clientID, RedirectURI: redirect}, client, ErrInvalidScope
	}
	challenge, err := single(values, "code_challenge", true, 128)
	if err != nil || !validPKCEChallenge(challenge) {
		return "", AuthorizationRequest{ClientID: clientID, RedirectURI: redirect}, client, ErrInvalidRequest
	}
	method, err := single(values, "code_challenge_method", true, 16)
	if err != nil || method != "S256" {
		return "", AuthorizationRequest{ClientID: clientID, RedirectURI: redirect}, client, ErrInvalidRequest
	}
	state, err := single(values, "state", false, 2048)
	if err != nil {
		return "", AuthorizationRequest{ClientID: clientID, RedirectURI: redirect}, client, err
	}
	nonce, err := single(values, "nonce", false, 2048)
	if err != nil {
		return "", AuthorizationRequest{ClientID: clientID, RedirectURI: redirect}, client, err
	}
	loginHint, err := single(values, "login_hint", false, 512)
	if err != nil {
		return "", AuthorizationRequest{ClientID: clientID, RedirectURI: redirect}, client, err
	}
	prompt, err := single(values, "prompt", false, 32)
	if err != nil || (prompt != "" && prompt != "none" && prompt != "login") {
		return "", AuthorizationRequest{ClientID: clientID, RedirectURI: redirect}, client, ErrInvalidRequest
	}
	maxAgeRaw, err := single(values, "max_age", false, 16)
	if err != nil {
		return "", AuthorizationRequest{ClientID: clientID, RedirectURI: redirect}, client, err
	}
	minAuth, err := parseMaxAge(maxAgeRaw, now)
	if err != nil {
		return "", AuthorizationRequest{ClientID: clientID, RedirectURI: redirect}, client, err
	}
	if prompt == "login" {
		t := now
		minAuth = &t
	}
	acrRaw, err := single(values, "acr_values", false, 1024)
	if err != nil {
		return "", AuthorizationRequest{ClientID: clientID, RedirectURI: redirect}, client, err
	}
	requiredACR, err := parseACRValues(acrRaw, client, scopes)
	if err != nil {
		return "", AuthorizationRequest{ClientID: clientID, RedirectURI: redirect}, client, err
	}
	req := AuthorizationRequest{ClientID: clientID, RedirectURI: redirect, Scopes: scopes, RequiredACR: requiredACR, State: state, Nonce: nonce, CodeChallenge: challenge, LoginHint: loginHint, Prompt: prompt, MinAuthTime: minAuth, CreatedAt: now.UTC(), ExpiresAt: now.Add(10 * time.Minute).UTC()}
	raw, err := cryptoutil.RandomToken(32)
	if err != nil {
		return "", AuthorizationRequest{}, Client{}, err
	}
	if err = s.Store.CreateAuthorizationRequest(ctx, identity.Hash(raw), req); err != nil {
		return "", AuthorizationRequest{}, Client{}, err
	}
	return raw, req, client, nil
}

func (s *Service) ContinueAuthorization(ctx context.Context, requestRaw, sessionRaw string, now time.Time) (redirect string, interaction bool, err error) {
	if !cryptoutil.ValidToken(requestRaw) {
		return "", false, ErrInvalidRequest
	}
	req, client, err := s.Store.AuthorizationRequest(ctx, identity.Hash(requestRaw))
	if err != nil {
		return "", false, ErrInvalidRequest
	}
	if !now.Before(req.ExpiresAt) || !client.Enabled {
		return s.authRedirect(req, "", "invalid_request"), false, ErrInvalidRequest
	}
	session, sessionErr := s.Sessions.Session(ctx, sessionRaw)
	needLogin := sessionErr != nil || !session.User.Enabled || session.User.ForcePasswordChange
	if !needLogin && req.MinAuthTime != nil && session.AuthTime.Before(*req.MinAuthTime) {
		needLogin = true
	}
	mfa := contains(session.AuthMethods, "otp") || contains(session.AuthMethods, "recovery")
	if !needLogin && !meetsACR(session.AuthMethods, req.RequiredACR) {
		needLogin = true
	}
	if needLogin {
		if sessionErr == nil && req.RequiredACR == ACRMFA && !session.User.MFAEnabled {
			return s.authRedirect(req, "", "unmet_authentication_requirements"), false, ErrUnmetAuthn
		}
		if req.Prompt == "none" {
			return s.authRedirect(req, "", "login_required"), false, ErrLoginRequired
		}
		// A session authenticated after this request but still lacking required MFA
		// cannot be improved by looping through login again if the account has no
		// enrolled factor. Treat that as denied rather than a redirect loop.
		if sessionErr == nil && req.RequiredACR == ACRMFA && !mfa && !session.AuthTime.Before(req.CreatedAt) {
			return s.authRedirect(req, "", "unmet_authentication_requirements"), false, ErrUnmetAuthn
		}
		return "", true, nil
	}
	if !subjectCanGrant(session, client, req.Scopes) {
		return s.authRedirect(req, "", "access_denied"), false, ErrAccessDenied
	}
	code, err := cryptoutil.RandomToken(32)
	if err != nil {
		return "", false, err
	}
	_, err = s.Store.IssueAuthorizationCode(ctx, identity.Hash(requestRaw), identity.Hash(sessionRaw), identity.Hash(code), now.Add(s.authCodeTTL))
	if err != nil {
		if errors.Is(err, ErrAccessDenied) {
			return s.authRedirect(req, "", "access_denied"), false, err
		}
		return "", false, err
	}
	return s.authRedirect(req, code, ""), false, nil
}

func subjectCanGrant(session identity.Session, client Client, scopes []string) bool {
	if client.RequireMFA && !contains(session.AuthMethods, "otp") && !contains(session.AuthMethods, "recovery") {
		return false
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

func (s *Service) ExchangeCode(ctx context.Context, client Client, code, redirectURI, verifier string, now time.Time) (TokenResponse, error) {
	if !cryptoutil.ValidToken(code) || !validVerifier(verifier) {
		return TokenResponse{}, ErrInvalidGrant
	}
	challenge := sha256.Sum256([]byte(verifier))
	encodedChallenge := base64.RawURLEncoding.EncodeToString(challenge[:])
	grant, err := s.Store.ConsumeAuthorizationCode(ctx, identity.Hash(code), client.ClientID, redirectURI, encodedChallenge, now)
	if err != nil {
		return TokenResponse{}, ErrInvalidGrant
	}
	return s.tokensForGrant(ctx, grant, now, contains(grant.Scopes, "offline_access"))
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

func (s *Service) tokensForGrant(ctx context.Context, grant CodeGrant, now time.Time, allowRefresh bool) (TokenResponse, error) {
	keyRecord, private, err := s.privateKey(ctx)
	if err != nil {
		return TokenResponse{}, err
	}
	ttl := grant.Client.AccessTokenTTL
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	expires := now.Add(ttl)
	jti, err := cryptoutil.RandomToken(16)
	if err != nil {
		return TokenResponse{}, err
	}
	scopeString := strings.Join(grant.Scopes, " ")
	base := tokenClaims{Issuer: s.issuer, Subject: grant.Subject.ID, Audience: grant.Client.ClientID, ClientID: grant.Client.ClientID, IssuedAt: now.Unix(), ExpiresAt: expires.Unix(), JWTID: jti, Scope: scopeString}
	access, err := signJWT(keyRecord.KID, private, withIdentityClaims(base, grant.Subject, grant.Scopes, false, ""))
	if err != nil {
		return TokenResponse{}, err
	}
	response := TokenResponse{AccessToken: access, TokenType: "Bearer", ExpiresIn: int64(ttl.Seconds()), Scope: scopeString}
	if contains(grant.Scopes, "openid") {
		idClaims := tokenClaims{Issuer: s.issuer, Subject: grant.Subject.ID, Audience: grant.Client.ClientID, IssuedAt: now.Unix(), ExpiresAt: expires.Unix(), AuthTime: grant.Subject.AuthTime.Unix(), ACR: acrForMethods(grant.Subject.AuthMethods), Nonce: grant.Nonce, AMR: append([]string(nil), grant.Subject.AuthMethods...), SID: grant.Subject.SessionID}
		response.IDToken, err = signJWT(keyRecord.KID, private, withIdentityClaims(idClaims, grant.Subject, grant.Scopes, true, grant.Nonce))
		if err != nil {
			return TokenResponse{}, err
		}
	}
	if allowRefresh && grant.Client.RefreshTokensEnabled {
		refresh, e := cryptoutil.RandomToken(32)
		if e != nil {
			return TokenResponse{}, e
		}
		if e = s.Store.CreateRefreshFamily(ctx, grant.Subject.ID, grant.Subject.SessionID, grant.Client.ID, grant.Scopes, grant.Subject.AuthTime, grant.Subject.AuthMethods, identity.Hash(refresh), now.Add(s.refreshIdleTTL), now.Add(s.refreshAbsoluteTTL)); e != nil {
			return TokenResponse{}, e
		}
		response.RefreshToken = refresh
	}
	return response, nil
}

func withIdentityClaims(c tokenClaims, subject Subject, scopes []string, includeAMR bool, _ string) tokenClaims {
	if contains(scopes, "profile") {
		c.Username = subject.Username
		c.Name = subject.DisplayName
	}
	if contains(scopes, "email") && subject.Email != "" {
		c.Email = subject.Email
		verified := subject.EmailVerified
		c.EmailVerified = &verified
	}
	if contains(scopes, "groups") {
		c.Groups = append([]string(nil), subject.Roles...)
	}
	if contains(scopes, "roles") {
		c.Roles = append([]string(nil), subject.Roles...)
	}
	if includeAMR {
		c.AMR = append([]string(nil), subject.AuthMethods...)
	}
	return c
}

func (s *Service) privateKey(ctx context.Context) (SigningKey, *rsa.PrivateKey, error) {
	record, err := s.Store.ActiveSigningKey(ctx)
	if err != nil {
		return SigningKey{}, nil, err
	}
	plain, err := cryptoutil.Open(s.masterKey, record.Ciphertext, []byte("oidc-signing-key:"+record.KID))
	if err != nil {
		return SigningKey{}, nil, err
	}
	key, err := parsePrivateKey(plain)
	return record, key, err
}

func (s *Service) VerifyAccessToken(ctx context.Context, raw string, now time.Time) (tokenClaims, error) {
	kid, err := tokenHeader(raw)
	if err != nil {
		return tokenClaims{}, ErrInvalidGrant
	}
	record, err := s.Store.SigningKey(ctx, kid)
	if err != nil {
		return tokenClaims{}, ErrInvalidGrant
	}
	public, err := parsePublicJWK(record.PublicJWK)
	if err != nil {
		return tokenClaims{}, ErrInvalidGrant
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
	out := map[string]any{"sub": claims.Subject}
	scopes, err := parseScopes(claims.Scope)
	if err != nil {
		return nil, ErrInvalidGrant
	}
	if contains(scopes, "profile") {
		if claims.Username != "" {
			out["preferred_username"] = claims.Username
		}
		if claims.Name != "" {
			out["name"] = claims.Name
		}
	}
	if contains(scopes, "email") && claims.Email != "" {
		out["email"] = claims.Email
		if claims.EmailVerified != nil {
			out["email_verified"] = *claims.EmailVerified
		}
	}
	if contains(scopes, "groups") {
		out["groups"] = claims.Groups
	}
	if contains(scopes, "roles") {
		out["roles"] = claims.Roles
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
			return TokenResponse{}, ErrInvalidScope
		}
	}
	replacement, err := cryptoutil.RandomToken(32)
	if err != nil {
		return TokenResponse{}, err
	}
	grant, err := s.Store.RotateRefreshToken(ctx, identity.Hash(raw), identity.Hash(replacement), client.ClientID, requested, now, now.Add(s.refreshIdleTTL), a)
	if err != nil {
		if errors.Is(err, ErrInvalidScope) {
			return TokenResponse{}, ErrInvalidScope
		}
		return TokenResponse{}, ErrInvalidGrant
	}
	codeGrant := CodeGrant{Client: grant.Client, Subject: grant.Subject, Scopes: grant.Scopes}
	response, err := s.tokensForGrant(ctx, codeGrant, now, false)
	if err != nil {
		return TokenResponse{}, err
	}
	response.RefreshToken = replacement
	return response, nil
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

func (s *Service) Revoke(ctx context.Context, token, clientID string, a identity.Audit) error {
	if token == "" || len(token) > 2048 {
		return nil
	}
	return s.Store.RevokeRefreshToken(ctx, identity.Hash(token), clientID, a)
}

func (s *Service) LogoutClient(ctx context.Context, idTokenHint string, now time.Time) (Client, string, string, error) {
	kid, err := tokenHeader(idTokenHint)
	if err != nil {
		return Client{}, "", "", ErrInvalidGrant
	}
	record, err := s.Store.SigningKey(ctx, kid)
	if err != nil {
		return Client{}, "", "", ErrInvalidGrant
	}
	public, err := parsePublicJWK(record.PublicJWK)
	if err != nil {
		return Client{}, "", "", ErrInvalidGrant
	}
	// RP-Initiated Logout recommends accepting an otherwise-valid ID Token
	// hint for a current/recent OP session even after exp. Signature, issuer,
	// audience, subject and token shape still have to validate.
	claims, err := verifyJWT(idTokenHint, public, s.issuer, now, false)
	if err != nil || claims.Audience == "" || claims.Subject == "" || claims.AuthTime == 0 || claims.ClientID != "" {
		return Client{}, "", "", ErrInvalidGrant
	}
	client, err := s.Store.Client(ctx, claims.Audience)
	if err != nil || !client.Enabled {
		return Client{}, "", "", ErrInvalidGrant
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

func (s *Service) PublicOriginAllowed(ctx context.Context, origin string) bool {
	want, ok := canonicalOrigin(origin)
	if !ok {
		return false
	}
	redirects, err := s.Store.PublicClientRedirectURIs(ctx)
	if err != nil {
		return false
	}
	for _, redirect := range redirects {
		u, err := url.Parse(redirect)
		if err != nil {
			continue
		}
		candidate, ok := canonicalOrigin(u.Scheme + "://" + u.Host)
		if ok && candidate == want {
			return true
		}
	}
	return false
}
