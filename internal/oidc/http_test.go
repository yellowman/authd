package oidc

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yellowman/authd/internal/cryptoutil"
	"github.com/yellowman/authd/internal/identity"
	"github.com/yellowman/authd/internal/requestid"
)

type fakeCode struct {
	grant     CodeGrant
	challenge string
	expires   time.Time
	consumed  bool
}
type fakeRefresh struct {
	grant    RefreshGrant
	clientID string
	expires  time.Time
	consumed bool
	family   string
}
type fakeOIDCStore struct {
	mu            sync.Mutex
	client        Client
	requests      map[string]AuthorizationRequest
	codes         map[string]*fakeCode
	refresh       map[string]*fakeRefresh
	keys          map[string]SigningKey
	active        string
	sessions      map[string]identity.Session
	familyRevoked map[string]bool
}

func newFakeOIDCStore(c Client) *fakeOIDCStore {
	return &fakeOIDCStore{client: c, requests: map[string]AuthorizationRequest{}, codes: map[string]*fakeCode{}, refresh: map[string]*fakeRefresh{}, keys: map[string]SigningKey{}, sessions: map[string]identity.Session{}, familyRevoked: map[string]bool{}}
}
func hashKey(v []byte) string { return base64.RawURLEncoding.EncodeToString(v) }
func (f *fakeOIDCStore) Client(_ context.Context, id string) (Client, error) {
	if id != f.client.ClientID {
		return Client{}, ErrInvalidClient
	}
	return f.client, nil
}
func (f *fakeOIDCStore) PublicClientRedirectURIs(_ context.Context) ([]string, error) {
	if !f.client.Enabled || f.client.Type != "public" {
		return nil, nil
	}
	return append([]string(nil), f.client.RedirectURIs...), nil
}
func (f *fakeOIDCStore) CreateAuthorizationRequest(_ context.Context, h []byte, r AuthorizationRequest) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests[hashKey(h)] = r
	return nil
}
func (f *fakeOIDCStore) AuthorizationRequest(_ context.Context, h []byte) (AuthorizationRequest, Client, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r, ok := f.requests[hashKey(h)]
	if !ok {
		return r, Client{}, ErrInvalidRequest
	}
	return r, f.client, nil
}
func (f *fakeOIDCStore) IssueAuthorizationCode(_ context.Context, rh, sh, ch []byte, exp time.Time) (CodeGrant, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r, ok := f.requests[hashKey(rh)]
	if !ok {
		return CodeGrant{}, ErrInvalidRequest
	}
	sess, ok := f.sessions[hashKey(sh)]
	if !ok {
		return CodeGrant{}, ErrLoginRequired
	}
	subject := Subject{ID: sess.User.ID, Username: sess.User.Username, DisplayName: sess.User.DisplayName, Email: sess.User.Email, EmailVerified: sess.User.EmailVerified, Enabled: true, Roles: sess.Roles, Permissions: sess.Permissions, AuthTime: sess.AuthTime, AuthMethods: sess.AuthMethods}
	if !subjectCanGrant(sess, f.client, r.Scopes) {
		return CodeGrant{}, ErrAccessDenied
	}
	g := CodeGrant{Client: f.client, Subject: subject, RedirectURI: r.RedirectURI, Scopes: r.Scopes, Nonce: r.Nonce}
	f.codes[hashKey(ch)] = &fakeCode{grant: g, challenge: r.CodeChallenge, expires: exp}
	delete(f.requests, hashKey(rh))
	return g, nil
}
func (f *fakeOIDCStore) ConsumeAuthorizationCode(_ context.Context, h []byte, clientID, redirect, challenge string, now time.Time) (CodeGrant, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	rec, ok := f.codes[hashKey(h)]
	if !ok || rec.consumed || !now.Before(rec.expires) || clientID != rec.grant.Client.ClientID || redirect != rec.grant.RedirectURI || !hmac.Equal([]byte(challenge), []byte(rec.challenge)) {
		return CodeGrant{}, ErrInvalidGrant
	}
	rec.consumed = true
	return rec.grant, nil
}
func (f *fakeOIDCStore) CreateRefreshFamily(_ context.Context, userID, clientDBID string, scopes []string, authTime time.Time, methods []string, h []byte, idle, absolute time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	family := "family-1"
	subject := Subject{ID: userID, Username: "alice", DisplayName: "Alice", Email: "alice@example.test", EmailVerified: true, Enabled: true, Roles: []string{"bdcmaps-admin"}, Permissions: []string{"bdcmaps.read"}, AuthTime: authTime, AuthMethods: methods}
	f.refresh[hashKey(h)] = &fakeRefresh{grant: RefreshGrant{FamilyID: family, Client: f.client, Subject: subject, Scopes: append([]string(nil), scopes...)}, clientID: f.client.ClientID, expires: minTime(idle, absolute), family: family}
	return nil
}
func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
func (f *fakeOIDCStore) RotateRefreshToken(_ context.Context, h, replacement []byte, clientID string, requested []string, now, idle time.Time, _ identity.Audit) (RefreshGrant, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	rec, ok := f.refresh[hashKey(h)]
	if !ok || f.familyRevoked[rec.family] || clientID != rec.clientID || !now.Before(rec.expires) {
		return RefreshGrant{}, ErrInvalidGrant
	}
	if rec.consumed {
		f.familyRevoked[rec.family] = true
		return RefreshGrant{}, ErrRefreshReuse
	}
	scopes := append([]string(nil), rec.grant.Scopes...)
	if len(requested) > 0 {
		if !subset(requested, scopes) {
			return RefreshGrant{}, ErrInvalidScope
		}
		scopes = append([]string(nil), requested...)
	}
	rec.consumed = true
	g := rec.grant
	g.Scopes = scopes
	f.refresh[hashKey(replacement)] = &fakeRefresh{grant: g, clientID: clientID, expires: idle, family: rec.family}
	return g, nil
}
func (f *fakeOIDCStore) RevokeRefreshToken(_ context.Context, h []byte, clientID string, _ identity.Audit) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if rec := f.refresh[hashKey(h)]; rec != nil && rec.clientID == clientID {
		f.familyRevoked[rec.family] = true
	}
	return nil
}
func (f *fakeOIDCStore) SigningKeys(_ context.Context) ([]SigningKey, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := []SigningKey{}
	for _, k := range f.keys {
		out = append(out, k)
	}
	return out, nil
}
func (f *fakeOIDCStore) ActiveSigningKey(_ context.Context) (SigningKey, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.active == "" {
		return SigningKey{}, ErrSigningKeyNotFound
	}
	return f.keys[f.active], nil
}
func (f *fakeOIDCStore) SigningKey(_ context.Context, kid string) (SigningKey, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	k, ok := f.keys[kid]
	if !ok {
		return k, ErrSigningKeyNotFound
	}
	return k, nil
}
func (f *fakeOIDCStore) InstallSigningKey(_ context.Context, k SigningKey, rotate bool) (SigningKey, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.active != "" && !rotate {
		return f.keys[f.active], nil
	}
	if rotate && f.active != "" {
		old := f.keys[f.active]
		old.Active = false
		now := time.Now()
		old.RetiredAt = &now
		f.keys[f.active] = old
	}
	k.ID = "key-id"
	k.Active = true
	f.keys[k.KID] = k
	f.active = k.KID
	return k, nil
}

func (f *fakeOIDCStore) AdminClients(_ context.Context, _ []byte) ([]Client, error) {
	return []Client{f.client}, nil
}
func (f *fakeOIDCStore) CreateClient(_ context.Context, _ []byte, edit ClientEdit, secret []byte, _ identity.Audit) (Client, error) {
	c := Client{ID: edit.ID, ClientID: edit.ClientID, Name: edit.Name, Type: edit.Type, SecretHash: secret, Enabled: edit.Enabled, RequireMFA: edit.RequireMFA, RefreshTokensEnabled: edit.RefreshTokensEnabled, AccessTokenTTL: edit.AccessTokenTTL, RedirectURIs: edit.RedirectURIs, LogoutURIs: edit.LogoutURIs, IdentityScopes: edit.IdentityScopes, PermissionIDs: edit.PermissionIDs}
	f.client = c
	return c, nil
}
func (f *fakeOIDCStore) UpdateClient(_ context.Context, _ []byte, edit ClientEdit, _ identity.Audit) error {
	f.client.Name = edit.Name
	f.client.Enabled = edit.Enabled
	f.client.RequireMFA = edit.RequireMFA
	f.client.RefreshTokensEnabled = edit.RefreshTokensEnabled
	f.client.AccessTokenTTL = edit.AccessTokenTTL
	f.client.RedirectURIs = edit.RedirectURIs
	f.client.LogoutURIs = edit.LogoutURIs
	f.client.IdentityScopes = edit.IdentityScopes
	f.client.PermissionIDs = edit.PermissionIDs
	return nil
}
func (f *fakeOIDCStore) RotateClientSecret(_ context.Context, _ []byte, _ string, secret []byte, _ identity.Audit) error {
	f.client.SecretHash = secret
	return nil
}

type fakeSessions struct {
	store *fakeOIDCStore
	byRaw map[string]identity.Session
	ended bool
}

func (s *fakeSessions) Session(_ context.Context, raw string) (identity.Session, error) {
	v, ok := s.byRaw[raw]
	if !ok {
		return v, identity.ErrSession
	}
	return v, nil
}
func (s *fakeSessions) EndSession(_ context.Context, raw string, _ identity.Audit) error {
	if _, ok := s.byRaw[raw]; !ok {
		return identity.ErrSession
	}
	delete(s.byRaw, raw)
	s.ended = true
	return nil
}

func providerFixture(t *testing.T) (*HTTP, *Service, *fakeOIDCStore, *fakeSessions, string, string) {
	t.Helper()
	master := sha256.Sum256([]byte("test master key material for oidc"))
	secret := "client-secret"
	client := Client{ID: "00000000-0000-4000-8000-000000000099", ClientID: "bdcmaps", Name: "BDC Maps", Type: "confidential", SecretHash: identity.Hash(secret), Enabled: true, RefreshTokensEnabled: true, AccessTokenTTL: 5 * time.Minute, RedirectURIs: []string{"https://bdc.example.test/auth/callback"}, LogoutURIs: []string{"https://bdc.example.test/"}, IdentityScopes: []string{"openid", "profile", "email", "groups", "offline_access"}, Permissions: []string{"bdcmaps.read"}}
	store := newFakeOIDCStore(client)
	sessions := &fakeSessions{store: store, byRaw: map[string]identity.Session{}}
	svc, err := NewService(store, sessions, "https://auth.example.test", master[:], time.Minute, 30*24*time.Hour, 90*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err = svc.EnsureSigningKey(context.Background()); err != nil {
		t.Fatal(err)
	}
	h := NewHTTP(svc, "https://auth.example.test", false)
	sessionRaw, _ := cryptoutil.RandomToken(32)
	sess := identity.Session{User: identity.User{ID: "00000000-0000-4000-8000-000000000001", Username: "alice", DisplayName: "Alice", Email: "alice@example.test", EmailVerified: true, Enabled: true}, Roles: []string{"bdcmaps-admin"}, Permissions: []string{"bdcmaps.read"}, AuthMethods: []string{"pwd"}, AuthTime: time.Now().Add(-time.Minute)}
	sessions.byRaw[sessionRaw] = sess
	store.sessions[hashKey(identity.Hash(sessionRaw))] = sess
	return h, svc, store, sessions, sessionRaw, secret
}
func muxFor(h *HTTP) http.Handler { m := http.NewServeMux(); h.Register(m); return m }
func verifierAndChallenge() (string, string) {
	v := strings.Repeat("A", 64)
	sum := sha256.Sum256([]byte(v))
	return v, base64.RawURLEncoding.EncodeToString(sum[:])
}

func TestAuthorizationCodePKCEBDCMapsFlow(t *testing.T) {
	h, _, _, _, sessionRaw, secret := providerFixture(t)
	mux := muxFor(h)
	verifier, challenge := verifierAndChallenge()
	q := url.Values{"response_type": {"code"}, "client_id": {"bdcmaps"}, "redirect_uri": {"https://bdc.example.test/auth/callback"}, "scope": {"openid profile email groups offline_access bdcmaps.read"}, "state": {"state-1"}, "nonce": {"nonce-1"}, "code_challenge": {challenge}, "code_challenge_method": {"S256"}}
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest("GET", "https://auth.example.test/authorize?"+q.Encode(), nil))
	if w.Code != 303 || !strings.HasPrefix(w.Header().Get("Location"), "/login?") {
		t.Fatalf("authorize interaction: %d %s", w.Code, w.Header().Get("Location"))
	}
	loginURL, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	requestHandle := loginURL.Query().Get("oidc")
	if !cryptoutil.ValidToken(requestHandle) {
		t.Fatal("missing authorization continuation handle")
	}
	r := httptest.NewRequest("GET", "https://auth.example.test/authorize?request="+url.QueryEscape(requestHandle), nil)
	r.AddCookie(&http.Cookie{Name: "__Host-authd_session", Value: sessionRaw})
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != 302 {
		t.Fatalf("resume: %d %s", w.Code, w.Body.String())
	}
	callback, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	code := callback.Query().Get("code")
	if code == "" || callback.Query().Get("state") != "state-1" || callback.Query().Get("iss") != "https://auth.example.test" {
		t.Fatalf("bad callback %s", callback)
	}
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {"https://bdc.example.test/auth/callback"}, "client_id": {"bdcmaps"}, "client_secret": {secret}, "code_verifier": {verifier}}
	r = httptest.NewRequest("POST", "https://auth.example.test/token", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("token: %d %s", w.Code, w.Body.String())
	}
	var tokens TokenResponse
	if json.Unmarshal(w.Body.Bytes(), &tokens) != nil || tokens.AccessToken == "" || tokens.IDToken == "" || tokens.RefreshToken == "" {
		t.Fatalf("bad tokens %#v", tokens)
	}
	r = httptest.NewRequest("GET", "https://auth.example.test/userinfo", nil)
	r.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"groups":["bdcmaps-admin"]`) {
		t.Fatalf("userinfo: %d %s", w.Code, w.Body.String())
	}
	// Authorization codes are one-use.
	r = httptest.NewRequest("POST", "https://auth.example.test/token", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != 400 || !strings.Contains(w.Body.String(), "invalid_grant") {
		t.Fatal("code replay accepted")
	}
	// Refresh rotates; replay of the consumed token compromises the family.
	refreshForm := url.Values{"grant_type": {"refresh_token"}, "client_id": {"bdcmaps"}, "client_secret": {secret}, "refresh_token": {tokens.RefreshToken}}
	r = httptest.NewRequest("POST", "https://auth.example.test/token", strings.NewReader(refreshForm.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("refresh: %d %s", w.Code, w.Body.String())
	}
	var rotated TokenResponse
	_ = json.Unmarshal(w.Body.Bytes(), &rotated)
	if rotated.RefreshToken == "" || rotated.RefreshToken == tokens.RefreshToken {
		t.Fatal("refresh token was not rotated")
	}
	r = httptest.NewRequest("POST", "https://auth.example.test/token", strings.NewReader(refreshForm.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != 400 {
		t.Fatal("refresh replay accepted")
	}
}

func TestPromptNoneReturnsTrustedErrorRedirect(t *testing.T) {
	h, _, _, _, _, _ := providerFixture(t)
	mux := muxFor(h)
	_, challenge := verifierAndChallenge()
	q := url.Values{"response_type": {"code"}, "client_id": {"bdcmaps"}, "redirect_uri": {"https://bdc.example.test/auth/callback"}, "scope": {"openid"}, "state": {"s"}, "prompt": {"none"}, "code_challenge": {challenge}, "code_challenge_method": {"S256"}}
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest("GET", "https://auth.example.test/authorize?"+q.Encode(), nil))
	if w.Code != 302 {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	u, _ := url.Parse(w.Header().Get("Location"))
	if u.Query().Get("error") != "login_required" || u.Query().Get("state") != "s" {
		t.Fatalf("unexpected redirect %s", u)
	}
}
func TestUnregisteredRedirectNeverReceivesOAuthError(t *testing.T) {
	h, _, _, _, _, _ := providerFixture(t)
	mux := muxFor(h)
	_, challenge := verifierAndChallenge()
	q := url.Values{"response_type": {"code"}, "client_id": {"bdcmaps"}, "redirect_uri": {"https://evil.example.test/cb"}, "scope": {"openid"}, "code_challenge": {challenge}, "code_challenge_method": {"S256"}}
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest("GET", "https://auth.example.test/authorize?"+q.Encode(), nil))
	if w.Code != 400 || w.Header().Get("Location") != "" {
		t.Fatal("unregistered redirect used")
	}
}
func TestClientSecretBasicAndLogout(t *testing.T) {
	h, _, _, sessions, sessionRaw, secret := providerFixture(t)
	mux := muxFor(h) // obtain an ID token quickly through the regular flow
	verifier, challenge := verifierAndChallenge()
	q := url.Values{"response_type": {"code"}, "client_id": {"bdcmaps"}, "redirect_uri": {"https://bdc.example.test/auth/callback"}, "scope": {"openid"}, "code_challenge": {challenge}, "code_challenge_method": {"S256"}}
	r := httptest.NewRequest("GET", "https://auth.example.test/authorize?"+q.Encode(), nil)
	r.AddCookie(&http.Cookie{Name: "__Host-authd_session", Value: sessionRaw})
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != 302 {
		t.Fatal(w.Code, w.Body.String())
	}
	u, _ := url.Parse(w.Header().Get("Location"))
	code := u.Query().Get("code")
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {"https://bdc.example.test/auth/callback"}, "code_verifier": {verifier}}
	r = httptest.NewRequest("POST", "https://auth.example.test/token", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetBasicAuth("bdcmaps", secret)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("basic token: %d %s", w.Code, w.Body.String())
	}
	var tokens TokenResponse
	_ = json.Unmarshal(w.Body.Bytes(), &tokens)
	logout := url.Values{"id_token_hint": {tokens.IDToken}, "post_logout_redirect_uri": {"https://bdc.example.test/"}, "state": {"bye"}}
	r = httptest.NewRequest("GET", "https://auth.example.test/logout?"+logout.Encode(), nil)
	r.AddCookie(&http.Cookie{Name: "__Host-authd_session", Value: sessionRaw})
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != 303 || w.Header().Get("Location") != "https://bdc.example.test/?state=bye" || !sessions.ended {
		t.Fatalf("logout %d %s ended=%v", w.Code, w.Header().Get("Location"), sessions.ended)
	}
}

func signedLogoutHint(t *testing.T, svc *Service, subject string, now time.Time, expired bool) string {
	t.Helper()
	record, key, err := svc.privateKey(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	expires := now.Add(5 * time.Minute)
	if expired {
		expires = now.Add(-time.Minute)
	}
	raw, err := signJWT(record.KID, key, tokenClaims{
		Issuer:    "https://auth.example.test",
		Subject:   subject,
		Audience:  "bdcmaps",
		IssuedAt:  now.Add(-10 * time.Minute).Unix(),
		ExpiresAt: expires.Unix(),
		AuthTime:  now.Add(-10 * time.Minute).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestLogoutWithoutTrustedHintDoesNotEndSession(t *testing.T) {
	h, _, _, sessions, sessionRaw, _ := providerFixture(t)
	mux := muxFor(h)
	r := httptest.NewRequest("GET", "https://auth.example.test/logout", nil)
	r.AddCookie(&http.Cookie{Name: "__Host-authd_session", Value: sessionRaw})
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != http.StatusSeeOther || sessions.ended {
		t.Fatalf("bare logout ended session: status=%d ended=%v", w.Code, sessions.ended)
	}
	if _, ok := sessions.byRaw[sessionRaw]; !ok {
		t.Fatal("bare logout removed current session")
	}
}

func TestLogoutHintForDifferentSubjectDoesNotEndCurrentSession(t *testing.T) {
	h, svc, _, sessions, sessionRaw, _ := providerFixture(t)
	mux := muxFor(h)
	hint := signedLogoutHint(t, svc, "00000000-0000-4000-8000-000000000002", time.Now().UTC(), false)
	q := url.Values{"id_token_hint": {hint}, "post_logout_redirect_uri": {"https://bdc.example.test/"}}
	r := httptest.NewRequest("GET", "https://auth.example.test/logout?"+q.Encode(), nil)
	r.AddCookie(&http.Cookie{Name: "__Host-authd_session", Value: sessionRaw})
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/login" || sessions.ended {
		t.Fatalf("cross-subject logout accepted: status=%d location=%q ended=%v", w.Code, w.Header().Get("Location"), sessions.ended)
	}
}

func TestExpiredLogoutHintForCurrentSubjectIsAccepted(t *testing.T) {
	h, svc, _, sessions, sessionRaw, _ := providerFixture(t)
	mux := muxFor(h)
	hint := signedLogoutHint(t, svc, "00000000-0000-4000-8000-000000000001", time.Now().UTC(), true)
	q := url.Values{"id_token_hint": {hint}, "post_logout_redirect_uri": {"https://bdc.example.test/"}, "state": {"done"}}
	r := httptest.NewRequest("GET", "https://auth.example.test/logout?"+q.Encode(), nil)
	r.AddCookie(&http.Cookie{Name: "__Host-authd_session", Value: sessionRaw})
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "https://bdc.example.test/?state=done" || !sessions.ended {
		t.Fatalf("expired logout hint rejected: status=%d location=%q ended=%v", w.Code, w.Header().Get("Location"), sessions.ended)
	}
}

func TestMalformedClientAuthenticationFailsClosed(t *testing.T) {
	h, _, _, _, _, secret := providerFixture(t)
	mux := muxFor(h)
	form := url.Values{"grant_type": {"refresh_token"}, "client_id": {"bdcmaps"}, "client_secret": {secret}, "refresh_token": {strings.Repeat("A", 43)}}
	r := httptest.NewRequest("POST", "https://auth.example.test/token", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Authorization", "Bearer nonsense")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatalf("malformed authorization header accepted: %d %s", w.Code, w.Body.String())
	}
}

func TestSigningKeyRotationRetainsOldVerificationKey(t *testing.T) {
	_, svc, store, _, sessionRaw, _ := providerFixture(t)
	sess := store.sessions[hashKey(identity.Hash(sessionRaw))]
	subject := Subject{
		ID: sess.User.ID, Username: sess.User.Username, DisplayName: sess.User.DisplayName,
		Email: sess.User.Email, EmailVerified: sess.User.EmailVerified, Enabled: true,
		Roles: sess.Roles, Permissions: sess.Permissions, AuthTime: sess.AuthTime, AuthMethods: sess.AuthMethods,
	}
	now := time.Now().UTC()
	before, err := svc.tokensForGrant(context.Background(), CodeGrant{Client: store.client, Subject: subject, Scopes: []string{"openid"}}, now, false)
	if err != nil {
		t.Fatal(err)
	}
	old, err := store.ActiveSigningKey(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := svc.RotateSigningKey(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if rotated.KID == old.KID {
		t.Fatal("rotation reused the active kid")
	}
	keys, err := store.SigningKeys(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 {
		t.Fatalf("JWKS overlap keys=%d want=2", len(keys))
	}
	if _, err = svc.VerifyAccessToken(context.Background(), before.AccessToken, now.Add(time.Minute)); err != nil {
		t.Fatalf("token signed by retired key stopped verifying: %v", err)
	}
}

func TestLogoutRejectsDuplicateSecurityParametersBeforeEndingSession(t *testing.T) {
	h, _, _, sessions, sessionRaw, _ := providerFixture(t)
	mux := muxFor(h)
	r := httptest.NewRequest("GET", "https://auth.example.test/logout?state=a&state=b", nil)
	r.AddCookie(&http.Cookie{Name: "__Host-authd_session", Value: sessionRaw})
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("duplicate logout state accepted: %d %s", w.Code, w.Body.String())
	}
	if sessions.ended {
		t.Fatal("invalid logout request ended the provider session")
	}
}

func TestOIDCAuditUsesTrustedRequestIDContext(t *testing.T) {
	r := httptest.NewRequest("POST", "https://auth.example.test/token", nil)
	r.RemoteAddr = "192.0.2.10:12345"
	r = r.WithContext(requestid.With(r.Context(), "request-123"))
	a := auditFromRequest(r)
	if a.RequestID != "request-123" || a.IP != "192.0.2.10" {
		t.Fatalf("audit context mismatch: %#v", a)
	}
}

func TestJWTInputIsBounded(t *testing.T) {
	if _, err := tokenHeader(strings.Repeat("A", (16<<10)+1)); err == nil {
		t.Fatal("oversized JWT header input accepted")
	}
}

func beginAndAuthorize(t *testing.T, h *HTTP, sessionRaw, scope, verifier, challenge string) string {
	t.Helper()
	mux := muxFor(h)
	q := url.Values{"response_type": {"code"}, "client_id": {"bdcmaps"}, "redirect_uri": {"https://bdc.example.test/auth/callback"}, "scope": {scope}, "state": {"s"}, "nonce": {"n"}, "code_challenge": {challenge}, "code_challenge_method": {"S256"}}
	r := httptest.NewRequest("GET", "https://auth.example.test/authorize?"+q.Encode(), nil)
	r.AddCookie(&http.Cookie{Name: "__Host-authd_session", Value: sessionRaw})
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != http.StatusFound {
		t.Fatalf("authorize: %d %s", w.Code, w.Body.String())
	}
	location, err := url.Parse(w.Header().Get("Location"))
	if err != nil || location.Query().Get("code") == "" {
		t.Fatalf("authorization code missing: %s", w.Header().Get("Location"))
	}
	return location.Query().Get("code")
}

func TestBadPKCEDoesNotConsumeAuthorizationCode(t *testing.T) {
	h, _, _, _, sessionRaw, secret := providerFixture(t)
	mux := muxFor(h)
	verifier, challenge := verifierAndChallenge()
	code := beginAndAuthorize(t, h, sessionRaw, "openid", verifier, challenge)

	exchange := func(v string) *httptest.ResponseRecorder {
		form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {"https://bdc.example.test/auth/callback"}, "client_id": {"bdcmaps"}, "client_secret": {secret}, "code_verifier": {v}}
		r := httptest.NewRequest("POST", "https://auth.example.test/token", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w
	}
	wrong := strings.Repeat("B", 64)
	if w := exchange(wrong); w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "invalid_grant") {
		t.Fatalf("wrong PKCE accepted or misreported: %d %s", w.Code, w.Body.String())
	}
	if w := exchange(verifier); w.Code != http.StatusOK {
		t.Fatalf("failed PKCE attempt consumed the code: %d %s", w.Code, w.Body.String())
	}
}

func TestRefreshScopeNarrowingPersistsAndFailedBroadeningDoesNotConsume(t *testing.T) {
	h, _, _, _, sessionRaw, secret := providerFixture(t)
	mux := muxFor(h)
	verifier, challenge := verifierAndChallenge()
	code := beginAndAuthorize(t, h, sessionRaw, "openid profile groups offline_access", verifier, challenge)
	codeForm := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {"https://bdc.example.test/auth/callback"}, "client_id": {"bdcmaps"}, "client_secret": {secret}, "code_verifier": {verifier}}
	r := httptest.NewRequest("POST", "https://auth.example.test/token", strings.NewReader(codeForm.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatal(w.Code, w.Body.String())
	}
	var first TokenResponse
	if err := json.Unmarshal(w.Body.Bytes(), &first); err != nil {
		t.Fatal(err)
	}

	refresh := func(raw, scope string) (TokenResponse, *httptest.ResponseRecorder) {
		form := url.Values{"grant_type": {"refresh_token"}, "client_id": {"bdcmaps"}, "client_secret": {secret}, "refresh_token": {raw}}
		if scope != "" {
			form.Set("scope", scope)
		}
		r := httptest.NewRequest("POST", "https://auth.example.test/token", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		var out TokenResponse
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return out, w
	}

	narrowed, w := refresh(first.RefreshToken, "openid offline_access")
	if w.Code != http.StatusOK || narrowed.Scope != "offline_access openid" || narrowed.RefreshToken == "" {
		t.Fatalf("narrowing failed: %d %#v %s", w.Code, narrowed, w.Body.String())
	}
	_, w = refresh(narrowed.RefreshToken, "openid profile offline_access")
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "invalid_scope") {
		t.Fatalf("refresh broadening accepted: %d %s", w.Code, w.Body.String())
	}
	again, w := refresh(narrowed.RefreshToken, "")
	if w.Code != http.StatusOK || again.Scope != "offline_access openid" {
		t.Fatalf("failed broadening consumed or re-expanded token: %d %#v %s", w.Code, again, w.Body.String())
	}
}

func TestRevocationRequiresToken(t *testing.T) {
	h, _, _, _, _, secret := providerFixture(t)
	mux := muxFor(h)
	form := url.Values{"client_id": {"bdcmaps"}, "client_secret": {secret}}
	r := httptest.NewRequest("POST", "https://auth.example.test/revoke", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "invalid_request") {
		t.Fatalf("empty revocation accepted: %d %s", w.Code, w.Body.String())
	}
}

func TestPublicClientCORSUsesRegisteredRedirectOriginOnly(t *testing.T) {
	h, _, store, _, sessionRaw, _ := providerFixture(t)
	store.client.Type = "public"
	store.client.SecretHash = nil
	mux := muxFor(h)

	preflight := httptest.NewRequest("OPTIONS", "https://auth.example.test/token", nil)
	preflight.Header.Set("Origin", "https://bdc.example.test")
	preflight.Header.Set("Access-Control-Request-Method", "POST")
	preflight.Header.Set("Access-Control-Request-Headers", "content-type")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, preflight)
	if w.Code != http.StatusNoContent || w.Header().Get("Access-Control-Allow-Origin") != "https://bdc.example.test" {
		t.Fatalf("registered public origin preflight failed: %d %#v %s", w.Code, w.Header(), w.Body.String())
	}

	evil := httptest.NewRequest("OPTIONS", "https://auth.example.test/token", nil)
	evil.Header.Set("Origin", "https://evil.example.test")
	evil.Header.Set("Access-Control-Request-Method", "POST")
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, evil)
	if w.Code != http.StatusForbidden || w.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("unregistered origin received CORS permission")
	}

	verifier, challenge := verifierAndChallenge()
	code := beginAndAuthorize(t, h, sessionRaw, "openid profile", verifier, challenge)
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {"https://bdc.example.test/auth/callback"}, "client_id": {"bdcmaps"}, "code_verifier": {verifier}}
	r := httptest.NewRequest("POST", "https://auth.example.test/token", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", "https://bdc.example.test")
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != http.StatusOK || w.Header().Get("Access-Control-Allow-Origin") != "https://bdc.example.test" {
		t.Fatalf("public token CORS failed: %d %s", w.Code, w.Body.String())
	}
	var tokens TokenResponse
	if err := json.Unmarshal(w.Body.Bytes(), &tokens); err != nil {
		t.Fatal(err)
	}
	r = httptest.NewRequest("GET", "https://auth.example.test/userinfo", nil)
	r.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	r.Header.Set("Origin", "https://bdc.example.test")
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != http.StatusOK || w.Header().Get("Access-Control-Allow-Origin") != "https://bdc.example.test" {
		t.Fatalf("public UserInfo CORS failed: %d %s", w.Code, w.Body.String())
	}
}

func TestOriginCanonicalization(t *testing.T) {
	cases := map[string]string{
		"https://Example.COM:443":  "https://example.com",
		"http://LOCALHOST:80":      "http://localhost",
		"https://[::1]:443":        "https://[::1]",
		"https://example.com:8443": "https://example.com:8443",
	}
	for raw, want := range cases {
		got, ok := canonicalOrigin(raw)
		if !ok || got != want {
			t.Fatalf("canonicalOrigin(%q)=%q,%v want %q,true", raw, got, ok, want)
		}
	}
	for _, raw := range []string{"null", "file:///tmp/x", "https://example.com/path", "https://user@example.com"} {
		if got, ok := canonicalOrigin(raw); ok {
			t.Fatalf("invalid origin %q accepted as %q", raw, got)
		}
	}
}
