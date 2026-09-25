package web

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/yellowman/authd/internal/config"
	"github.com/yellowman/authd/internal/cryptoutil"
	"github.com/yellowman/authd/internal/identity"
	"github.com/yellowman/authd/internal/oidc"
	"github.com/yellowman/authd/internal/requestid"
)

const userID = "00000000-0000-4000-8000-000000000001"

// A test-only password double. No replacement modules or alternate production
// credential verifier are installed to execute these HTTP tests.
type testHasher struct{}

func (testHasher) Hash(p string) (string, error)          { return "test-only:" + p, nil }
func (testHasher) Verify(e, p string) (bool, bool, error) { return e == "test-only:"+p, false, nil }

type testStore struct {
	identity.Store
	session                                   identity.Session
	record                                    identity.LoginRecord
	raw                                       string
	adminCalls, mutationCalls, sessionCreates int
	profileEdits                              int
	mutationError                             error
	revoked                                   bool
	loginAudit                                identity.Audit
	loginSession                              identity.Session
	snapshot                                  identity.AdminData
	groupEdit                                 identity.GroupEdit
}

func (m *testStore) BootstrapOpen(context.Context) (bool, error) { return true, nil }
func (m *testStore) Session(_ context.Context, hash []byte, _ time.Duration) (identity.Session, error) {
	if len(m.loginSession.TokenHash) > 0 && bytes.Equal(hash, m.loginSession.TokenHash) {
		return m.loginSession, nil
	}
	if m.revoked || !bytes.Equal(hash, identity.Hash(m.raw)) {
		return identity.Session{}, identity.ErrSession
	}
	return m.session, nil
}
func (m *testStore) Sessions(context.Context, []byte) ([]identity.Session, error) {
	return []identity.Session{m.session}, nil
}
func (m *testStore) AdminData(context.Context, []byte) (identity.AdminData, error) {
	m.adminCalls++
	return m.snapshot, nil
}
func (m *testStore) CreatePermission(context.Context, []byte, string, string, identity.Audit) error {
	m.mutationCalls++
	return m.mutationError
}
func (m *testStore) SavePermission(context.Context, []byte, identity.PermissionEdit, identity.Audit) error {
	m.mutationCalls++
	return nil
}
func (m *testStore) DeletePermission(context.Context, []byte, string, identity.Audit) error {
	m.mutationCalls++
	return nil
}
func (m *testStore) DeleteRole(context.Context, []byte, string, identity.Audit) error {
	m.mutationCalls++
	return nil
}
func (m *testStore) SaveGroup(_ context.Context, _ []byte, edit identity.GroupEdit, _ identity.Audit) error {
	m.groupEdit = edit
	m.mutationCalls++
	return nil
}
func (m *testStore) DeleteUser(context.Context, []byte, string, identity.Audit) error {
	m.mutationCalls++
	return nil
}
func (m *testStore) ResetMFA(context.Context, []byte, string, identity.Audit) error {
	m.mutationCalls++
	return nil
}
func (m *testStore) ReplaceRecoveryCodes(context.Context, []byte, [][]byte, identity.Audit) error {
	m.mutationCalls++
	return nil
}
func (m *testStore) AuditFailure(context.Context, string, identity.Audit) error { return nil }
func (m *testStore) LoginRecord(_ context.Context, name string) (identity.LoginRecord, error) {
	if name != "alice" {
		return identity.LoginRecord{}, identity.ErrCredentials
	}
	return m.record, nil
}
func (m *testStore) CreateSession(_ context.Context, _ identity.LoginRecord, s identity.Session, _ *identity.FactorUse, _ string, a identity.Audit) error {
	m.sessionCreates++
	m.loginSession = s
	m.loginAudit = a
	return nil
}
func (m *testStore) RevokeSession(context.Context, []byte, string, bool, identity.Audit) error {
	m.mutationCalls++
	m.revoked = true
	return nil
}
func (m *testStore) EditOwnProfile(_ context.Context, _ []byte, p identity.Profile, _ identity.Audit) error {
	m.profileEdits++
	m.session.User.DisplayName = p.DisplayName
	m.session.User.Email = p.Email
	return nil
}
func fixture(t *testing.T, admin bool) (*Server, http.Handler, *testStore) {
	t.Helper()
	raw, e := cryptoutil.RandomToken(32)
	if e != nil {
		t.Fatal(e)
	}
	store := &testStore{raw: raw, record: identity.LoginRecord{User: identity.User{ID: userID, Username: "alice", Enabled: true}, PasswordHash: "test-only:correct password"}}
	service, e := identity.NewService(store, testHasher{}, []byte("0123456789abcdef0123456789abcdef"), time.Hour, 24*time.Hour)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now()
	store.session = identity.Session{ID: userID, User: store.record.User, TokenHash: identity.Hash(raw), CSRFHash: identity.Hash(service.CSRF(raw, "session")), AuthMethods: []string{"pwd"}, AuthTime: now, CreatedAt: now, IdleExpiresAt: now.Add(time.Hour), AbsoluteExpiresAt: now.Add(24 * time.Hour)}
	if admin {
		store.session.Permissions = []string{"system.admin"}
		store.session.Roles = []string{"system-admin"}
	}
	store.snapshot = identity.AdminData{Users: []identity.User{store.session.User}, Sessions: []identity.Session{store.session}, Roles: []identity.Role{{ID: userID, Name: "system-admin", BuiltIn: true, PermissionIDs: []string{userID}, Permissions: []string{"system.admin"}}}, Permissions: []identity.Permission{{ID: userID, Name: "system.admin"}}, Events: []identity.AuditEvent{{ID: 1, At: now, Event: "login.success", Actor: "alice"}}}
	server, e := New(config.Config{Issuer: "https://auth.example.test", SessionIdleTTL: time.Hour, SessionAbsoluteTTL: 24 * time.Hour}, service, func(context.Context) error { return nil })
	if e != nil {
		t.Fatal(e)
	}
	handler, e := server.Handler()
	if e != nil {
		t.Fatal(e)
	}
	return server, handler, store
}
func request(s *Server, m *testStore, method, path string, values url.Values, authenticated bool) *http.Request {
	var body *strings.Reader
	if values != nil {
		body = strings.NewReader(values.Encode())
	} else {
		body = strings.NewReader("")
	}
	r := httptest.NewRequest(method, "https://auth.example.test"+path, body)
	if method == http.MethodPost {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Origin", s.cfg.Issuer)
	}
	if authenticated {
		r.AddCookie(&http.Cookie{Name: s.cookieName("session"), Value: m.raw})
	}
	return r
}
func TestParseFormAcceptsGroupMembersButRejectsDuplicateScalar(t *testing.T) {
	s, _, m := fixture(t, true)
	values := url.Values{"users": {userID, "00000000-0000-4000-8000-000000000002"}, "name": {"Operators"}}
	if err := s.parseForm(httptest.NewRecorder(), request(s, m, http.MethodPost, "/admin/groups/save", values, true)); err != nil {
		t.Fatalf("group members rejected: %v", err)
	}
	values["name"] = []string{"Operators", "Admins"}
	if err := s.parseForm(httptest.NewRecorder(), request(s, m, http.MethodPost, "/admin/groups/save", values, true)); err == nil {
		t.Fatal("duplicate scalar field accepted")
	}
}
func TestGroupSaveAcceptsMultipleMembers(t *testing.T) {
	s, handler, m := fixture(t, true)
	members := []string{userID, "00000000-0000-4000-8000-000000000002"}
	values := url.Values{"name": {"networkmap.operators"}, "users": members, "csrf_token": {s.auth.CSRF(m.raw, "session")}}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, request(s, m, http.MethodPost, "/admin/groups/save", values, true))
	if w.Code != http.StatusSeeOther || m.mutationCalls != 1 || len(m.groupEdit.UserIDs) != 2 || m.groupEdit.UserIDs[0] != members[0] || m.groupEdit.UserIDs[1] != members[1] {
		t.Fatalf("group save: status=%d, mutations=%d, members=%v", w.Code, m.mutationCalls, m.groupEdit.UserIDs)
	}
}
func TestAnonymousCannotReadAccountOrAdmin(t *testing.T) {
	s, h, m := fixture(t, false)
	for _, path := range []string{"/account", "/admin/"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, request(s, m, "GET", path, nil, false))
		if w.Code != 303 || !strings.HasPrefix(w.Header().Get("Location"), "/login") {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body.String())
		}
	}
	if m.adminCalls != 0 {
		t.Fatal("read privileged database data before authentication")
	}
}
func TestZeroRoleAccountWorksButAdminDenied(t *testing.T) {
	s, h, m := fixture(t, false)
	for path, want := range map[string]int{"/account": 200, "/admin/": 403} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, request(s, m, "GET", path, nil, true))
		if w.Code != want {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body.String())
		}
	}
	v := url.Values{"name": {"app.read"}, "csrf_token": {s.auth.CSRF(m.raw, "session")}}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, request(s, m, "POST", "/admin/permissions/create", v, true))
	if w.Code != 403 || m.mutationCalls != 0 || m.adminCalls != 0 {
		t.Fatal("unprivileged access crossed the guard")
	}
}
func TestAdminMutationRejectsMissingWrongAndCrossSessionCSRF(t *testing.T) {
	for _, token := range []string{"", strings.Repeat("A", 43), "other-session"} {
		s, h, m := fixture(t, true)
		if token == "other-session" {
			other, _ := cryptoutil.RandomToken(32)
			token = s.auth.CSRF(other, "session")
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, request(s, m, "POST", "/admin/permissions/create", url.Values{"name": {"app.read"}, "csrf_token": {token}}, true))
		if w.Code != 403 || m.mutationCalls != 0 {
			t.Fatalf("bad CSRF accepted: %d", w.Code)
		}
	}
}
func TestAdminMutationChecksOriginDuplicatesAndBodyLimit(t *testing.T) {
	cases := []string{"origin", "duplicate", "oversized", "query"}
	for _, c := range cases {
		t.Run(c, func(t *testing.T) {
			s, h, m := fixture(t, true)
			v := url.Values{"name": {"app.read"}, "csrf_token": {s.auth.CSRF(m.raw, "session")}}
			path := "/admin/permissions/create"
			if c == "duplicate" {
				v["name"] = []string{"app.read", "app.write"}
			}
			if c == "oversized" {
				v.Set("description", strings.Repeat("x", 40000))
			}
			if c == "query" {
				path += "?csrf_token=in-query"
			}
			r := request(s, m, "POST", path, v, true)
			if c == "origin" {
				r.Header.Set("Origin", "https://evil.example.test")
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code < 400 || m.mutationCalls != 0 {
				t.Fatal("invalid mutation reached store")
			}
		})
	}
}
func TestValidCSRFMutationWorks(t *testing.T) {
	s, h, m := fixture(t, true)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, request(s, m, "POST", "/admin/permissions/create", url.Values{"name": {"app.read"}, "csrf_token": {s.auth.CSRF(m.raw, "session")}}, true))
	if w.Code != 303 || m.mutationCalls != 1 {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
}
func TestSelfProfileEditUsesAuthenticatedIdentity(t *testing.T) {
	s, h, m := fixture(t, false)
	v := url.Values{"display_name": {"Alice Example"}, "email": {"alice@example.test"}, "csrf_token": {s.auth.CSRF(m.raw, "session")}}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, request(s, m, "POST", "/account/profile", v, true))
	if w.Code != http.StatusSeeOther || m.profileEdits != 1 || m.session.User.DisplayName != "Alice Example" || m.session.User.Email != "alice@example.test" {
		t.Fatalf("profile edit failed: code=%d edits=%d user=%+v", w.Code, m.profileEdits, m.session.User)
	}
}
func TestForcedPasswordChangeCannotReachAdmin(t *testing.T) {
	s, h, m := fixture(t, true)
	m.session.User.ForcePasswordChange = true
	w := httptest.NewRecorder()
	h.ServeHTTP(w, request(s, m, "GET", "/admin/", nil, true))
	if w.Code != 303 || w.Header().Get("Location") != "/account" || m.adminCalls != 0 {
		t.Fatal("forced-change guard missing")
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, request(s, m, "GET", "/account", nil, true))
	if w.Code != 200 || !strings.Contains(w.Body.String(), "You must change your password") {
		t.Fatal("cannot reach password change")
	}
}
func TestDuplicateSessionCookiesFailClosed(t *testing.T) {
	s, h, m := fixture(t, true)
	r := request(s, m, "GET", "/admin/", nil, true)
	r.AddCookie(&http.Cookie{Name: s.cookieName("session"), Value: m.raw})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 303 || m.adminCalls != 0 {
		t.Fatal("ambiguous cookie accepted")
	}
}
func TestLoginIssuesFreshSecureSessionAndIgnoresForwardedIP(t *testing.T) {
	s, h, m := fixture(t, false)
	browser, _ := cryptoutil.RandomToken(32)
	v := url.Values{"username": {"alice"}, "password": {"correct password"}, "csrf_token": {s.auth.CSRF(browser, "browser")}, "return_to": {"https://evil.test/"}}
	r := request(s, m, "POST", "/login", v, false)
	r.AddCookie(&http.Cookie{Name: s.cookieName("browser"), Value: browser})
	r.RemoteAddr = "127.0.0.1:4567"
	r.Header.Set("X-Forwarded-For", "1.2.3.4")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 303 || w.Header().Get("Location") != "/account" || m.sessionCreates != 1 {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	var sessionCookie *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == s.cookieName("session") {
			sessionCookie = c
		}
	}
	if sessionCookie == nil || !sessionCookie.Secure || !sessionCookie.HttpOnly || sessionCookie.Domain != "" || sessionCookie.Path != "/" || sessionCookie.SameSite != http.SameSiteLaxMode {
		t.Fatalf("bad cookie %+v", sessionCookie)
	}
	if sessionCookie.Value == browser || !bytes.Equal(m.loginSession.TokenHash, identity.Hash(sessionCookie.Value)) {
		t.Fatal("session not fresh or hashed")
	}
	if m.loginAudit.IP != "127.0.0.1" {
		t.Fatal("trusted a spoofed forwarding header")
	}
}
func TestTrustedProxyResolutionStopsAtNearestUntrustedHop(t *testing.T) {
	trusted := []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32"), netip.MustParsePrefix("10.0.0.0/8")}
	r := httptest.NewRequest(http.MethodGet, "https://auth.example.test/", nil)
	r.RemoteAddr = "127.0.0.1:44321"
	r.Header.Set("X-Forwarded-For", "198.51.100.9, 203.0.113.44, 10.1.2.3")
	if got := resolvedClientIP(r, trusted, false); got != "203.0.113.44" {
		t.Fatalf("client IP=%q want nearest untrusted hop", got)
	}

	// A directly untrusted peer never gets to nominate its own source address.
	r.RemoteAddr = "192.0.2.30:44321"
	r.Header.Set("X-Forwarded-For", "198.51.100.1")
	if got := resolvedClientIP(r, trusted, false); got != "192.0.2.30" {
		t.Fatalf("untrusted peer spoofed source: %q", got)
	}

	// Malformed trusted-proxy chains fail closed to the direct peer.
	r.RemoteAddr = "127.0.0.1:44321"
	r.Header.Set("X-Forwarded-For", "198.51.100.1, garbage")
	if got := resolvedClientIP(r, trusted, false); got != "127.0.0.1" {
		t.Fatalf("malformed chain partially trusted: %q", got)
	}
}
func TestLoginRequiresBrowserBoundCSRF(t *testing.T) {
	s, h, m := fixture(t, false)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, request(s, m, "POST", "/login", url.Values{"username": {"alice"}, "password": {"correct password"}}, false))
	if w.Code != 403 || m.sessionCreates != 0 {
		t.Fatal("login CSRF bypass")
	}
}
func TestLogoutRequiresPostAndCSRF(t *testing.T) {
	s, h, m := fixture(t, false)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, request(s, m, "GET", "/session/logout", nil, true))
	if w.Code != 405 || m.revoked {
		t.Fatal("GET logged out user")
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, request(s, m, "POST", "/session/logout", url.Values{}, true))
	if w.Code != 403 || m.revoked {
		t.Fatal("CSRF logout")
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, request(s, m, "POST", "/session/logout", url.Values{"csrf_token": {s.auth.CSRF(m.raw, "session")}}, true))
	if w.Code != 303 || !m.revoked {
		t.Fatal("logout failed")
	}
}
func TestAllAdminTemplatesRenderAndEscape(t *testing.T) {
	s, h, m := fixture(t, true)
	m.snapshot.Users[0].DisplayName = "<script>bad()</script>"
	for _, path := range []string{"/admin/?view=users", "/admin/?view=roles", "/admin/?view=permissions", "/admin/?view=sessions", "/admin/?view=audit", "/admin/?user=" + userID, "/admin/?role=" + userID, "/admin/?permission=" + userID} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, request(s, m, "GET", path, nil, true))
		if w.Code != 200 {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body.String())
		}
		if strings.Contains(w.Body.String(), "<script>bad") {
			t.Fatal("unescaped profile")
		}
	}
	for _, name := range []string{"setup.html", "login.html", "message.html", "mfa.html", "client_secret.html"} {
		d := s.data("test")
		d.CSRF = s.auth.CSRF(m.raw, "session")
		d.Secret = "ABCD"
		w := httptest.NewRecorder()
		s.render(w, 200, name, d)
		if w.Code != 200 {
			t.Fatal(name)
		}
	}
	d := s.data("recovery")
	d.RecoveryCodes = []string{strings.Repeat("A", 43)}
	w := httptest.NewRecorder()
	s.render(w, 200, "mfa.html", d)
	if w.Code != 200 {
		t.Fatal("recovery template")
	}
	clients := s.data("clients")
	clients.View = "clients"
	clients.Session = m.session
	clients.Admin = m.snapshot
	clients.OIDCClients = []oidc.Client{{ID: userID, ClientID: "bdcmaps", Name: "BDC Maps", Type: "confidential", Enabled: true, AccessTokenTTL: 5 * time.Minute, RedirectURIs: []string{"https://bdc.example.test/auth/callback"}, IdentityScopes: []string{"openid", "profile", "email", "groups"}}}
	clients.SelectedClient = &clients.OIDCClients[0]
	w = httptest.NewRecorder()
	s.render(w, 200, "admin.html", clients)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "bdcmaps") {
		t.Fatal("OIDC client administration template")
	}
	keys := s.data("keys")
	keys.View = "keys"
	keys.Session = m.session
	keys.Admin = m.snapshot
	keys.SigningKeys = []oidc.SigningKey{{KID: "kid-current", Algorithm: "RS256", Active: true, CreatedAt: time.Now()}}
	w = httptest.NewRecorder()
	s.render(w, 200, "admin.html", keys)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "kid-current") {
		t.Fatal("signing-key administration template")
	}
}
func TestNoSecretsInRequestLogs(t *testing.T) {
	s, h, m := fixture(t, false)
	var b bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&b, nil)))
	defer slog.SetDefault(old)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, request(s, m, "GET", "/unexpected-secret-value?code=secret-query", nil, false))
	if strings.Contains(b.String(), "unexpected-secret-value") || strings.Contains(b.String(), "secret-query") {
		t.Fatal("URL secret logged")
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("sensitive response can be cached")
	}
}
func TestInternalFailureUsesSafeClassAndRequestReference(t *testing.T) {
	s, h, m := fixture(t, true)
	m.mutationError = errors.New("postgres://user:SECRET@db/internal")
	var logs bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	defer slog.SetDefault(old)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, request(s, m, "POST", "/admin/permissions/create", url.Values{"name": {"app.read"}, "csrf_token": {s.auth.CSRF(m.raw, "session")}}, true))
	requestID := w.Header().Get("X-Request-ID")
	if w.Code != http.StatusInternalServerError || requestID == "" || !strings.Contains(w.Body.String(), requestID) {
		t.Fatalf("internal failure lacks correlation reference: code=%d id=%q body=%s", w.Code, requestID, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "SECRET") || strings.Contains(logs.String(), "SECRET") || strings.Contains(logs.String(), "postgres://") {
		t.Fatal("raw internal error leaked")
	}
	if !strings.Contains(logs.String(), "error_class=internal") || !strings.Contains(logs.String(), requestID) {
		t.Fatalf("safe internal classification missing: %s", logs.String())
	}
}

func TestFailureClassifiesUnavailableAndDeadlineWithoutRawError(t *testing.T) {
	s, _, _ := fixture(t, false)
	for _, tc := range []struct {
		err   error
		class string
	}{
		{identity.ErrUnavailable, "dependency_unavailable"},
		{context.DeadlineExceeded, "deadline"},
	} {
		r := httptest.NewRequest(http.MethodGet, "https://auth.example.test/account", nil)
		id := "test-request-reference"
		r = r.WithContext(requestid.With(r.Context(), id))
		w := httptest.NewRecorder()
		var logs bytes.Buffer
		old := slog.Default()
		slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
		s.failure(w, r, tc.err)
		slog.SetDefault(old)
		if w.Code != http.StatusServiceUnavailable || !strings.Contains(logs.String(), "error_class="+tc.class) || !strings.Contains(w.Body.String(), id) {
			t.Fatalf("classification %s failed: code=%d logs=%s body=%s", tc.class, w.Code, logs.String(), w.Body.String())
		}
	}
}

func TestHealthDoesNotLeakBackendFailure(t *testing.T) {
	s, _, m := fixture(t, false)
	s.healthCheck = func(context.Context) error { return errors.New("postgres://user:SECRET@host") }
	h, _ := s.Handler()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, request(s, m, "GET", "/healthz", nil, false))
	if w.Code != 503 || strings.Contains(w.Body.String(), "SECRET") {
		t.Fatal("health leaked backend details")
	}
}

func TestStaleAdministratorCannotMutate(t *testing.T) {
	s, h, m := fixture(t, true)
	m.session.AuthTime = time.Now().Add(-11 * time.Minute)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, request(s, m, "POST", "/admin/permissions/create", url.Values{"name": {"app.read"}, "csrf_token": {s.auth.CSRF(m.raw, "session")}}, true))
	if w.Code != 403 || m.mutationCalls != 0 {
		t.Fatal("stale admin mutation reached storage")
	}
}
func TestIdentityScopeCannotBecomePermission(t *testing.T) {
	for _, name := range []string{"openid", "profile", "email", "groups", "roles", "offline_access"} {
		s, h, m := fixture(t, true)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, request(s, m, "POST", "/admin/permissions/create", url.Values{"name": {name}, "csrf_token": {s.auth.CSRF(m.raw, "session")}}, true))
		if w.Code != 400 || m.mutationCalls != 0 {
			t.Fatal("identity scope entered permission catalog", name)
		}
	}
}

func TestDestructiveAdminActionRequiresTypedConfirmation(t *testing.T) {
	s, h, m := fixture(t, true)
	csrf := s.auth.CSRF(m.raw, "session")
	for _, confirm := range []string{"", "DELETE", "yes"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, request(s, m, "POST", "/admin/users/delete", url.Values{"id": {userID}, "confirm": {confirm}, "csrf_token": {csrf}}, true))
		if w.Code != 400 || m.mutationCalls != 0 {
			t.Fatalf("confirmation %q reached destructive store: status=%d calls=%d", confirm, w.Code, m.mutationCalls)
		}
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, request(s, m, "POST", "/admin/users/delete", url.Values{"id": {"00000000-0000-4000-8000-000000000002"}, "confirm": {"delete"}, "csrf_token": {csrf}}, true))
	if w.Code != 303 || m.mutationCalls != 1 {
		t.Fatalf("confirmed deletion status=%d calls=%d body=%s", w.Code, m.mutationCalls, w.Body.String())
	}
}

func TestRecoveryCodeRegenerationRequiresFreshMFASession(t *testing.T) {
	s, h, m := fixture(t, false)
	m.session.User.MFAEnabled = true
	csrf := s.auth.CSRF(m.raw, "session")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, request(s, m, "POST", "/account/mfa/recovery", url.Values{"csrf_token": {csrf}}, true))
	if w.Code != 403 || m.mutationCalls != 0 {
		t.Fatalf("password-only session regenerated recovery codes: %d calls=%d", w.Code, m.mutationCalls)
	}
	m.session.AuthMethods = []string{"pwd", "otp"}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, request(s, m, "POST", "/account/mfa/recovery", url.Values{"csrf_token": {csrf}}, true))
	if w.Code != 200 || m.mutationCalls != 1 || !strings.Contains(w.Body.String(), "Previous unused recovery codes no longer work") {
		t.Fatalf("MFA recovery regeneration failed: %d calls=%d body=%s", w.Code, m.mutationCalls, w.Body.String())
	}
}
