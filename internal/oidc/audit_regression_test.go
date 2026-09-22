package oidc

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/yellowman/authd/internal/identity"
)

func auditRequest() url.Values {
	_, challenge := verifierAndChallenge()
	return url.Values{"response_type": {"code"}, "client_id": {"bdcmaps"}, "redirect_uri": {"https://bdc.example.test/auth/callback"}, "scope": {"openid"}, "state": {"audit-state"}, "code_challenge": {challenge}, "code_challenge_method": {"S256"}}
}
func TestAuditAuthorizationPost(t *testing.T) {
	h, _, _, _, session, _ := providerFixture(t)
	r := httptest.NewRequest("POST", "https://auth.example.test/authorize", strings.NewReader(auditRequest().Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(&http.Cookie{Name: "__Host-authd_session", Value: session})
	w := httptest.NewRecorder()
	muxFor(h).ServeHTTP(w, r)
	if w.Code != 302 {
		t.Fatalf("POST authorization: %d %s", w.Code, w.Body.String())
	}
}
func TestAuditProtocolParameters(t *testing.T) {
	h, _, _, _, session, _ := providerFixture(t)
	for _, tc := range []struct{ name, value, want string }{
		{"request", "signed-request", "request_not_supported"},
		{"request_uri", "https://idp.example.test/request.jwt", "request_uri_not_supported"},
		{"response_type", "token", "unsupported_response_type"},
		{"response_mode", "fragment", "invalid_request"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			q := auditRequest()
			q.Set(tc.name, tc.value)
			r := httptest.NewRequest("GET", "https://auth.example.test/authorize?"+q.Encode(), nil)
			r.AddCookie(&http.Cookie{Name: "__Host-authd_session", Value: session})
			w := httptest.NewRecorder()
			muxFor(h).ServeHTTP(w, r)
			u, _ := url.Parse(w.Header().Get("Location"))
			if u.Query().Get("error") != tc.want || u.Query().Get("state") != "audit-state" {
				t.Fatalf("status %d location %q body %s", w.Code, u, w.Body.String())
			}
		})
	}
}
func TestAuditUnknownACRIsVoluntary(t *testing.T) {
	h, _, _, _, session, _ := providerFixture(t)
	q := auditRequest()
	q.Set("acr_values", "urn:unknown:assurance")
	r := httptest.NewRequest("GET", "https://auth.example.test/authorize?"+q.Encode(), nil)
	r.AddCookie(&http.Cookie{Name: "__Host-authd_session", Value: session})
	w := httptest.NewRecorder()
	muxFor(h).ServeHTTP(w, r)
	u, _ := url.Parse(w.Header().Get("Location"))
	if u.Query().Get("code") == "" {
		t.Fatalf("voluntary ACR became a hard rejection: %s %s", u, w.Body.String())
	}
}
func TestAuditBasicUsesFormEncoding(t *testing.T) {
	h, _, store, _, _, _ := providerFixture(t)
	store.client.ClientID = "test:client"
	store.client.SecretHash = identity.Hash("a+b:% value")
	r := httptest.NewRequest("POST", "https://auth.example.test/token", nil)
	r.SetBasicAuth(url.QueryEscape(store.client.ClientID), url.QueryEscape("a+b:% value"))
	if _, err := h.authenticateClient(r, url.Values{}); err != nil {
		t.Fatalf("encoded client credentials rejected: %v", err)
	}
}

type failingRevokeStore struct{ Store }

func (f failingRevokeStore) RevokeRefreshToken(context.Context, []byte, Client, identity.Audit) error {
	return errors.New("database unavailable")
}
func TestAuditRevocationFailureIsNotSuccess(t *testing.T) {
	h, svc, store, _, _, secret := providerFixture(t)
	svc.Store = failingRevokeStore{store}
	q := url.Values{"client_id": {"bdcmaps"}, "client_secret": {secret}, "token": {strings.Repeat("A", 43)}}
	r := httptest.NewRequest("POST", "https://auth.example.test/revoke", strings.NewReader(q.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	muxFor(h).ServeHTTP(w, r)
	if w.Code != 503 {
		t.Fatalf("revocation failure status=%d, want 503", w.Code)
	}
}
func TestAuditUserInfoRequiresOpenIDScope(t *testing.T) {
	_, svc, store, _, session, _ := providerFixture(t)
	sess := store.sessions[hashKey(identity.Hash(session))]
	g := CodeGrant{Client: store.client, Subject: Subject{ID: sess.User.ID, Enabled: true, AuthTime: sess.AuthTime, AuthMethods: sess.AuthMethods}, Scopes: []string{"bdcmaps.read"}}
	resp, err := svc.tokensForGrant(context.Background(), g, time.Now(), false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = svc.UserInfo(context.Background(), resp.AccessToken, time.Now()); err == nil {
		t.Fatal("non-OIDC access token admitted to UserInfo")
	}
}
