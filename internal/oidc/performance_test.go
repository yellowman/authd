package oidc

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/yellowman/authd/internal/identity"
)

// These CPU/allocation benchmarks deliberately use an in-memory store. They do
// not measure PostgreSQL, TLS, proxying, network latency, or deployment capacity.
func benchmarkGrant(b *testing.B) (*HTTP, *Service, CodeGrant) {
	b.Helper()
	h, s, store, _, raw, _ := providerFixture(b)
	sess := store.sessions[hashKey(identity.Hash(raw))]
	return h, s, CodeGrant{Client: store.client, Subject: Subject{ID: sess.User.ID, SessionID: sess.ID, Enabled: true, Username: sess.User.Username, DisplayName: sess.User.DisplayName, Email: sess.User.Email, EmailVerified: sess.User.EmailVerified, AuthTime: sess.AuthTime, AuthMethods: sess.AuthMethods, Roles: sess.Roles}, Scopes: []string{"openid", "profile", "email", "groups"}}
}
func BenchmarkTokenEncoding(b *testing.B) {
	_, s, g := benchmarkGrant(b)
	ctx := context.Background()
	if _, err := s.tokensForGrant(ctx, g, time.Now(), false); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := s.tokensForGrant(ctx, g, time.Now(), false); err != nil {
			b.Fatal(err)
		}
	}
}
func BenchmarkUserInfoHTTP(b *testing.B) {
	h, s, g := benchmarkGrant(b)
	response, err := s.tokensForGrant(context.Background(), g, time.Now(), false)
	if err != nil {
		b.Fatal(err)
	}
	handler := muxFor(h)
	req := httptest.NewRequest("GET", "https://auth.example.test/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+response.AccessToken)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != 200 {
			b.Fatal(w.Code, w.Body.String())
		}
	}
}
