package oidc

import (
	"context"
	"testing"
	"time"

	"github.com/yellowman/authd/internal/cryptoutil"
	"github.com/yellowman/authd/internal/identity"
)

func TestPendingLoginReportsBrowserBoundMFAPolicy(t *testing.T) {
	h, _, store, _, _, _ := providerFixture(t)
	browser, _ := cryptoutil.RandomToken(32)
	flow, _ := cryptoutil.RandomToken(32)
	req := AuthorizationRequest{BrowserHash: identity.Hash(browser), RedirectURI: store.client.RedirectURIs[0], ExpiresAt: time.Now().Add(time.Minute)}
	if err := store.CreateAuthorizationRequest(context.Background(), identity.Hash(flow), req); err != nil {
		t.Fatal(err)
	}
	if _, _, required, ok := h.PendingLogin(context.Background(), flow, browser); !ok || required {
		t.Fatal("ordinary client incorrectly requires MFA")
	}
	store.mu.Lock()
	store.client.RequireMFA = true
	store.mu.Unlock()
	if name, _, required, ok := h.PendingLogin(context.Background(), flow, browser); !ok || !required || name != store.client.Name {
		t.Fatal("MFA-required client not described")
	}
	if _, _, _, ok := h.PendingLogin(context.Background(), flow, "wrong-browser"); ok {
		t.Fatal("cross-browser policy leak")
	}
	store.mu.Lock()
	store.client.RequireMFA = false
	store.mu.Unlock()
	req.RequiredACR = ACRMFA
	if err := store.CreateAuthorizationRequest(context.Background(), identity.Hash(flow), req); err != nil {
		t.Fatal(err)
	}
	if _, _, required, ok := h.PendingLogin(context.Background(), flow, browser); !ok || !required {
		t.Fatal("essential ACR not shown as requirement")
	}
}
