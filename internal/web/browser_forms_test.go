//go:build browser

package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/yellowman/authd/internal/identity"
)

// Only the persistence/credential fixture is synthetic. Pages, form submission,
// cookies, CSRF, origin enforcement, TLS and navigation use actual application
// handlers and Chromium. This does not qualify PostgreSQL or the Argon2 KDF.
type browserIdentityStore struct {
	*testStore
	setupOpen  bool
	brand      identity.Branding
	bootstraps int
}

func (m *browserIdentityStore) Branding(context.Context) (identity.Branding, error) {
	return m.brand, nil
}
func (m *browserIdentityStore) SaveBranding(_ context.Context, _ []byte, b identity.Branding, replace, remove bool, _ identity.Audit) error {
	m.mutationCalls++
	m.brand.Name = b.Name
	if replace {
		m.brand.Logo = b.Logo
	}
	if remove {
		m.brand.Logo = nil
	}
	return nil
}

func (m *browserIdentityStore) BootstrapOpen(context.Context) (bool, error) { return m.setupOpen, nil }
func (m *browserIdentityStore) Bootstrap(_ context.Context, _ []byte, _ identity.NewUser, _ identity.Audit) error {
	m.bootstraps++
	m.setupOpen = false
	return nil
}

func TestBrowserNativeWebForms(t *testing.T) { browserWebFixture(t, "web") }
func TestBrowserOperatorLayout(t *testing.T) { browserWebFixture(t, "layout") }
func browserWebFixture(t *testing.T, scenario string) {
	s, _, m := fixture(t, true)
	bs := &browserIdentityStore{testStore: m, setupOpen: true, brand: identity.Branding{Name: "Example Network", UpdatedAt: time.Now()}}
	s.auth.Store = bs
	var handler http.Handler
	var mu sync.Mutex // shared fixture state, not a production serialization rule
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { mu.Lock(); defer mu.Unlock(); handler.ServeHTTP(w, r) }))
	defer ts.Close()
	s.cfg.Issuer = ts.URL
	helpProvider(t, s)
	var err error
	handler, err = s.Handler()
	if err != nil {
		t.Fatal(err)
	}
	manifest := map[string]string{"scenario": scenario, "origin": ts.URL, "session": m.raw, "username": "alice", "password": "correct password", "output": os.Getenv("AUTHD_BROWSER_OUTPUT_DIR")}
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "fixture.json")
	if err = os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("python3", "../../scripts/browser_forms.py", path)
	out, err := cmd.CombinedOutput()
	t.Log(string(out))
	if err != nil {
		t.Fatal("browser "+scenario+" witness:", err)
	}
	mu.Lock()
	bootstraps, logins, mutations := bs.bootstraps, m.sessionCreates, m.mutationCalls
	mu.Unlock()
	if scenario == "web" && (bootstraps != 1 || logins < 1 || mutations < 1) {
		t.Fatalf("real form handlers not reached: bootstrap=%d login=%d mutation=%d", bootstraps, logins, mutations)
	}
}
