//go:build browser

package oidc

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
)

func TestBrowserNativeConsentAndLogout(t *testing.T) {
	_, svc, store, sessions, raw, _ := providerFixture(t)
	var handler http.Handler
	var mu sync.Mutex // protects test fixture across CSS/navigation requests
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { mu.Lock(); defer mu.Unlock(); handler.ServeHTTP(w, r) }))
	defer ts.Close()
	svc.issuer = ts.URL
	store.client.RedirectURIs = []string{ts.URL + "/auth/callback"}
	store.client.LogoutURIs = []string{ts.URL + "/"}
	h := NewHTTP(svc, ts.URL, false)
	mux := http.NewServeMux()
	h.Register(mux)
	mux.HandleFunc("GET /auth/callback", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("code") == "" || r.URL.Query().Get("state") != "browser-test" {
			http.Error(w, "missing sign-in result", 400)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte("<h1>Callback received</h1>"))
	})
	mux.HandleFunc("GET /login", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("Signed out")) })
	mux.HandleFunc("GET /static/app.css", func(w http.ResponseWriter, r *http.Request) { http.ServeFile(w, r, "../web/static/app.css") })
	handler = mux
	_, challenge := verifierAndChallenge()
	q := url.Values{"response_type": {"code"}, "client_id": {"bdcmaps"}, "redirect_uri": {store.client.RedirectURIs[0]}, "scope": {"openid profile email groups offline_access"}, "prompt": {"consent"}, "state": {"browser-test"}, "nonce": {"browser-nonce"}, "code_challenge": {challenge}, "code_challenge_method": {"S256"}}
	data, err := json.Marshal(map[string]string{"scenario": "oidc", "origin": ts.URL, "session": raw, "authorize": ts.URL + "/authorize?" + q.Encode(), "output": os.Getenv("AUTHD_BROWSER_OUTPUT_DIR")})
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
		t.Fatal("native OIDC browser witness:", err)
	}
	mu.Lock()
	ended := sessions.ended
	mu.Unlock()
	if !ended {
		t.Fatal("browser never completed the actual logout handler")
	}
}
