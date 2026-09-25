//go:build linux || openbsd

package web

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/yellowman/authd/internal/listener"
	"github.com/yellowman/authd/internal/oidc"
)

// This exercises a real HTTPS connection, a real HTTP reverse proxy, a real
// filesystem Unix listener and the real web handlers. The identity store/KDF are
// test fixtures; it is not PostgreSQL or an nginx/OpenBSD deployment witness.
func TestHTTPSProxyToUnixLoginCookiesAndIdentity(t *testing.T) {
	dir, err := os.MkdirTemp("", "authd-http-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "authd.sock")
	ln, err := listener.Open(listener.Options{Address: "unix:" + path})
	if err != nil {
		t.Fatal(err)
	}
	tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", path)
	}}
	defer tr.CloseIdleConnections()
	backendURL, _ := url.Parse("http://authd-internal")
	proxy := httptest.NewTLSServer(&httputil.ReverseProxy{Transport: tr, Rewrite: func(p *httputil.ProxyRequest) {
		p.SetURL(backendURL)
		p.Out.Host = p.In.Host
		peer, _, _ := net.SplitHostPort(p.In.RemoteAddr)
		// The edge overwrites incoming forwarding metadata, as the deployment
		// example requires, rather than promoting a browser-supplied leftmost IP.
		p.Out.Header.Set("X-Forwarded-For", peer)
		p.Out.Header.Set("X-Forwarded-Proto", "https")
	}})
	defer proxy.Close()
	s, _, store := fixture(t, false)
	s.cfg.Issuer = proxy.URL
	s.cfg.TrustUnixProxy = true
	s.oidc = oidc.NewHTTP(nil, proxy.URL, false)
	handler, err := s.Handler()
	if err != nil {
		t.Fatal(err)
	}
	completed := make(chan struct{}, 16)
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() { completed <- struct{}{} }()
		handler.ServeHTTP(w, r)
	})}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- listener.Serve(ctx, srv, ln, time.Second) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()
	client := proxy.Client()
	client.Timeout = 2 * time.Second
	client.Jar, _ = cookiejar.New(nil)
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	fetch := func(method, path string, form url.Values, origin string) (*http.Response, []byte) {
		t.Helper()
		var body io.Reader
		if form != nil {
			body = strings.NewReader(form.Encode())
		}
		req, err := http.NewRequest(method, proxy.URL+path, body)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("X-Forwarded-For", "203.0.113.123")
		req.Header.Set("X-Forwarded-Proto", "http")
		if form != nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("Origin", origin)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		select {
		case <-completed:
		case <-time.After(time.Second):
			t.Fatal("handler did not finish")
		}
		return resp, data
	}
	for _, path := range []string{"/healthz", "/.well-known/openid-configuration"} {
		resp, body := fetch("GET", path, nil, "")
		if resp.StatusCode != 200 {
			t.Fatalf("%s status=%d body=%s", path, resp.StatusCode, body)
		}
		if path != "/healthz" {
			var doc map[string]any
			if err = json.Unmarshal(body, &doc); err != nil {
				t.Fatal(err)
			}
			if doc["issuer"] != proxy.URL {
				t.Fatal("issuer became Unix/internal URL", doc["issuer"])
			}
		}
	}
	resp, body := fetch("GET", "/login", nil, "")
	match := regexp.MustCompile(`name="csrf_token" value="([^"]+)"`).FindSubmatch(body)
	if len(match) != 2 {
		t.Fatalf("no browser-bound form CSRF: %s", body)
	}
	if len(resp.Cookies()) == 0 {
		t.Fatal("no browser cookie")
	}
	for _, c := range resp.Cookies() {
		if !c.Secure || !c.HttpOnly || c.Path != "/" || c.Domain != "" {
			t.Fatal("insecure production cookie")
		}
	}
	form := url.Values{"username": {"alice"}, "password": {"correct password"}, "csrf_token": {string(match[1])}}
	resp, body = fetch("POST", "/login", form, proxy.URL)
	if resp.StatusCode != 303 {
		t.Fatalf("login status=%d body=%s", resp.StatusCode, body)
	}
	if store.loginAudit.IP != "127.0.0.1" {
		t.Fatalf("spoofed client IP accepted: %q", store.loginAudit.IP)
	}
	found := false
	for _, c := range resp.Cookies() {
		if c.Name == "__Host-authd_session" {
			found = true
			if !c.Secure || !c.HttpOnly || c.Path != "/" || c.Domain != "" || c.SameSite != http.SameSiteLaxMode {
				t.Fatal("invalid session cookie attributes")
			}
		}
	}
	if !found {
		t.Fatal("no secure session cookie")
	}
	// Go's CookieJar treats loopback HTTP as a secure origin. Test the same
	// response cookies under a non-loopback host to assert production behavior.
	productionHTTPS, _ := url.Parse("https://auth.example.test/")
	client.Jar.SetCookies(productionHTTPS, resp.Cookies())
	insecure, _ := url.Parse("http://auth.example.test/")
	for _, c := range client.Jar.Cookies(insecure) {
		if c.Name == "__Host-authd_session" {
			t.Fatal("secure cookie leaked to HTTP")
		}
	}
	resp, body = fetch("GET", "/account", nil, "")
	if resp.StatusCode != 200 {
		t.Fatalf("account status=%d body=%s", resp.StatusCode, body)
	}
	match = regexp.MustCompile(`name="csrf_token" value="([^"]+)"`).FindSubmatch(body)
	if len(match) != 2 {
		t.Fatal("no authenticated form CSRF")
	}
	resp, _ = fetch("POST", "/session/logout", url.Values{"csrf_token": {string(match[1])}}, "https://attacker.test")
	if resp.StatusCode != 403 || store.revoked {
		t.Fatal("proxying bypassed Origin/CSRF")
	}
	cancel()
	// The deferred Serve wait proves listener cleanup; proxy must not be
	// switched to a new transport until this new version passes its site smoke.
}
