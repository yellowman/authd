package web

import (
	"bytes"
	"context"
	"image"
	"image/png"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/yellowman/authd/internal/identity"
)

type brandingTestStore struct {
	*testStore
	brand identity.Branding
}

func (m *brandingTestStore) Branding(context.Context) (identity.Branding, error) { return m.brand, nil }
func (m *brandingTestStore) SaveBranding(_ context.Context, _ []byte, b identity.Branding, replace, remove bool, _ identity.Audit) error {
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

func logoFixture(t *testing.T) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := png.Encode(&b, image.NewNRGBA(image.Rect(0, 0, 12, 8))); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func TestLoginBrandingAndEscaping(t *testing.T) {
	s, h, m := fixture(t, true)
	store := &brandingTestStore{testStore: m, brand: identity.Branding{Name: `Example <script>alert(1)</script>`, Logo: logoFixture(t), UpdatedAt: time.Now()}}
	s.auth.Store = store
	for _, path := range []string{"/login", "/admin/branding"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, request(s, m, "GET", path, nil, true))
		if w.Code != 200 {
			t.Fatal(path, w.Code)
		}
		html := w.Body.String()
		if !strings.Contains(html, "Example &lt;script&gt;") || strings.Contains(html, "Example <script>") || !strings.Contains(html, `src="/login/logo"`) {
			t.Fatal("branding missing or unescaped")
		}
		if strings.Contains(html, "There is no public signup") || strings.Contains(html, "Administrators manage accounts after signing in.") {
			t.Fatal("extraneous login copy retained")
		}
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, request(s, m, "GET", "/login/logo", nil, false))
	if w.Code != 200 || w.Header().Get("Content-Type") != "image/png" || !bytes.Equal(w.Body.Bytes(), store.brand.Logo) {
		t.Fatal("public local logo missing")
	}
	w = httptest.NewRecorder()
	r := request(s, m, "POST", "/login", url.Values{"username": {"bad"}, "password": {"bad"}}, false)
	r.AddCookie(&http.Cookie{Name: s.cookieName("browser"), Value: m.raw})
	r.PostForm = nil
	values := url.Values{"username": {"bad"}, "password": {"bad"}, "csrf_token": {s.auth.CSRF(m.raw, "browser")}}
	r = request(s, m, "POST", "/login", values, false)
	r.AddCookie(&http.Cookie{Name: s.cookieName("browser"), Value: m.raw})
	h.ServeHTTP(w, r)
	if w.Code != 401 || !strings.Contains(w.Body.String(), "Example &lt;script&gt;") {
		t.Fatal("failed sign-in lost branding", w.Code)
	}
}

func TestBrandingUploadSecurity(t *testing.T) {
	for _, mode := range []string{"valid", "remove", "missing_csrf", "origin", "nonadmin", "stale", "svg", "oversized", "duplicate", "conflict"} {
		t.Run(mode, func(t *testing.T) {
			s, h, m := fixture(t, mode != "nonadmin")
			store := &brandingTestStore{testStore: m, brand: identity.Branding{Name: "authd", Logo: logoFixture(t), UpdatedAt: time.Now()}}
			s.auth.Store = store
			var b bytes.Buffer
			form := multipart.NewWriter(&b)
			_ = form.WriteField("name", "Example Network")
			_ = form.WriteField("expected_updated_at", store.brand.UpdatedAt.Format(time.RFC3339Nano))
			if mode != "missing_csrf" {
				_ = form.WriteField("csrf_token", s.auth.CSRF(m.raw, "session"))
			}
			if mode == "duplicate" {
				_ = form.WriteField("name", "Second")
			}
			if mode == "remove" || mode == "conflict" {
				_ = form.WriteField("remove_logo", "true")
			}
			if mode != "remove" {
				f, _ := form.CreateFormFile("logo", "logo.png")
				raw := logoFixture(t)
				if mode == "svg" {
					raw = []byte(`<svg onload="alert(1)"></svg>`)
				}
				if mode == "oversized" {
					raw = make([]byte, 513<<10)
				}
				_, _ = f.Write(raw)
			}
			_ = form.Close()
			r := httptest.NewRequest("POST", s.cfg.Issuer+"/admin/branding", &b)
			r.Header.Set("Content-Type", form.FormDataContentType())
			r.Header.Set("Origin", s.cfg.Issuer)
			r.AddCookie(&http.Cookie{Name: s.cookieName("session"), Value: m.raw})
			if mode == "origin" {
				r.Header.Set("Origin", "https://other.example")
			}
			if mode == "stale" {
				m.session.AuthTime = time.Now().Add(-11 * time.Minute)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if mode == "valid" || mode == "remove" {
				if w.Code != 303 || m.mutationCalls != 1 || store.brand.Name != "Example Network" {
					t.Fatal("save failed", w.Code, w.Body.String())
				}
				if mode == "remove" && len(store.brand.Logo) != 0 {
					t.Fatal("logo not removed")
				}
			} else if w.Code < 400 || m.mutationCalls != 0 {
				t.Fatal("unsafe update accepted", w.Code)
			}
		})
	}
}

func TestLogoLimits(t *testing.T) {
	for _, raw := range [][]byte{[]byte("<svg/>"), []byte("not an image"), make([]byte, 262145)} {
		if _, err := normalizeLogo(raw); err == nil {
			t.Fatal("unsafe logo accepted")
		}
	}
	var wide bytes.Buffer
	_ = png.Encode(&wide, image.NewNRGBA(image.Rect(0, 0, 2049, 1)))
	if _, err := normalizeLogo(wide.Bytes()); err == nil {
		t.Fatal("oversized dimensions accepted")
	}
}
