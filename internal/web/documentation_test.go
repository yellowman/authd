package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/yellowman/authd/internal/docsite"
)

func TestDocumentationRequiresLiveAdministrator(t *testing.T) {
	for _, admin := range []bool{false, true} {
		s, h, m := fixture(t, admin)
		for _, p := range []string{"/admin/docs", "/admin/docs?doc=README.md", "/admin/docs/raw?doc=README.md"} {
			for _, authenticated := range []bool{false, true} {
				w := httptest.NewRecorder()
				h.ServeHTTP(w, request(s, m, "GET", p, nil, authenticated))
				if !authenticated {
					if w.Code != http.StatusSeeOther {
						t.Fatalf("anonymous %s: %d", p, w.Code)
					}
					continue
				}
				want := 200
				if !admin {
					want = 403
				}
				if w.Code != want {
					t.Errorf("admin=%v %s: %d", admin, p, w.Code)
				}
				if w.Header().Get("Cache-Control") != "no-store" {
					t.Fatal("documentation response can be cached")
				}
			}
		}
		if m.adminCalls != 0 {
			t.Fatal("documentation read scanned identity catalog")
		}
	}
}
func TestEveryDocumentCanBeReadAndDownloaded(t *testing.T) {
	s, h, m := fixture(t, true)
	for _, group := range s.docs.Groups("") {
		for _, e := range group.Entries {
			w := httptest.NewRecorder()
			h.ServeHTTP(w, request(s, m, "GET", e.URL, nil, true))
			if w.Code != 200 || !strings.Contains(w.Body.String(), `class="markdown-body"`) {
				t.Fatalf("%s: %d", e.Path, w.Code)
			}
			w = httptest.NewRecorder()
			h.ServeHTTP(w, request(s, m, "GET", "/admin/docs/raw?doc="+url.QueryEscape(e.Path), nil, true))
			want, _ := s.docs.Source(e.Path)
			if w.Code != 200 || w.Body.String() != want || w.Header().Get("Content-Type") != "text/plain; charset=utf-8" {
				t.Fatalf("raw %s did not match source", e.Path)
			}
		}
	}
	if m.adminCalls != 0 {
		t.Fatal("catalog scan on documentation read")
	}
}
func TestDocumentationTraversalAndQueryRefusal(t *testing.T) {
	s, h, m := fixture(t, true)
	for _, name := range []string{"SPEC.md", "../../etc/passwd", "/etc/passwd", "docs/../SPEC.md", "%2e%2e/SPEC.md", ".env.example", ".git/config", "go.mod", "missing.md", "docs\\ADDING_AN_APP.md"} {
		for _, base := range []string{"/admin/docs?doc=", "/admin/docs/raw?doc="} {
			w := httptest.NewRecorder()
			h.ServeHTTP(w, request(s, m, "GET", base+url.QueryEscape(name), nil, true))
			if w.Code != 404 {
				t.Errorf("%s%s: %d", base, name, w.Code)
			}
		}
	}
	for _, q := range []string{"doc=SPEC.md&doc=README.md", "q=x&q=y", "q=" + strings.Repeat("a", 201), "unknown=x"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, request(s, m, "GET", "/admin/docs?"+q, nil, true))
		if w.Code != 400 {
			t.Errorf("query accepted: %q", q)
		}
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, request(s, m, "GET", "/admin/docs?q="+url.QueryEscape(`<script>alert(1)</script>`), nil, true))
	if w.Code != 200 || strings.Contains(w.Body.String(), "<script>alert") {
		t.Fatal("search input became HTML")
	}
}
func TestSidebarUsesAccessibleSVGsAndCurrentPage(t *testing.T) {
	s, h, m := fixture(t, true)
	for _, view := range []string{"guide", "users", "roles", "groups", "permissions", "sessions", "audit"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, request(s, m, "GET", "/admin/?view="+view, nil, true))
		rail := regexp.MustCompile(`(?s)<aside class="rail".*?</aside>`).FindString(w.Body.String())
		// The rail has the admin entries plus its two fixed navigation links.
		iconCount := len(adminNavigation(view)) + 2
		if strings.Count(rail, "<svg ") != iconCount {
			t.Fatalf("rail needs %d actual SVGs, got %d", iconCount, strings.Count(rail, "<svg "))
		}
		if strings.Count(rail, `aria-current="page"`) != 1 {
			t.Fatal("rail must have exactly one active page")
		}
		if strings.Count(rail, `aria-hidden="true"`) != iconCount || strings.Count(rail, `focusable="false"`) != iconCount {
			t.Fatal("decorative SVG is not hidden from accessibility tree")
		}
		if regexp.MustCompile(`>[A-Z?@]</a>`).MatchString(rail) {
			t.Fatal("letter navigation remains")
		}
		for _, link := range adminNavigation(view) {
			if !strings.Contains(rail, `aria-label="`+link.Label+`"`) {
				t.Errorf("missing accessible name %s", link.Label)
			}
		}
	}
}

// Exercise the HTTP index with filenames the product has never seen before.
func TestDocumentationIndexUsesSourceTreeNotAnAppRegistry(t *testing.T) {
	s, h, m := fixture(t, true)
	var err error
	s.docs, err = docsite.New(fstest.MapFS{
		"README.md":                        {Data: []byte("# An authored overview\n")},
		"docs/new-folder/guide & notes.md": {Data: []byte("# New & useful\n")},
		"docs/new-folder/no-heading.md":    {Data: []byte("Plain documentation.\n")},
		"docs/<unsafe>/entry.md":           {Data: []byte("# Heading\n")},
	})
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, request(s, m, "GET", "/admin/docs", nil, true))
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	body := w.Body.String()
	for _, want := range []string{
		"<code>./</code>", "<code>docs/new-folder/</code>",
		"<strong>README.md</strong>", "An authored overview",
		"<strong>guide &amp; notes.md</strong>", "New &amp; useful",
		"<strong>no-heading.md</strong>", "4 documents in this release",
		"<code>docs/&lt;unsafe&gt;/</code>",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("index did not reflect source tree: missing %q", want)
		}
	}
	for _, unwanted := range []string{"<unsafe>", "Get started</h2>", "Connect applications</h2>", "BDC Maps", "BDCMAPS_INTEGRATION"} {
		if strings.Contains(body, unwanted) {
			t.Errorf("invented category/app or unsafe path: %q", unwanted)
		}
	}
	for _, group := range s.docs.Groups("") {
		for _, e := range group.Entries {
			w := httptest.NewRecorder()
			h.ServeHTTP(w, request(s, m, "GET", e.URL, nil, true))
			if w.Code != 200 {
				t.Errorf("discovered document not readable: %s: %d", e.Path, w.Code)
			}
		}
	}
}
