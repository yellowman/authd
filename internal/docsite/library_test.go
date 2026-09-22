package docsite

import (
	"strings"
	"sync"
	"testing"
	"testing/fstest"
)

func testLibrary(t *testing.T, source string) *Library {
	t.Helper()
	l, err := New(fstest.MapFS{
		"README.md":      {Data: []byte("# Overview\n\n[Start](docs/start.md#same)")},
		"docs/start.md":  {Data: []byte(source)},
		"docs/check.log": {Data: []byte("PASS fixture evidence")},
	})
	if err != nil {
		t.Fatal(err)
	}
	return l
}
func TestMarkdownStructureAndRelativeLinks(t *testing.T) {
	source := "# Setup\n\n## Same\n\n## Same\n\n**Strong** and *emphasis* with `code` and ~~old~~.\n\n1. First\n   - Nested\n2. Second\n\n> Quoted\n\n| Field | Value |\n| --- | --- |\n| Issuer | HTTPS |\n\n```sh\necho '<script>not executable</script>'\n```\n\n[Overview](../README.md) [Evidence](check.log) [Anchor](#same) [Ref][r]\n\n[r]: ../README.md\n"
	l := testLibrary(t, source)
	d, ok := l.Document("docs/start.md")
	if !ok {
		t.Fatal("missing document")
	}
	body := string(d.Body)
	for _, want := range []string{"<h2", `id="doc-same"`, `id="doc-same-1"`, "<strong>Strong</strong>", "<em>emphasis</em>", "<ol>", "<ul>", "<blockquote>", "<table>", "<pre><code>", "&lt;script&gt;", "<del>old</del>", `/admin/docs?doc=README.md`, `/admin/docs/raw?doc=docs%2Fcheck.log`, `href="#doc-same"`} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q in %s", want, body)
		}
	}
	if d.Title != "Setup" || len(d.TOC) != 3 {
		t.Fatalf("bad title/TOC: %+v", d)
	}
	if strings.Contains(body, "<script>") {
		t.Fatal("fenced code became active HTML")
	}
}
func TestRendererNeverExecutesHTMLOrLoadsImages(t *testing.T) {
	source := "# Safety\n\n<script>alert(1)</script>\n\n<form action='/admin/users/delete'><input name='id'></form>\n\nText <img src=x onerror=alert(1)> <svg onload=alert(1)>\n\n[bad](javascript:alert) [encoded](javascript&#58;alert) [data](data:text/html,bad) [file](file:///etc/passwd) [relative](//evil.test/x)\n\n![tracking](https://evil.test/pixel)\n\n[good](https://example.test/docs)\n"
	l := testLibrary(t, source)
	d, _ := l.Document("docs/start.md")
	b := string(d.Body)
	for _, bad := range []string{"<script", "<form", "<input", "<img", "<svg", `href="javascript:`, `href="data:`, `href="file:`, `href="//`} {
		if strings.Contains(b, bad) {
			t.Errorf("active HTML/link %q: %s", bad, b)
		}
	}
	if !strings.Contains(b, `href="https://example.test/docs" rel="noreferrer noopener"`) {
		t.Fatal("safe external link missing")
	}
}
func TestCatalogLinkAllowList(t *testing.T) {
	l := testLibrary(t, "# Start")
	for _, bad := range []string{"../../../etc/passwd", "/etc/passwd", "../../README.md", "../.env.example", "https://u:p@host/a", "data:text/html,a", "JaVaScRiPt:alert(1)", "%6aavascript:alert(1)", "java\tscript:alert(1)", "//host/file", "\\host\\file", "../README.md?raw=1", "/admin/users/delete", "/admin/?view=clients&grant=admin"} {
		if href, _ := l.resolveLink("docs/start.md", bad); href != "" {
			t.Errorf("accepted %q => %q", bad, href)
		}
	}
	for raw, want := range map[string]string{"../README.md": "/admin/docs?doc=README.md", "/admin/?view=roles": "/admin/?view=roles", "start.md#same": "/admin/docs?doc=docs%2Fstart.md#doc-same", "#same": "#doc-same", "/account": "/account"} {
		if href, _ := l.resolveLink("docs/start.md", raw); href != want {
			t.Errorf("%q => %q, want %q", raw, href, want)
		}
	}
}
func TestSearchAndReadOnlyCatalog(t *testing.T) {
	l := testLibrary(t, "# Setup\n\nAn unusual giraffe callback.\n\n## Section")
	if len(l.Groups("GIRAFFE callback")) != 1 {
		t.Fatal("full text search is not case-insensitive AND matching")
	}
	if len(l.Groups("missing-term")) != 0 {
		t.Fatal("search fabricated a match")
	}
	d, _ := l.Document("docs/start.md")
	d.TOC[0].Text = "mutated"
	d, _ = l.Document("docs/start.md")
	if d.TOC[0].Text == "mutated" {
		t.Fatal("caller mutated cached TOC")
	}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				l.Document("docs/start.md")
				l.Groups("callback")
				l.Source("docs/check.log")
			}
		}()
	}
	wg.Wait()
}
func TestDocumentBounds(t *testing.T) {
	if _, err := New(fstest.MapFS{"large.md": {Data: []byte(strings.Repeat("a", maxDocumentBytes+1))}}); err == nil {
		t.Fatal("oversized document accepted")
	}
	if _, err := New(fstest.MapFS{"bad.md": {Data: []byte{0xff}}}); err == nil {
		t.Fatal("invalid UTF-8 accepted")
	}
}
func FuzzSafeMarkdownRendering(f *testing.F) {
	f.Add("# Heading\n\n[x](javascript:alert(1))")
	f.Add("<script>alert(1)</script>")
	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > 8192 {
			t.Skip()
		}
		l, err := New(fstest.MapFS{"test.md": {Data: []byte(input)}})
		if err != nil {
			return
		}
		d, _ := l.Document("test.md")
		for _, bad := range []string{"<script", "<iframe", "<object", "<img", "<form", `href="javascript:`, `href="data:`, `href="file:`} {
			if strings.Contains(strings.ToLower(string(d.Body)), bad) {
				t.Fatalf("unsafe rendering %q", bad)
			}
		}
	})
}

func TestHeadingIDsRemainUniqueAcrossLiteralSuffixes(t *testing.T) {
	l := testLibrary(t, "# Same\n\n## Same-1\n\n## Same\n\n## Same-2\n\n## Same\n")
	d, _ := l.Document("docs/start.md")
	seen := map[string]bool{}
	for _, h := range d.TOC {
		if seen[h.ID] {
			t.Fatalf("duplicate heading ID %q", h.ID)
		}
		seen[h.ID] = true
		if strings.Count(string(d.Body), `id="`+h.ID+`"`) != 1 {
			t.Fatalf("heading target %q missing or duplicated", h.ID)
		}
	}
}
