package docsite

import (
	"fmt"
	"html"
	"net/url"
	"path"
	"strconv"
	"strings"
	"unicode"

	"github.com/yellowman/authd/internal/thirdparty/markdown"
)

type renderedDocument struct {
	title, body string
	headings    []Heading
}
type renderer struct {
	library  *Library
	name     string
	body     strings.Builder
	headings []Heading
	ids      map[string]int
	usedIDs  map[string]bool
	title    string
	err      error
}

func (l *Library) render(name, source string) (renderedDocument, error) {
	p := markdown.Parser{Table: true, Strikethrough: true, TaskListItems: true, AutoLinkText: true}
	r := renderer{library: l, name: name, ids: make(map[string]int), usedIDs: make(map[string]bool)}
	r.block(p.Parse(source), 0)
	return renderedDocument{title: r.title, body: r.body.String(), headings: r.headings}, r.err
}

// No AST node's PrintHTML method is called. This small allow-list is the HTML
// security boundary; parsing Markdown grammar is the upstream parser's job.
func (r *renderer) block(b markdown.Block, depth int) {
	if depth > 128 {
		r.err = fmt.Errorf("documentation nesting limit exceeded")
		return
	}
	children := func(blocks []markdown.Block) {
		for _, child := range blocks {
			r.block(child, depth+1)
		}
	}
	switch b := b.(type) {
	case *markdown.Document:
		children(b.Blocks)
	case *markdown.Heading:
		text := plain(b.Text.Inline)
		if r.title == "" {
			r.title = text
		}
		base := slug(text)
		n := r.ids[base]
		id := "doc-" + base
		if n > 0 {
			id += "-" + strconv.Itoa(n)
		}
		// A literal heading ending in "-1" must not collide with a
		// duplicate heading's generated suffix.
		for r.usedIDs[id] {
			n++
			id = "doc-" + base + "-" + strconv.Itoa(n)
		}
		r.ids[base] = n + 1
		r.usedIDs[id] = true
		r.headings = append(r.headings, Heading{ID: id, Text: text, Level: b.Level})
		level := min(b.Level+1, 6) // the surrounding page owns the single h1
		fmt.Fprintf(&r.body, `<h%d id="%s">`, level, html.EscapeString(id))
		r.inlines(b.Text.Inline, depth+1)
		fmt.Fprintf(&r.body, "</h%d>\n", level)
	case *markdown.Paragraph:
		r.body.WriteString("<p>")
		r.inlines(b.Text.Inline, depth+1)
		r.body.WriteString("</p>\n")
	case *markdown.Text:
		r.inlines(b.Inline, depth+1)
	case *markdown.CodeBlock:
		r.body.WriteString("<pre><code>")
		r.body.WriteString(html.EscapeString(strings.Join(b.Text, "\n")))
		r.body.WriteString("</code></pre>\n")
	case *markdown.Quote:
		r.body.WriteString("<blockquote>")
		children(b.Blocks)
		r.body.WriteString("</blockquote>\n")
	case *markdown.List:
		tag := "ul"
		if b.Bullet == '.' || b.Bullet == ')' {
			tag = "ol"
		}
		r.body.WriteString("<" + tag)
		if tag == "ol" && b.Start != 1 {
			fmt.Fprintf(&r.body, ` start="%d"`, b.Start)
		}
		r.body.WriteString(">\n")
		children(b.Items)
		r.body.WriteString("</" + tag + ">\n")
	case *markdown.Item:
		r.body.WriteString("<li>")
		children(b.Blocks)
		r.body.WriteString("</li>\n")
	case *markdown.Table:
		r.body.WriteString(`<div class="table-wrap" role="region" aria-label="Documentation table" tabindex="0"><table><thead><tr>`)
		for _, t := range b.Header {
			r.body.WriteString(`<th scope="col">`)
			r.inlines(t.Inline, depth+1)
			r.body.WriteString("</th>")
		}
		r.body.WriteString("</tr></thead><tbody>")
		for _, row := range b.Rows {
			r.body.WriteString("<tr>")
			for _, t := range row {
				r.body.WriteString("<td>")
				r.inlines(t.Inline, depth+1)
				r.body.WriteString("</td>")
			}
			r.body.WriteString("</tr>")
		}
		r.body.WriteString("</tbody></table></div>\n")
	case *markdown.HTMLBlock:
		// Show markup as source; never execute even release-authored HTML.
		r.body.WriteString(`<pre class="literal-html"><code>`)
		r.body.WriteString(html.EscapeString(strings.Join(b.Text, "\n")))
		r.body.WriteString("</code></pre>\n")
	case *markdown.ThematicBreak:
		r.body.WriteString("<hr>\n")
	case *markdown.Empty:
	default:
		r.err = fmt.Errorf("unsupported documentation block %T", b)
	}
}

func (r *renderer) inlines(nodes []markdown.Inline, depth int) {
	if depth > 128 {
		r.err = fmt.Errorf("documentation nesting limit exceeded")
		return
	}
	for _, node := range nodes {
		switch n := node.(type) {
		case *markdown.Plain:
			r.body.WriteString(html.EscapeString(n.Text))
		case *markdown.Escaped:
			r.body.WriteString(html.EscapeString(n.Text))
		case *markdown.Code:
			r.body.WriteString("<code>" + html.EscapeString(n.Text) + "</code>")
		case *markdown.Emph:
			r.body.WriteString("<em>")
			r.inlines(n.Inner, depth+1)
			r.body.WriteString("</em>")
		case *markdown.Strong:
			r.body.WriteString("<strong>")
			r.inlines(n.Inner, depth+1)
			r.body.WriteString("</strong>")
		case *markdown.Del:
			r.body.WriteString("<del>")
			r.inlines(n.Inner, depth+1)
			r.body.WriteString("</del>")
		case *markdown.Link:
			r.link(n.URL, n.Inner, depth)
		case *markdown.AutoLink:
			r.link(n.URL, []markdown.Inline{&markdown.Plain{Text: n.Text}}, depth)
		case *markdown.Image:
			// Images never make the administrator's browser fetch a tracking URL.
			r.body.WriteString(`<span class="doc-image">Image: `)
			r.link(n.URL, n.Inner, depth)
			r.body.WriteString("</span>")
		case *markdown.HTMLTag:
			r.body.WriteString(html.EscapeString(n.Text))
		case *markdown.HardBreak:
			r.body.WriteString("<br>\n")
		case *markdown.SoftBreak:
			r.body.WriteByte('\n')
		case *markdown.Emoji:
			r.body.WriteString(html.EscapeString(n.Text))
		case *markdown.Task:
			if n.Checked {
				r.body.WriteString(`<span class="doc-task" aria-label="Completed">☑ </span>`)
			} else {
				r.body.WriteString(`<span class="doc-task" aria-label="Not completed">☐ </span>`)
			}
		default:
			r.err = fmt.Errorf("unsupported documentation inline %T", n)
		}
	}
}
func (r *renderer) link(raw string, label []markdown.Inline, depth int) {
	href, external := r.library.resolveLink(r.name, raw)
	if href == "" {
		r.body.WriteString(`<span class="doc-unlinked">`)
		r.inlines(label, depth+1)
		r.body.WriteString("</span>")
		return
	}
	r.body.WriteString(`<a href="` + html.EscapeString(href) + `"`)
	if external {
		r.body.WriteString(` rel="noreferrer noopener"`)
	}
	r.body.WriteByte('>')
	r.inlines(label, depth+1)
	r.body.WriteString("</a>")
}
func plain(nodes []markdown.Inline) string {
	var b strings.Builder
	for _, node := range nodes {
		switch n := node.(type) {
		case *markdown.Plain:
			b.WriteString(n.Text)
		case *markdown.Escaped:
			b.WriteString(n.Text)
		case *markdown.Code:
			b.WriteString(n.Text)
		case *markdown.Emph:
			b.WriteString(plain(n.Inner))
		case *markdown.Strong:
			b.WriteString(plain(n.Inner))
		case *markdown.Del:
			b.WriteString(plain(n.Inner))
		case *markdown.Link:
			b.WriteString(plain(n.Inner))
		case *markdown.Image:
			b.WriteString(plain(n.Inner))
		case *markdown.AutoLink:
			b.WriteString(n.Text)
		case *markdown.SoftBreak, *markdown.HardBreak:
			b.WriteByte(' ')
		case *markdown.Emoji:
			b.WriteString(n.Text)
		}
	}
	return strings.TrimSpace(b.String())
}
func slug(text string) string {
	var b strings.Builder
	for _, c := range strings.ToLower(text) {
		switch {
		case unicode.IsLetter(c) || unicode.IsNumber(c) || c == '-' || c == '_':
			b.WriteRune(c)
		case unicode.IsSpace(c):
			b.WriteByte('-')
		}
	}
	if b.Len() == 0 {
		return "section"
	}
	return b.String()
}

func (l *Library) resolveLink(from, raw string) (string, bool) {
	raw = html.UnescapeString(strings.TrimSpace(raw))
	if raw == "" || strings.ContainsAny(raw, "\\\x00\r\n\t") || strings.HasPrefix(raw, "//") {
		return "", false
	}
	u, err := url.Parse(raw)
	if err != nil || u.User != nil {
		return "", false
	}
	if u.IsAbs() {
		switch strings.ToLower(u.Scheme) {
		case "https", "http":
			if u.Hostname() != "" {
				return u.String(), true
			}
		case "mailto":
			if u.Opaque != "" {
				return u.String(), true
			}
		}
		return "", false
	}
	if u.Host != "" {
		return "", false
	}
	// Only explicitly named UI destinations may appear as root-relative links.
	if strings.HasPrefix(u.Path, "/") {
		if u.Path == "/admin/" {
			q, err := url.ParseQuery(u.RawQuery)
			if err != nil || len(q) != 1 || len(q["view"]) != 1 {
				return "", false
			}
			switch q.Get("view") {
			case "users", "roles", "permissions", "clients", "sessions", "keys", "audit", "guide":
				return "/admin/?view=" + q.Get("view"), false
			}
		}
		if (u.Path == "/account" || u.Path == "/login" || u.Path == "/admin/docs") && u.RawQuery == "" && u.Fragment == "" {
			return u.Path, false
		}
		return "", false
	}
	if u.RawQuery != "" {
		return "", false
	}
	name := from
	if u.Path != "" {
		name = path.Clean(path.Join(path.Dir(from), u.Path))
	}
	if _, ok := l.files[name]; !ok {
		return "", false
	}
	fragment := ""
	if u.Fragment != "" {
		fragment = "#" + url.PathEscape("doc-"+u.Fragment)
	}
	if strings.ToLower(path.Ext(name)) == ".md" {
		if u.Path == "" {
			return fragment, false
		}
		return URL(name) + fragment, false
	}
	return "/admin/docs/raw?doc=" + url.QueryEscape(name), false
}
