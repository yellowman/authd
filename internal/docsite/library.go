// Package docsite renders only a finite, embedded release catalog.
// It never reads request-selected filesystem paths or fetches URLs.
package docsite

import (
	"fmt"
	"html/template"
	"io/fs"
	"net/url"
	"path"
	"sort"
	"strings"
	"unicode/utf8"
)

const (
	StartDocument    = "docs/ADDING_AN_APP.md"
	maxDocumentBytes = 1 << 20
	maxLibraryBytes  = 16 << 20
	maxFiles         = 512
)

type Heading struct {
	ID, Text string
	Level    int
}
type Entry struct{ Path, Title, Description, Category, URL string }
type Group struct {
	Name    string
	Entries []Entry
}

type Document struct {
	Entry
	Body   template.HTML // only the allow-list renderer constructs this value
	TOC    []Heading
	Source string
}

type Library struct {
	documents map[string]Document
	files     map[string]string
	entries   []Entry
	search    map[string]string
}

var descriptions = map[string]string{
	StartDocument:                  "Connect any OIDC application, choose an access model, and assign people the right roles.",
	"OPERATOR_GUIDE.md":            "Everyday user, role, permission, client and session administration.",
	"DEPLOYMENT.md":                "PostgreSQL setup, installation, runtime configuration and upgrades.",
	"DESIGN_LANGUAGE.md":           "Layout, typography, icon and interaction rules for the interface.",
	"SPEC.md":                      "The binding product, protocol and security requirements.",
	"ARCHITECTURE.md":              "Components, data ownership and transaction boundaries.",
	"SECURITY.md":                  "Security invariants, known limits and reporting guidance.",
	"VALIDATION.md":                "What was actually exercised, including the verified first relying party.",
	"CHANGELOG.md":                 "Release changes and upgrade consequences.",
	"TODO.md":                      "Remaining implementation and qualification work.",
	"README.md":                    "Product overview and entry points.",
	"docs/RP_INTEGRATION.md":       "Identity linking, scopes, tenant boundaries, MFA, sessions and logout for app developers.",
	"docs/BDCMAPS_INTEGRATION.md":  "The BDC Maps client settings and the first verified application profile.",
	"docs/UNIX_SOCKET.md":          "Unix sockets, proxy group permissions and nginx chroot paths.",
	"docs/BROWSER_TESTS.md":        "Native browser form tests and the distinction from layout checks.",
	"docs/DOCUMENTATION_PORTAL.md": "How release Markdown is embedded, rendered and kept safe.",
	"docs/FIELD_REFERENCE.md":      "What each form field means, what to enter and what changing it affects.",
	"deploy/openbsd/README.md":     "OpenBSD service installation, environment loading and rc.d operation.",
	"deploy/systemd/README.md":     "Linux installation, runtime directories and systemd operation.",
	"deploy/postgresql/README.md":  "Database and role bootstrap, migrations and restricted runtime grants.",
	"AGENTS.md":                    "Repository rules for contributors: architecture, dependencies and security.",
	"THIRD_PARTY.md":               "The bundled Markdown parser, its license and the rendering boundary.",
}

func category(name string) string {
	switch {
	case name == StartDocument || name == "OPERATOR_GUIDE.md" || name == "docs/FIELD_REFERENCE.md":
		return "Get started"
	case name == "DEPLOYMENT.md" || strings.HasPrefix(name, "deploy/") || name == "docs/UNIX_SOCKET.md":
		return "Install and operate"
	case name == "docs/RP_INTEGRATION.md" || name == "docs/BDCMAPS_INTEGRATION.md" || name == "docs/PROTOCOL_ADAPTERS.md":
		return "Connect applications"
	case strings.HasPrefix(name, "docs/validation/") || name == "VALIDATION.md" || name == "docs/OIDC_AUDIT.md" || name == "docs/BROWSER_TESTS.md":
		return "Validation and testing"
	default:
		return "Design and reference"
	}
}

// URL names a catalog entry. It is not a filesystem URL.
func URL(name string) string { return "/admin/docs?doc=" + url.QueryEscape(name) }

func New(src fs.FS) (*Library, error) {
	l := &Library{documents: make(map[string]Document), files: make(map[string]string), search: make(map[string]string)}
	total := 0
	err := fs.WalkDir(src, ".", func(name string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		ext := strings.ToLower(path.Ext(name))
		if ext != ".md" && ext != ".log" && ext != ".txt" && ext != ".json" {
			return nil
		}
		if !fs.ValidPath(name) || strings.ContainsAny(name, "\\\x00") || d.Type()&fs.ModeSymlink != 0 {
			return fmt.Errorf("invalid documentation entry")
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if info.Size() > maxDocumentBytes || len(l.files) >= maxFiles {
			return fmt.Errorf("documentation catalog limit exceeded")
		}
		b, err := fs.ReadFile(src, name)
		if err != nil {
			return err
		}
		total += len(b)
		if total > maxLibraryBytes || !utf8.Valid(b) {
			return fmt.Errorf("invalid or oversized documentation catalog")
		}
		l.files[name] = string(b)
		return nil
	})
	if err != nil {
		return nil, err
	}
	for name, source := range l.files {
		if strings.ToLower(path.Ext(name)) != ".md" {
			continue
		}
		rendered, err := l.render(name, source)
		if err != nil {
			return nil, fmt.Errorf("render %s: %w", name, err)
		}
		e := Entry{Path: name, Title: rendered.title, Description: descriptions[name], Category: category(name), URL: URL(name)}
		if e.Title == "" {
			e.Title = path.Base(name)
		}
		if e.Description == "" {
			e.Description = name
		}
		l.entries = append(l.entries, e)
		l.search[name] = strings.ToLower(e.Title + " " + e.Path + " " + e.Description + " " + source)
		l.documents[name] = Document{Entry: e, Body: template.HTML(rendered.body), TOC: rendered.headings, Source: source}
	}
	sort.Slice(l.entries, func(i, j int) bool {
		if l.entries[i].Path == l.entries[j].Path {
			return false
		}
		if l.entries[i].Path == StartDocument {
			return true
		}
		if l.entries[j].Path == StartDocument {
			return false
		}
		return l.entries[i].Path < l.entries[j].Path
	})
	return l, nil
}

// Document returns a copy, so handlers cannot mutate the cached catalog.
func (l *Library) Document(name string) (Document, bool) {
	d, ok := l.documents[name]
	d.TOC = append([]Heading(nil), d.TOC...)
	return d, ok
}
func (l *Library) Source(name string) (string, bool) { b, ok := l.files[name]; return b, ok }
func (l *Library) Count() int                        { return len(l.entries) }
func (l *Library) Groups(query string) []Group {
	terms := strings.Fields(strings.ToLower(query))
	groups := []Group{{Name: "Get started"}, {Name: "Install and operate"}, {Name: "Connect applications"}, {Name: "Validation and testing"}, {Name: "Design and reference"}}
	for _, e := range l.entries {
		haystack := l.search[e.Path]
		match := true
		for _, term := range terms {
			if !strings.Contains(haystack, term) {
				match = false
				break
			}
		}
		if !match {
			continue
		}
		for i := range groups {
			if groups[i].Name == e.Category {
				groups[i].Entries = append(groups[i].Entries, e)
				break
			}
		}
	}
	var out []Group
	for _, g := range groups {
		if len(g.Entries) > 0 {
			out = append(out, g)
		}
	}
	return out
}
