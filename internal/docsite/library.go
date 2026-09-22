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
type Entry struct{ Path, Name, Title, Directory, URL string }
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
		if ext != ".md" {
			// Only the docs tree carries published evidence. Walking deploy
			// for Markdown must not also expose future deployment JSON/text.
			if !strings.HasPrefix(name, "docs/") || (ext != ".log" && ext != ".txt" && ext != ".json") {
				return nil
			}
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
		e := Entry{Path: name, Name: path.Base(name), Title: rendered.title, Directory: path.Dir(name), URL: URL(name)}
		if e.Title == "" {
			e.Title = path.Base(name)
		}
		l.entries = append(l.entries, e)
		l.search[name] = strings.ToLower(e.Title + " " + e.Path + " " + source)
		l.documents[name] = Document{Entry: e, Body: template.HTML(rendered.body), TOC: rendered.headings, Source: source}
	}
	// Order the exact paths; Start here is a route, not an exception in the index.
	sort.Slice(l.entries, func(i, j int) bool { return l.entries[i].Path < l.entries[j].Path })
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

// Groups lists only Markdown documents, grouped by their containing directory.
// Titles come from the Markdown; paths, membership and ordering come from the
// source tree. There is no application registry, filename metadata or pinned row.
// A new release snapshot automatically reflects added, renamed and removed files.
func (l *Library) Groups(query string) []Group {
	terms := strings.Fields(strings.ToLower(query))
	byDirectory := make(map[string][]Entry)
	for _, e := range l.entries {
		haystack := l.search[e.Path]
		match := true
		for _, term := range terms {
			if !strings.Contains(haystack, term) {
				match = false
				break
			}
		}
		if match {
			byDirectory[e.Directory] = append(byDirectory[e.Directory], e)
		}
	}
	directories := make([]string, 0, len(byDirectory))
	for dir := range byDirectory {
		directories = append(directories, dir)
	}
	sort.Strings(directories)
	out := make([]Group, 0, len(directories))
	for _, dir := range directories {
		out = append(out, Group{Name: dir, Entries: byDirectory[dir]})
	}
	return out
}
