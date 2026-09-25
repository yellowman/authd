package web

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/yellowman/authd/internal/docsite"
)

func (s *Server) documents(w http.ResponseWriter, r *http.Request) {
	sess, raw, ok := s.user(w, r, true, false)
	if !ok {
		return
	}
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || len(r.URL.RawQuery) > 2048 || len(q["doc"]) > 1 || len(q["q"]) > 1 || len(q) > 2 || len(q.Get("q")) > 200 {
		http.Error(w, "Invalid documentation request", http.StatusBadRequest)
		return
	}
	for key := range q {
		if key != "q" && key != "doc" {
			http.Error(w, "Invalid documentation request", http.StatusBadRequest)
			return
		}
	}
	d := s.data("Documentation")
	d.View, d.Session, d.CSRF = "docs", sess, s.auth.CSRF(raw, "session")
	d.DocumentCount = s.docs.Count()
	name := q.Get("doc")
	if name != "" {
		doc, found := s.docs.Document(name)
		if !found {
			http.NotFound(w, r)
			return
		}
		d.Document = &doc
		d.Title = doc.Title
	} else {
		d.DocumentQuery = strings.TrimSpace(q.Get("q"))
		d.DocumentGroups = s.docs.Groups(d.DocumentQuery)
	}
	s.render(w, http.StatusOK, "admin.html", d)
}

func (s *Server) documentSource(w http.ResponseWriter, r *http.Request) {
	if _, _, ok := s.user(w, r, true, false); !ok {
		return
	}
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || len(r.URL.RawQuery) > 2048 || len(q) != 1 || len(q["doc"]) != 1 {
		http.NotFound(w, r)
		return
	}
	source, ok := s.docs.Source(q.Get("doc"))
	if !ok {
		http.NotFound(w, r)
		return
	}
	// Never content-sniff Markdown/HTML examples into an executable document.
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; sandbox")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(source))
}

type navigationEntry struct {
	Label, Icon, Href string
	Current           bool
}

func adminNavigation(view string) []navigationEntry {
	entries := []navigationEntry{
		{Label: "Start here", Icon: "guide", Href: "/admin/?view=guide", Current: view == "guide"},
		{Label: "Documentation", Icon: "docs", Href: "/admin/docs", Current: view == "docs"},
		{Label: "Users", Icon: "users", Href: "/admin/?view=users", Current: view == "users"},
		{Label: "Roles", Icon: "roles", Href: "/admin/?view=roles", Current: view == "roles"},
		{Label: "Groups", Icon: "users", Href: "/admin/?view=groups", Current: view == "groups"},
		{Label: "Permissions", Icon: "permissions", Href: "/admin/?view=permissions", Current: view == "permissions"},
		{Label: "Clients", Icon: "clients", Href: "/admin/?view=clients", Current: view == "clients"},
		{Label: "Sessions", Icon: "sessions", Href: "/admin/?view=sessions", Current: view == "sessions"},
		{Label: "Signing keys", Icon: "keys", Href: "/admin/?view=keys", Current: view == "keys"},
		{Label: "Audit", Icon: "audit", Href: "/admin/?view=audit", Current: view == "audit"},
	}
	return entries
}

// Reuse the original Markdown for the administration landing page.
func (s *Server) startDocument(d *pageData) {
	doc, _ := s.docs.Document(docsite.StartDocument)
	d.Document, d.DocumentCount = &doc, s.docs.Count()
}
