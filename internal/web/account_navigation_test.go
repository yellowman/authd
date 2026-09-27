package web

import (
	"bytes"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAccountNavigationAndFactorStatus(t *testing.T) {
	for _, admin := range []bool{false, true} {
		for _, enabled := range []bool{false, true} {
			s, h, m := fixture(t, admin)
			m.session.User.MFAEnabled = enabled
			w := httptest.NewRecorder()
			h.ServeHTTP(w, request(s, m, "GET", "/account", nil, true))
			body := w.Body.String()
			if w.Code != 200 {
				t.Fatal(w.Code)
			}
			if strings.Contains(body, `aria-label="Administration"`) != admin || strings.Contains(body, `href="/admin/?view=users"`) != admin {
				t.Fatal("account navigation permission mismatch")
			}
			if strings.Contains(body, "Administration · Start here") {
				t.Fatal("old admin link remains")
			}
			if admin && !strings.Contains(body, `href="/account" aria-current="page"`) {
				t.Fatal("account not marked current")
			}
			if !strings.Contains(body, "Two-step verification") {
				t.Fatal("missing factor section")
			}
			if enabled {
				if !strings.Contains(body, "Your sign-ins require an authenticator or recovery code.") || strings.Contains(body, "Not enabled · Optional") {
					t.Fatal("enabled status unclear")
				}
			} else if !strings.Contains(body, "Not enabled · Optional") || !strings.Contains(body, "Set up authenticator") || strings.Contains(body, "Completing enrollment") {
				t.Fatal("optional status unclear")
			}
		}
	}
}

func TestUsersAndGroupsHaveDistinctOutlineIcons(t *testing.T) {
	s, _, _ := fixture(t, true)
	var users, groups bytes.Buffer
	if err := s.templates.ExecuteTemplate(&users, "icon", "users"); err != nil {
		t.Fatal(err)
	}
	if err := s.templates.ExecuteTemplate(&groups, "icon", "groups"); err != nil {
		t.Fatal(err)
	}
	if users.String() == groups.String() {
		t.Fatal("identical user/group icon geometry")
	}
	for _, n := range adminNavigation("account") {
		if n.Label == "Users" && n.Icon != "users" || n.Label == "Groups" && n.Icon != "groups" {
			t.Fatal("navigation uses wrong icon")
		}
	}
}

func TestLoginNamesApplicationMFARequirement(t *testing.T) {
	s, _, _ := fixture(t, false)
	d := s.data("Sign in")
	d.ClientName = "Example App"
	d.ClientRequiresMFA = true
	w := httptest.NewRecorder()
	s.render(w, 200, "login.html", d)
	if !strings.Contains(w.Body.String(), "Example App requires two-step verification.") {
		t.Fatal("required state missing")
	}
	d.ClientRequiresMFA = false
	w = httptest.NewRecorder()
	s.render(w, 200, "login.html", d)
	if strings.Contains(w.Body.String(), "requires two-step verification") {
		t.Fatal("optional app portrayed as requiring MFA")
	}
}
