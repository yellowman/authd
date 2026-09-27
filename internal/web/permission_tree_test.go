package web

import (
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/yellowman/authd/internal/identity"
)

func permissionTreeFixture() []identity.Permission {
	return []identity.Permission{
		{ID: "write", Name: "inventory.assets.write"},
		{ID: "admin", Name: "system.admin"},
		{ID: "run", Name: "inventory.projects.jobs.run"},
		{ID: "standalone", Name: "standalone"},
		{ID: "relay", Name: "relay.session.read"},
		{ID: "read", Name: "inventory.assets.read", Description: "Read <assets>"},
		{ID: "assets", Name: "inventory.assets"},
	}
}

func TestPermissionTreeHierarchy(t *testing.T) {
	nodes := permissionTree(permissionTreeFixture(), "run", []string{"read"})
	labels := []string{}
	for _, node := range nodes {
		labels = append(labels, node.Label)
	}
	if !slices.Equal(labels, []string{"inventory", "relay", "standalone", "system"}) {
		t.Fatal("root ordering", labels)
	}
	inventory := nodes[0]
	if inventory.Count != 4 || !inventory.Open || inventory.Permission != nil {
		t.Fatal("application branch is not a grant", inventory)
	}
	assets := inventory.Children[0]
	if assets.Label != "assets" || assets.Count != 3 || !assets.Open || assets.Permission.ID != "assets" || assets.Checked {
		t.Fatal("prefix permission lost or implicitly selected", assets)
	}
	if assets.Children[0].Label != "read" || !assets.Children[0].Checked || assets.Children[1].Label != "write" || assets.Children[1].Checked {
		t.Fatal("leaf ordering or selection changed")
	}
	projects := inventory.Children[1]
	if projects.Label != "projects" || !projects.Open || !projects.Children[0].Open || projects.Children[0].Children[0].Permission.ID != "run" {
		t.Fatal("deep selected path is not open")
	}
	if nodes[1].Open || nodes[2].Open || len(nodes[2].Children) != 0 || nodes[2].Permission.ID != "standalone" {
		t.Fatal("unrelated or standalone permission changed")
	}
	counts := map[string]int{}
	var walk func([]*permissionNode)
	walk = func(nodes []*permissionNode) {
		for _, node := range nodes {
			if node.Permission != nil {
				counts[node.Permission.ID]++
			}
			walk(node.Children)
		}
	}
	walk(nodes)
	for _, permission := range permissionTreeFixture() {
		if counts[permission.ID] != 1 {
			t.Fatal("permission lost or duplicated", permission.ID, counts)
		}
	}
	if len(permissionTree(nil, "", nil)) != 0 {
		t.Fatal("empty catalog gained a branch")
	}
}

func TestPermissionCatalogDisclosureAndSelection(t *testing.T) {
	s, h, m := fixture(t, true)
	m.snapshot.Permissions = permissionTreeFixture()
	for _, tc := range []struct {
		path string
		open int
	}{
		{"/admin/?view=permissions", 0},
		{"/admin/?permission=run", 3},
	} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, request(s, m, "GET", tc.path, nil, true))
		body := w.Body.String()
		if w.Code != 200 {
			t.Fatal(tc.path, w.Code, body)
		}
		if strings.Count(body, `class="permission-branch" open`) != tc.open {
			t.Fatal("wrong selected ancestor expansion", tc.path)
		}
		for _, want := range []string{"<summary><code>inventory</code>", "<summary><code>assets</code>", "<summary><code>projects</code>", "<summary><code>jobs</code>", "Read &lt;assets&gt;", `id="permission-editor"`} {
			if !strings.Contains(body, want) {
				t.Errorf("%s missing %q", tc.path, want)
			}
		}
		for _, permission := range m.snapshot.Permissions {
			if strings.Count(body, `/admin/?permission=`+permission.ID+`#permission-editor`) != 1 {
				t.Fatal("exact permission edit action lost or duplicated", permission.ID)
			}
		}
	}
}

func TestPermissionSelectorsKeepExactGrants(t *testing.T) {
	for _, view := range []string{"roles", "clients"} {
		t.Run(view, func(t *testing.T) {
			s, h, m := fixture(t, true)
			m.snapshot.Permissions = permissionTreeFixture()
			m.snapshot.Roles[0].PermissionIDs = []string{"read"}
			path := "/admin/?role=" + userID
			if view == "clients" {
				provider := helpProvider(t, s)
				provider.client.PermissionIDs = []string{"read"}
				var err error
				h, err = s.Handler()
				if err != nil {
					t.Fatal(err)
				}
				path = "/admin/?client=" + userID
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, request(s, m, "GET", path, nil, true))
			body := w.Body.String()
			if w.Code != 200 {
				t.Fatal(w.Code, body)
			}
			if strings.Count(body, `class="permission-branch" open`) != 2 || strings.Count(body, `name="permissions" value="read" checked`) != 1 {
				t.Fatal("saved grant not checked or its ancestors not open")
			}
			for _, permission := range m.snapshot.Permissions {
				want := 1
				if view == "clients" && permission.Name == "system.admin" {
					want = 0
				}
				if strings.Count(body, `name="permissions" value="`+permission.ID+`"`) != want {
					t.Fatal("checkbox identity or client admin exclusion changed", permission.Name)
				}
			}
			if strings.Contains(body, `value="write" checked`) || strings.Contains(body, `value="assets" checked`) {
				t.Fatal("hierarchy implicitly granted an ancestor or sibling")
			}
		})
	}
}
