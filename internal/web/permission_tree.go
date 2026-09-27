package web

import (
	"slices"
	"strings"

	"github.com/yellowman/authd/internal/identity"
)

// permissionNode is a presentation tree. Only nodes with Permission are grants;
// intermediate names are navigation, not implicit permissions.
type permissionNode struct {
	Label      string
	Permission *identity.Permission
	Children   []*permissionNode
	Count      int
	Open       bool
	Checked    bool
}

func permissionTree(permissions []identity.Permission, selectedID string, checkedIDs []string) []*permissionNode {
	root := &permissionNode{}
	checked := make(map[string]bool, len(checkedIDs))
	for _, id := range checkedIDs {
		checked[id] = true
	}
	for i := range permissions {
		permission := &permissions[i]
		current := root
		for _, part := range strings.Split(permission.Name, ".") {
			var next *permissionNode
			for _, child := range current.Children {
				if child.Label == part {
					next = child
					break
				}
			}
			if next == nil {
				next = &permissionNode{Label: part}
				current.Children = append(current.Children, next)
			}
			next.Count++
			if permission.ID == selectedID || checked[permission.ID] {
				next.Open = true
			}
			current = next
		}
		current.Permission = permission
		current.Checked = checked[permission.ID]
	}
	var sortNodes func([]*permissionNode)
	sortNodes = func(nodes []*permissionNode) {
		slices.SortFunc(nodes, func(a, b *permissionNode) int { return strings.Compare(a.Label, b.Label) })
		for _, node := range nodes {
			sortNodes(node.Children)
		}
	}
	sortNodes(root.Children)
	return root.Children
}
