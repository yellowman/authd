package identity

import "sort"

// EffectivePermissions computes authd's deliberately boring authorization model:
// the union of permissions belonging to all assigned roles. There are no denies,
// inheritance rules, priorities, or nested roles.
func EffectivePermissions(assignedRoles []string, rolePermissions map[string][]string) []string {
	set := make(map[string]struct{})
	for _, role := range assignedRoles {
		for _, permission := range rolePermissions[role] {
			if permission != "" {
				set[permission] = struct{}{}
			}
		}
	}
	out := make([]string, 0, len(set))
	for permission := range set {
		out = append(out, permission)
	}
	sort.Strings(out)
	return out
}
