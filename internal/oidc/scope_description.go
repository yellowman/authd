package oidc

// ScopeDescription explains a wire scope without changing validation or grants.
// Unknown application scopes stay visibly application-defined; no privileges
// are inferred from a name or description.
func ScopeDescription(scope string) string {
	switch scope {
	case "openid":
		return "Sign you in and provide a stable identity identifier."
	case "profile":
		return "Share your display name and username."
	case "email":
		return "Share your email address and its verification state."
	case "groups", "roles":
		return "Share your assigned authd role names."
	case "offline_access":
		return "Allow renewed access after you leave, until expiry or revocation."
	default:
		return "Application-defined permission; the application decides which operations it authorizes."
	}
}
