package protocol

// Subject is the protocol-neutral identity view that future frontends such as
// OIDC, RADIUS, or TACACS+ consume. Protocol adapters do not own users or roles.
type Subject struct {
	ID          string
	Username    string
	DisplayName string
	Email       string
	Roles       []string
	Permissions []string
	Enabled     bool
}
