package protocol

// Subject is the protocol-neutral identity view that future frontends such as
// OIDC, RADIUS, or TACACS+ consume. Protocol adapters do not own users or roles.
type Subject struct {
	ID            string
	Username      string
	DisplayName   string
	Email         string
	EmailVerified bool
	Roles         []string
	Permissions   []string
	AMR           []string
	Enabled       bool
}
