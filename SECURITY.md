# Security policy and implementation rules

`authd` is security infrastructure. Convenience does not override protocol or credential safety.

## Non-negotiable rules

- Never log passwords, client secrets, session values, authorization codes, refresh tokens, TOTP secrets, recovery codes, or bootstrap tokens.
- Store user passwords only as Argon2id encoded hashes.
- Store high-entropy bearer values only as one-way hashes.
- Encrypt reversible secrets such as TOTP seeds and signing private keys with a deployment master key held outside PostgreSQL.
- Use exact redirect URI matching.
- Require PKCE S256 for all authorization-code clients.
- Make authorization codes single-use and short-lived.
- Rotate refresh tokens on every use and revoke the family on reuse.
- Re-evaluate current user/client permission state on refresh.
- Keep access tokens short-lived rather than building a mandatory online introspection dependency into every app.
- Treat every admin authorization check as server-side. UI hiding is not authorization.
- Use CSRF protection on all provider-operated state-changing HTML forms.
- Production issuers are HTTPS only.

## Dependency review

Before adding a dependency, document why the standard library or an existing dependency is insufficient, the package's maintenance status, and what security-critical code it replaces.

## Reporting

Until a project-specific security mailbox is established, report issues privately to the repository owner rather than filing a public issue containing exploit details.
