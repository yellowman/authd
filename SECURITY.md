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


## v0.5 operational status

OIDC issuance is implemented in source, but this is not yet a production-qualified
identity service. Do not expose it to production traffic before completing the real
dependency/PostgreSQL gates and an independent interoperability review described in
VALIDATION.md. Local OIDC tests exercise real RSA/JWT/JWK/PKCE code with an in-memory
store; they do not prove PostgreSQL behavior or protocol conformance. No module
replacement counts as release evidence.

Keep master-key files owner-only. Use loopback-only development mode; production
uses an HTTPS reverse proxy and authenticated PostgreSQL TLS. Forwarded IP headers
are ignored until an explicit trusted-proxy implementation is reviewed. Run one
active instance: limits and the demonstrated architecture do not claim HA support.

Only an explicit local bootstrap command may display the initial setup token.
Never put that token in a URL, system service logs, or persistent environment
configuration. Setup cannot reopen when administrators are removed. Recovery and
break-glass behavior still need a dedicated reviewed workflow.
