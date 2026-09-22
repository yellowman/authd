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


## v0.9.1 operational status (unchanged v0.9.0 runtime)

A user-supplied v0.9.0 report states that the real OpenBSD build/tests/PostgreSQL
gate, greenfield owner/runtime setup and a live OIDC provider flow passed. Raw logs
were not supplied; this is not an independent authoring-environment rerun or a
production approval. Actual RP interoperability, production HTTPS/proxy behavior,
live MFA, service-manager operation, Linux race tests and the other gates in
VALIDATION.md remain. Local in-memory tests alone do not establish SQL behavior or
protocol conformance. No module replacement counts as release evidence.

Keep master-key files owner-only. Use loopback-only development mode; production
uses an HTTPS reverse proxy and authenticated PostgreSQL TLS. Forwarded IP headers
are used only from configured trusted proxy CIDRs through the shared resolver. Run one
active instance: limits and the demonstrated architecture do not claim HA support.

Only an explicit local bootstrap command may display the initial setup token.
Never put that token in a URL, system service logs, or persistent environment
configuration. Setup cannot reopen when administrators are removed. Recovery and
break-glass behavior still need a dedicated reviewed workflow.

## Protocol and transaction safeguards

Browser continuations are bound to the initiating browser; consent is also bound
to the authenticated provider session. Request Objects and other unsupported
protocol modes fail explicitly, rather than being mistaken for internal handles.
`acr_values` is voluntary; mandatory MFA comes from client policy or an essential
ACR selector. ID-token/access-token purposes remain distinct, and normal identity
claim selectors cannot synthesize authority or application membership.

Code/refresh redemption validates live authority and signs before changing
credential state, all under one grant transaction. Successful response delivery
requires successful commit; precommit failure rolls back consumption. Lost or
ambiguous responses remain a distributed-system uncertainty, not permission to
accept replays. RPs must serialize refreshes. Failure to contact storage is not
invalid credentials or a successful revoke/logout.

See docs/OIDC_AUDIT.md for the fixes and migration 005. The external report now
states that the v0.9.0 real database gate passed. Do not extend that report to
untested production, load, failover, restored-database or conformance scenarios.

## Unix HTTP transport (v0.9.2)

Unix support is not a reason to relax application authentication or public HTTPS.
Only the daemon may mutate the socket parent; final `0600`/`0660` permissions are
set before publication. Use a dedicated proxy group, not the private `_authd`
group. A lifetime lock prevents competing authd listeners from unlinking one
another. Foreign/non-socket/symlink paths and unprovably stale endpoints are
refused. The socket is removed on graceful close only if it is still the same
inode. Do not remove the `.lock` file while a listener may exist.

`AUTHD_TRUST_UNIX_PROXY` is an explicit delegation of client-IP attribution to
processes permitted to connect. It is off by default and does not trust TCP.
It never grants user authentication or bypasses CSRF. Empty/malformed IP evidence
remains unknown in rate limits and audit. There is no peer-UID authentication.

See `docs/UNIX_SOCKET.md` for directory/chroot/service setup. New Linux listener,
crash/concurrency and TLS-to-Unix handler tests are separate evidence from the
reported v0.9.0 PostgreSQL pass. Full v0.9.2 build/native OpenBSD/actual nginx,
service-manager operation and production RP testing still require qualification.
