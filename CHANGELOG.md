# Changelog

## v0.5 — OIDC provider

Implemented Authorization Code + mandatory PKCE S256, durable authorization
continuations, exact redirect matching, prompt/max-age/login-hint handling,
one-use codes, encrypted persisted RSA signing keys, RS256 ID/access tokens,
JWKS, UserInfo, rotating opaque refresh tokens, refresh replay-family revocation,
RFC 7009-style revocation, and RP-initiated logout.

Added both `client_secret_basic` and current-bdcmaps-compatible
`client_secret_post`, plus public-client `none` and registered-origin-only CORS for
public browser clients. Added OIDC client administration
for redirect/logout URIs, allowed identity/application scopes, MFA and refresh
policy, per-client access-token TTL, and one-time secret generation/rotation.

Added migration 003 for durable authorization requests and refresh authentication
context. Added bdcmaps-shaped end-to-end protocol tests, refresh narrowing/replay
regressions, PKCE non-consumption checks, JWT/input bounds, logout ambiguity checks,
signing-key rotation overlap, OIDC real-PostgreSQL integration test source, and
token audit events. Client scope assignment now rejects the provider-only
`system.admin` permission server-side. Retired signing keys keep public JWKS data
but discard encrypted private-key ciphertext. Signing-key lifecycle operations
are audited. RP logout no longer permits a bare/cross-subject request to terminate
the current provider session, while signed expired ID-token hints remain usable
for current/recent-session logout.

This is not a production signoff: real dependency/PostgreSQL execution and actual
bdcmaps interoperability remain external qualification gates. See `VALIDATION.md`.

## v0.4 — local identity and administration

Implemented explicit one-time bootstrap, PostgreSQL identity repository, local
password/MFA login, sessions/CSRF, password lifecycle, TOTP enrollment/recovery,
user/role/permission management, session inventory/revocation, and audit browsing.
Added transactional authority/snapshot rechecks, final-admin protection, bounded
KDF input/concurrency, strict configuration, and responsive real forms.

Added additive migration 002; no rewrite of migration 001. Added unit/race/HTTP
regressions and an explicit real-PostgreSQL integration suite. Dependency-free
checks execute actual production components without substitute modules.

## v0.3 — baseline

Separated password credentials from identities and refined the protocol-neutral
AAA credential/peer model.
