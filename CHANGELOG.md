# Changelog

## v0.9.1 — 2026-09-22

Documentation/qualification update only; no runtime, dependency, migration,
privilege-statement, Makefile or native-service changes. Standardized the native
PostgreSQL administrator procedure on `psql -Upostgres` with explicit `-dpostgres`
for cluster bootstrap and `-dauthd` with `authd_owner` for runtime grants. Replaced
the interactive password-meta-command instructions with explicit SQL password
assignment from a private temporary file, including credential/logging cautions.
Updated SQL comments/operator guidance and fixed README's stale `make deps` text.

Recorded the user-supplied v0.9.0 external OpenBSD/PostgreSQL/live-OIDC PASS report
separately from authoring-environment tests. Raw logs were not supplied. The actual
BDC callback, HTTPS/proxying, native installation, live MFA, Linux race/systemd
and other unreported qualification gates remain open. No new migration, credential
rotation or daemon restart is required solely for this documentation update.

## v0.9.0 — 2026-09-22

Substantive OIDC/security/performance audit of v0.8.4. Rebuilt code and refresh
issuance as single PostgreSQL transactions with shared grant/exclusive mutation
coordination; rollback on precommit signing failure; code-replay family revocation;
live client-proof/session checks; browser-bound continuations and consent; corrected
voluntary `acr_values` semantics plus essential/normal `claims`; access/ID token
separation, strict JOSE JSON, `at_hash`, one UserInfo verification; real failure
classes for token/revocation/logout; bounded key caches/cleanup and session writes;
registered-origin query and missing reverse indexes. Added migration 005 and
regressions, integration concurrency witnesses, fuzz target and before/after CPU
benchmarks. Read docs/OIDC_AUDIT.md, VALIDATION.md and DEPLOYMENT.md before upgrade.
Earlier ACR and offline-consent descriptions below are historical, not current policy.


## v0.8.4 — repeatable native install/update baseline

Corrected the v0.8.3 over-specialization around greenfield deployment. `make install-openbsd` and `make install-linux` are now safe repeatable install/update targets: they create missing env/master-key state on first install, preserve existing active env/master-key/pgpass contents on later runs, and refresh the binary, examples, documentation, PostgreSQL helper SQL, and service-manager definition. Existing runtime file ownership/modes are reasserted. PostgreSQL data is never an installer-owned artifact.

Schema migration remains deliberately explicit and separate from installation: upgrades run the new release binary's `authd migrate` using `authd_owner`, optionally reapply the idempotent runtime grants, then install/restart under `authd_runtime`. The deployment guide now documents that normal upgrade sequence and warns that executable rollback after a successful schema migration is not a substitute for a reviewed database rollback plan.

## v0.8.3 — greenfield native services on OpenBSD and Linux

Added a WaveControl-style Linux systemd unit using the same `/etc/authd/authd.env`, `_authd`, master-key, and `PGPASSFILE` contract as OpenBSD. Added `make install-linux`, common native service-control targets, `make verify-linux`, environment-template parity checks, and systemd unit validation.

Simplified native installation to match the project's greenfield status. `make install-openbsd` and `make install-linux` now create first-install env/master-key state and refuse an existing active installation rather than carrying preservation/merge behavior before an installed-base upgrade contract exists. Service start never generates key material. Staged `DESTDIR` installs still create only package assets/examples.

`DEPLOYMENT.md` now documents one PostgreSQL bootstrap path plus complete OpenBSD rc.d and Linux systemd service setup, shared file permissions, bootstrap, service control, and the current manual update boundary.

## v0.8.2 — native deployment bootstrap and OpenBSD rc.d

Added a complete `DEPLOYMENT.md` covering fresh PostgreSQL/OpenBSD installation: cluster initialization, dedicated `authd_owner` and `authd_runtime` LOGIN roles, database creation, interactive password assignment, owner-only migrations against the authd database, DML-only runtime grants, persistent master-key/runtime pgpass layout, bootstrap, HTTPS proxy boundary, upgrades, and backup minimums.

Added `deploy/postgresql/create-database.sql`, hardened `runtime-grants.sql` to revoke schema CREATE from PUBLIC/runtime, and changed `authd migrate` so it requires only `DATABASE_URL`; migration credentials no longer need issuer/master-key configuration and are explicitly kept out of the daemon environment.

Added a native OpenBSD `_authd` service account/install path and WaveControl-style `rc.d` script. `/etc/authd/authd.env` is sourced with `set -a` in both validation and daemon execution shells so environment variables survive rc.d privilege drop. `make install-openbsd` preserves an existing env/master key, generates the master key only on first install, installs pgpass/env templates, and provides rcctl-oriented enable/start/restart/status/stop targets.

## v0.8.1 — real PostgreSQL/OpenBSD qualification fixes

Incorporated defects found by an external OpenBSD/amd64 Go 1.27 and disposable PostgreSQL qualification run. Refresh-token creation/rotation now casts both `LEAST` timestamp parameters explicitly to `timestamptz`, avoiding PostgreSQL's indeterminate-parameter-type error with database/sql/pgx. The PostgreSQL integration helper no longer hard-codes an expected migration count; `CheckSchema` is already the authoritative exact embedded-manifest check, so future migrations cannot stale a duplicate count assertion.

Committed the real dependency lock state (`go.sum`) and raised the module minimum to Go 1.26 because the pinned `golang.org/x/crypto v0.57.0` itself requires Go 1.26. Added `make verify-openbsd`, which runs formatting, unit tests, vet, build, and the real PostgreSQL integration suite without the unsupported race detector; release qualification still requires the race suite on a supported Go platform.

External qualification exercised the real authd executable, bootstrap/setup/login forms, admin OIDC client registration, discovery, Authorization Code + PKCE, `client_secret_post`, ID-token claims, UserInfo, and refresh rotation. Actual bdcmaps callback/deployment, production HTTPS/proxying, live MFA, runtime-role separation, backup/restore, rc.d boot, race testing, master-key rotation, and external OIDC conformance remain open.

## v0.8 — RP integration and authentication context

Added a binding relying-party integration contract: durable identity is `(iss, sub)`; mutable profile/role claims are not identity keys; matching email never silently links an existing RP account; and authd authentication never creates application-local tenant, organization, PBX, project, case, boundary, workspace, room, or resource membership. Documented identity-only, hybrid, and authd-authorized RP modes, local-identity coexistence, and the Evident pattern where a product gateway may trust customer OIDC/SAML providers directly rather than forcing federation through authd.

Implemented OIDC authentication context with `acr_values`, `urn:authd:acr:pwd`, `urn:authd:acr:mfa`, client-level MFA minimums, and the finalized `unmet_authentication_requirements` authorization error. Discovery now advertises supported ACRs plus `acr` and `sid` claims. ID Tokens emit the authentication context actually satisfied and the UUID `sid` of the provider login session. Authorization codes and refresh families retain that session ID so refreshed ID Tokens preserve session correlation. RP-initiated logout uses `sid` when present to prevent a same-subject token from ending a different provider session.

Added protocol/store regression coverage for ACR discovery, MFA step-up, unsupported ACRs, stable `sid` across refresh, cross-`sid` logout refusal, client MFA policy precedence, and migration 004. Real PostgreSQL execution and external RP interoperability remain qualification gates.

## v0.7 — deployment hardening

Separated schema ownership from normal runtime: `authd migrate` is now the explicit DDL path, while daemon and bootstrap startup only verify the exact embedded migration manifest and fail closed on absent, stale, ahead, or altered history. Added a PostgreSQL runtime-grant script/default-privilege recipe so production can use a DML-only authd role without schema ownership or CREATE rights.

Added safe internal failure observability. HTTP 5xx responses carry their request reference; structured logs emit only a bounded error class and request ID rather than raw driver/credential errors. Added regression coverage for secret-bearing internal errors, dependency-unavailable/deadline classification, migration manifest ordering, and real-PostgreSQL source coverage for migration-history drift.

The v0.6 lifecycle controls remain unchanged. Full Go 1.26+/real-pgx/PostgreSQL execution and actual bdcmaps interoperability remain external qualification gates.

## v0.6 — lifecycle and operations

Completed the first destructive/maintenance control-plane slice: soft user deletion with security-state teardown and final-admin protection; non-built-in role deletion; permission editing and reference-safe deletion; administrative MFA reset; recent-MFA-only recovery-code regeneration; destructive OIDC-client deletion; signing-key inventory/rotation in the admin UI; and periodic expiry/audit cleanup.

Added PostgreSQL integration coverage for those lifecycle transitions and cleanup semantics. Added row-version optimistic concurrency for user, role, permission, and OIDC-client edit forms; stale saves fail with a conflict instead of overwriting a newer administrator change. Client deletion now atomically removes its durable authorization continuations, codes, redirects/scopes, and refresh families through the schema ownership boundary while existing short-lived JWTs expire normally. Signing-key administration redacts encrypted private material, and automatic cleanup never deletes signing keys. Added self-service display-name/email editing with fresh-session enforcement and automatic email-verification clearing. Added explicit trusted-proxy CIDRs with spoof-resistant right-to-left `X-Forwarded-For` resolution for audit and login-rate-limit source addresses.

The full dependency-backed Go 1.26+/PostgreSQL gate and actual bdcmaps interoperability remain external qualification requirements; see `VALIDATION.md`.

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
