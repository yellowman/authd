# Implementation sequence — v0.9.0

Checked items mean implemented source with the local evidence in `VALIDATION.md`,
not production qualification. Real PostgreSQL/dependency-backed execution and an
actual bdcmaps login remain the first external gates.

## Identity delivery

- [x] Separate password-credential repository and effective role/permission reads.
- [x] First-user bootstrap token, permanent completion state, serialized consume.
- [x] Password login with credential/factor snapshot checks at session creation.
- [x] Hashed provider sessions, session-bound CSRF, idle and absolute expiry.
- [x] Zero-role authentication and live server-side admin authorization.
- [x] Password change/reset, forced change, disable and credential revocation.
- [x] User create/edit/roles; role create/edit; permission creation.
- [x] Last enabled administrator protection and recent-auth write guards.
- [x] Email verification assertion and normalized-address-change clearing.
- [x] Encrypted TOTP enrollment, confirmation, replay prevention and recovery codes.
- [x] Authenticated TOTP removal and provider-session revocation.
- [x] Audit writer/browser and account/session UI.

## OIDC provider

- [x] Encrypted persisted RSA signing keys and real JWKS.
- [x] Signing-key rotation overlap; retired private material is discarded.
- [x] Client repository and exact redirect/post-logout URI validation.
- [x] Server-side authorization continuation storage and parallel-login-safe handles.
- [x] GET/POST authorization; browser-bound continuation/consent; `none/login/consent/select_account`, completion-time `max_age`, login hints, nonce/state/issuer.
- [x] Voluntary `acr_values`, essential ACR/sub selectors, selective profile claims and client MFA floors.
- [x] ID-token `acr`/`amr` plus stable provider-session `sid` retained across refresh.
- [x] RP integration contract for `(iss, sub)` linking and application-local authority boundaries.
- [x] Permission-scope evaluation and requested+allowed groups/roles projection.
- [x] Single-use authorization codes and PKCE S256 code exchange.
- [x] `client_secret_basic`, bdcmaps-compatible `client_secret_post`, and public none.
- [x] Exact registered-origin CORS for public browser clients; no wildcard/reflection.
- [x] RS256 ID/access tokens, explicit audience/client binding, JWKS, and UserInfo.
- [x] Opaque refresh rotation, persistent scope narrowing, current-grant evaluation.
- [x] Refresh-family replay detection, revocation, and RP-initiated logout.
- [x] OIDC client create/edit/delete/secret rotation in the admin UI.
- [x] Protocol-level bdcmaps-shaped in-memory end-to-end regression.
- [ ] Run `docs/BDCMAPS_INTEGRATION.md` against the actual private bdcmaps app.
- [ ] Run an independent OIDC/OAuth interoperability/conformance suite.

## v0.9.0 audit corrections

- [x] Single transaction for code/refresh validation, signing, credential updates and audit.
- [x] Shared grant gate plus per-code/family row locks; exclusive authority changes.
- [x] Code replay revokes descendants; wrong-client probes cannot revoke another grant.
- [x] Revocation and token infrastructure failures remain 503 rather than false success/invalid credentials.
- [x] Strict JWT/JSON parsing, distinct ID/access token types, `at_hash`, one UserInfo verification.
- [x] Scoped claim selection/value constraints and actual consent for offline access.
- [x] Live-session code redemption; atomic login replacement and explicit logout grant revocation.
- [x] Bounded crypto caches, origin lookup without catalog truncation, throttled session touches, batched cleanup and reverse indexes.
- [x] Exact-prefix migration validation and reserved-scope constraints.
- [ ] Independent full OIDC conformance runner, real bdcmaps callback, SQL lock/query plan/load qualification.

## Qualification

- [x] Real-PostgreSQL integration test source and non-skipping gate definition.
- [x] OIDC SQL lifecycle integration source added to that gate.
- [ ] Run the NEW v0.9.0 migration/atomicity/concurrency integration suite against PostgreSQL with the actual pgx driver (earlier revision was externally tested).
- [ ] Rerun the v0.9.0 full build/tests/vet with the pinned modules on OpenBSD/amd64 or Linux (earlier external lock state is retained).
- [ ] Full browser automation against the actual daemon and database (live setup/login forms were exercised manually).
- [ ] Full race-detector suite on a supported Go platform (OpenBSD/amd64 does not support `-race`).

## Administration completion and operations

- [x] User/role/permission deletion with reference and last-admin safeguards.
- [x] Permission editing.
- [ ] Role/permission/user pagination.
- [x] Per-row optimistic concurrency checks for simultaneous admin editors.
- [x] Signing-key inventory and rotation UI.
- [ ] Reviewed signing-key rotation/retention/deletion schedule.
- [x] Administrative MFA reset and recent-MFA recovery-code regeneration.
- [ ] Safe break-glass process.
- [x] Self-service profile editing with email-verification clearing.
- [ ] TOTP QR display.
- [x] Expired authorization/session/token/enrollment cleanup and bounded audit retention.
- [x] Explicit trusted-proxy IP parsing and deployment rate-limit guidance.
- [x] Operator-visible internal error classification plus request correlation without leaking raw errors.
- [x] Explicit migrate command plus dedicated migration/runtime PostgreSQL role boundary.
- [x] Greenfield PostgreSQL database/LOGIN-role bootstrap SQL and complete `DEPLOYMENT.md`.
- [x] Native OpenBSD `_authd` install layout and rc.d env-file propagation.
- [x] Native Linux `_authd` install layout and WaveControl-style systemd EnvironmentFile service.
- [x] Repeatable native install/update path that preserves env, pgpass, master key, and database state while keeping migration explicit.
- [ ] Fresh native OpenBSD install witness covering runtime-role separation, rc.d enable/start/restart/stop, and env/pgpass permissions.
- [ ] Fresh Linux install witness covering runtime-role separation, systemd enable/start/restart/stop, sandboxing, and env/pgpass permissions.
- [ ] Backup/restore and master-key rotation.
- [ ] Dependency/vulnerability checks.

## Later, only from concrete need

WebAuthn; RADIUS PAP and explicit NAS/method/attribute registration; TACACS+ peers
and command mappings; separately enrolled legacy network credentials only when a
device actually requires them; separate resource-server audiences; multi-instance
deployment. No weakened primary password store, generic plugin framework, or
second identity database.
