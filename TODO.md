# Implementation sequence — v0.5

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
- [x] `prompt=none/login`, `max_age`, `login_hint`, nonce, state, and `iss` response.
- [x] Permission-scope evaluation and requested+allowed groups/roles projection.
- [x] Single-use authorization codes and PKCE S256 code exchange.
- [x] `client_secret_basic`, bdcmaps-compatible `client_secret_post`, and public none.
- [x] Exact registered-origin CORS for public browser clients; no wildcard/reflection.
- [x] RS256 ID/access tokens, explicit audience/client binding, JWKS, and UserInfo.
- [x] Opaque refresh rotation, persistent scope narrowing, current-grant evaluation.
- [x] Refresh-family replay detection, revocation, and RP-initiated logout.
- [x] OIDC client create/edit/secret rotation in the admin UI.
- [x] Protocol-level bdcmaps-shaped in-memory end-to-end regression.
- [ ] Run `docs/BDCMAPS_INTEGRATION.md` against the actual private bdcmaps app.
- [ ] Run an independent OIDC/OAuth interoperability/conformance suite.

## Qualification

- [x] Real-PostgreSQL integration test source and non-skipping gate definition.
- [x] OIDC SQL lifecycle integration source added to that gate.
- [ ] Run the integration suite against PostgreSQL with the actual pgx driver.
- [ ] Resolve real pinned modules, review/commit `go.sum`, run full tests/build/vet.
- [ ] End-to-end browser exercise against the actual daemon and database.

## Administration completion and operations

- [ ] User/role/permission deletion with reference and last-admin safeguards.
- [ ] Permission editing and role/permission/user pagination.
- [ ] Per-row optimistic concurrency checks for simultaneous admin editors.
- [ ] Signing-key rotation UI and reviewed rotation/retention schedule.
- [ ] Administrative MFA reset; recovery-code regeneration; safe break-glass process.
- [ ] QR display; self-service profile editing.
- [ ] Expired authorization/session/token/enrollment cleanup and bounded audit retention.
- [ ] Explicit trusted-proxy IP parsing and deployment rate-limit guidance.
- [ ] Operator-visible internal error classification without leaking secrets.
- [ ] Backup/restore, master-key rotation, dedicated migration/runtime DB roles.
- [ ] Dependency/vulnerability checks.

## Later, only from concrete need

WebAuthn; RADIUS PAP and explicit NAS/method/attribute registration; TACACS+ peers
and command mappings; separately enrolled legacy network credentials only when a
device actually requires them; separate resource-server audiences; multi-instance
deployment. No weakened primary password store, generic plugin framework, or
second identity database.
