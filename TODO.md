# Implementation sequence — v0.4

Checked items mean implemented source with the local coverage in `VALIDATION.md`,
not production qualification. Real PostgreSQL and dependency-backed validation
remain the first gate before expanding protocol behavior.

## Identity delivery

- [x] Separate password-credential repository and effective role/permission reads.
- [x] First-user bootstrap token, permanent completion state, serialized consume.
- [x] Password login with credential/factor snapshot checks at session creation.
- [x] Hashed provider sessions, session-bound CSRF, idle and absolute expiry.
- [x] Zero-role account authentication and live server-side admin authorization.
- [x] Password change/reset, forced change, disable and credential revocation.
- [x] User create/edit/roles; role create/edit; permission creation.
- [x] Last enabled administrator protection and recent-auth write guards.
- [x] Email verification assertion and normalized-address-change clearing.
- [x] Encrypted TOTP enrollment bound to a session; confirmation; MFA login.
- [x] One-use OTP counters and recovery-code consumption in the session transaction.
- [x] Authenticated TOTP removal and provider-session revocation.
- [x] Audit writer/browser and account/session UI.
- [x] Real-PostgreSQL integration test suite and non-skipping gate definition.
- [ ] Run the integration suite against PostgreSQL with the actual pgx driver.
- [ ] Resolve real pinned modules, review/commit go.sum, run full tests/build/vet.
- [ ] End-to-end browser exercise against the actual daemon and database.

## OIDC, next

- [ ] Persist encrypted RSA signing keys; publish real JWKS and rotation overlap.
- [ ] Client repository and exact redirect-URI validation.
- [ ] Authorization transaction storage and browser login continuation.
- [ ] prompt=none/login, max_age, login_hint, nonce, state, and issuer response.
- [ ] Permission-scope evaluation and requested+allowed groups/roles projection.
- [ ] Single-use authorization codes; PKCE S256 code exchange.
- [ ] client_secret_basic, client_secret_post, public none authentication.
- [ ] RS256 ID/access tokens; explicit token types/audiences and UserInfo.
- [ ] Opaque refresh rotation, family replay detection, current-grant evaluation.
- [ ] Revocation and RP-initiated logout; disclose app-session limits.
- [ ] Run docs/BDCMAPS_INTEGRATION.md against the actual relying party.
- [ ] Remove preview-only discovery claims when real protocol coverage is ready.

## Administration completion and operations

- [ ] User/role/permission deletion with reference and last-admin safeguards.
- [ ] Permission editing, client CRUD and one-time client-secret display.
- [ ] Role/permission/user pagination without truncating assignment controls.
- [ ] Per-row optimistic concurrency checks for simultaneous admin editors.
- [ ] Administrative MFA reset; recovery-code regeneration; safe break-glass process.
- [ ] QR display; self-service profile editing.
- [ ] Expired sessions/tokens/enrollments and bounded audit-retention cleanup.
- [ ] Explicit trusted-proxy IP parsing and deployment rate-limit guidance.
- [ ] Operator-visible internal error classification without leaking secrets.
- [ ] Backup/restore, master-key rotation, dedicated migration/runtime DB roles.
- [ ] Dependency/vulnerability checks and independent OIDC interoperability review.

## Later, only from concrete need

WebAuthn; RADIUS PAP and explicit NAS/method/attribute registration; TACACS+ peers
and command mappings; explicitly enrolled legacy network credentials when needed;
separate API audiences; multi-instance deployment. No weakened primary password
store, generic plugin framework, or second identity database.
