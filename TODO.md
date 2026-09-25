# Current follow-through

- [x] Dynamic Client Registration with app-prefixed permission creation and
  optional unassigned role/group templates.
- [x] Administrative groups that assign roles to members; direct and group
  roles combine for effective permission evaluation.
- [ ] Qualify the current BDC access-token-scope cutover end to end; the
  2026-09-22 BDC PASS below belongs to the older role-claim flow.

- [x] Generic Markdown-driven adding-an-app workflow, separate application profiles.
- [x] Administrator-only catalog, renderer, full-text search, TOC and original source.
- [x] Unshaded SVG sidebar with accessible names and explicit current-page state.
- [x] Visible field explanations and a searchable field reference.
- [x] **Full bdcmaps application login verified**, as reported by the operator on
  2026-09-22. The first actual relying-party callback/login gate is complete.
- [ ] Independent OIDC/OAuth conformance certification (not implied by one working app).

See VALIDATION.md for current and historical evidence. The sections below track
implementation and remaining qualification, not a claim that each future app
has been integrated.

# Implementation sequence — v0.9.1

Checked implementation items mean source is present, not production qualification.
Qualification items identify reported or locally executed evidence explicitly in
`VALIDATION.md`. The v0.9.0 external PostgreSQL/build/live-provider pass is now
recorded; the later full bdcmaps app login is also recorded. Unreported deployment checks remain open.

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
- [x] Actual bdcmaps callback and complete application login, operator-reported PASS (2026-09-22); not just a fixture.
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
- [ ] Independent full OIDC conformance runner and SQL lock/query plan/load qualification.

## Qualification

- [x] Real-PostgreSQL integration test source and non-skipping gate definition.
- [x] OIDC SQL lifecycle integration source added to that gate.
- [x] External v0.9.0 `make verify-openbsd` PostgreSQL integration pass reported by the user; raw log not supplied.
- [x] External v0.9.0 formatting/tests/vet/build and deployment syntax pass reported via `make verify-openbsd`.
- [x] External v0.9.0 greenfield database/roles, owner migration, runtime grants/bootstrap reported PASS.
- [x] External v0.9.0 live consent/PKCE/client_secret_post/ID-claims/UserInfo/refresh/code-replay flow reported PASS.
- [ ] Negative runtime-role privilege checks (DDL/owner assumption denied); not explicitly established by the summary.
- [ ] v0.8.4 → v0.9.0 migration against a restored existing database, rather than only greenfield.
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

## v0.9.2 transport tranche

Implemented source: TCP/Unix listener selection; restrictive socket publication;
lifetime lock, stale-path refusal/recovery and inode-safe shutdown; explicit
Unix-proxy IP trust; Linux runtime-directory sandbox allowance; OpenBSD standard
rc.subr background/start plus post-su environment launcher; socket/chroot/cutover
documentation. No dependency or migration added.

Qualification remains separate: run `make verify-openbsd` with real dependencies,
exercise native rcctl start/check/restart/stop and a SIGKILL/restart, inspect
actual worker supplementary groups and chroot reachability, run Linux's full
race/systemd gate, and exercise the real HTTPS/RP path. The repository's Linux
socket/proxy fixtures do not constitute these deployment approvals.

## v0.9.5 documentation index

- [x] Generic connection help for every client, with no named-client branches.
- [x] Directory-derived Markdown list, filenames and source headings; no curated metadata.
- [x] Discover newly added nested docs/deployment files without editing an index.
- [x] Retain the completed first-app integration record separately from local UI tests.
