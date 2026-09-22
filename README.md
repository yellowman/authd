# authd

A small Go identity and access service backed by PostgreSQL. Own users, primary
credentials, roles, permissions, MFA, provider sessions, and OIDC once; let many
applications consume the same identity. The first relying-party target is
`yellowman/bdcmaps`.

Relying-party identity linking, application-local authority, ACR step-up, and `sid` session correlation are defined in [`docs/RP_INTEGRATION.md`](docs/RP_INTEGRATION.md).

## v0.8.1 — external PostgreSQL/OpenBSD qualification fixes

v0.8.1 incorporates fixes found by an external OpenBSD/amd64 + real PostgreSQL
qualification run of v0.8. The live provider completed bootstrap, web login, client
registration, Authorization Code + PKCE, `client_secret_post`, ID-token/UserInfo,
and refresh rotation against PostgreSQL. The actual private bdcmaps callback and
production deployment remain unqualified. See `VALIDATION.md` for the exact evidence
boundary.

Implemented in this revision:

- OIDC `acr_values` handling with `urn:authd:acr:pwd` and `urn:authd:acr:mfa`, client-level MFA minimums, and `unmet_authentication_requirements` when the requested context cannot be satisfied.
- ID Tokens now emit actual `acr`/`amr` plus stable provider-session `sid`; refresh families retain the originating `sid`.
- RP-initiated logout checks `sid` when present so one same-subject provider session cannot terminate another.
- A binding RP integration contract requires `(iss, sub)` identity keys, forbids silent email-based linking and tenant inference, and explicitly permits customer applications such as Evident to trust other IdPs directly instead of federating them through authd.
- `authd migrate` is now the only normal executable path that performs DDL. Daemon and bootstrap startup verify the exact embedded migration manifest and fail closed on missing, stale, ahead, or altered migration history.
- A reviewed PostgreSQL runtime-grant script supports a DML-only daemon role without schema ownership/CREATE privileges; migration/login role creation and passwords remain operator-owned.
- Internal HTTP failures return a request reference and structured bounded error class for operator correlation without logging raw database/credential errors.
- Soft deletion of local users with credential, MFA, role, session, authorization-code, and refresh-family teardown; the immutable identity row remains for audit/sub continuity.
- Deletion of non-built-in roles with transactional final-administrator protection.
- Permission editing and reference-safe deletion; `system.admin` cannot be renamed or deleted.
- Administrative MFA reset that revokes the affected user's live provider sessions and refresh capability.
- Self-service profile editing with email-verification clearing, plus recovery-code regeneration restricted to a recent MFA-authenticated session.
- Destructive OIDC-client deletion with foreign-key-cascade removal of durable authorization requests, codes, scopes, redirects, secrets, and refresh families.
- Administrator signing-key inventory and signing-key rotation UI; private-key ciphertext is never exposed by the listing.
- Periodic bounded-state cleanup for expired authorization continuations/codes, sessions, pending TOTP enrollment, old bootstrap tokens, absolutely expired refresh families, and configurable audit retention. Signing keys are deliberately excluded from automatic cleanup.
- New PostgreSQL integration cases for destructive lifecycle invariants, client deletion cascades, recovery regeneration/MFA reset, signing-key administration, cleanup, and fresh-session self-profile changes.
- Explicit trusted-proxy CIDR configuration with right-to-left `X-Forwarded-For` resolution; untrusted peers and malformed chains cannot spoof audit/rate-limit source IPs.

The v0.5 provider functionality remains:

- OpenID Connect discovery and OAuth authorization-server metadata.
- Encrypted persisted 3072-bit RSA signing keys, RS256 JWTs, JWKS publication,
  signing-key rotation overlap, and destruction of retired private-key ciphertext.
- Authorization Code flow with exact redirect matching and mandatory PKCE S256.
- Durable server-side authorization continuations; the browser carries only an
  opaque random handle through login, so OAuth state/nonce/challenge values do not
  pass through login forms and parallel application logins do not share one cookie.
- `state`, `nonce`, `login_hint`, `prompt=none`, `prompt=login`, `max_age`, and the
  RFC 9207 `iss` authorization-response parameter.
- One-use, client/redirect/PKCE-bound authorization codes.
- Confidential clients using `client_secret_basic` or `client_secret_post`, plus
  public clients using `none`; the POST form mode exists for current bdcmaps.
- Registered-origin-only CORS for public browser clients on `/token`, `/userinfo`,
  and `/revoke`; origins are derived from exact redirect registrations and are also
  bound back to the specific public client on credential-bearing requests.
- Signed access tokens and ID tokens, `/userinfo`, requested/client-allowed
  `groups` and `roles` projection, and application permissions as OAuth scopes.
- Opaque rotating refresh tokens, token-specific scope narrowing, current
  user/client/permission re-evaluation, and whole-family revocation on replay.
- RFC 7009-style refresh-token revocation and RP-initiated logout with exact
  registered post-logout redirects.
- Admin creation/editing of OIDC clients, exact redirect/logout URIs, allowed
  identity/application scopes, MFA/refresh policy, access-token TTL, and one-time
  client-secret creation/rotation.
- Token refresh/replay/revocation audit events and server-side prevention of
  granting the provider-only `system.admin` permission to an OAuth client.

The v0.4 identity functionality also remains: one-time bootstrap, Argon2id passwords,
local roles/permissions, provider sessions, password lifecycle, TOTP/recovery
codes, audit, account UI, and transactionally rechecked administration.

## Dependencies and boundaries

Only two direct external Go modules are selected:

```text
github.com/jackc/pgx/v5    PostgreSQL database/sql driver
golang.org/x/crypto        Argon2id
```

HTTP, JWT/JWK framing, PKCE, TOTP framing, and the identity/control layers use the
standard library around those cryptographic/database primitives. There is no ORM,
frontend package manager, Redis, message bus, or external policy service.

OIDC and future RADIUS/TACACS+ adapters consume the same identity model but have
separate protocol registrations. The canonical password remains a one-way Argon2id
verifier; no recoverable primary password or NT hash is introduced for future AAA.

## Build and first use

Use Go 1.26 or newer and PostgreSQL. `golang.org/x/crypto v0.57.0` requires Go 1.26.
The dependency lockfile is committed. `make deps` runs `go mod tidy` and `go mod verify`; it should leave the module files clean:

```sh
make deps
make build
make dev-db
export DATABASE_URL='postgres://authd:authd-dev-only@127.0.0.1:55432/authd?sslmode=disable'
export AUTHD_ISSUER='http://127.0.0.1:8080'
export AUTHD_LISTEN='127.0.0.1:8080'
export AUTHD_DEVELOPMENT=true
umask 077
./scripts/generate-master-key.sh > authd-master.key
export AUTHD_MASTER_KEY_FILE="$PWD/authd-master.key"
./bin/authd migrate
./bin/authd bootstrap
./bin/authd
```

`authd migrate` is the only normal executable path that performs schema DDL.
`authd bootstrap` and the daemon verify that every embedded migration is present
and fail closed when the database is behind or its migration history differs.
`authd bootstrap` prints a one-time 30-minute setup token to the invoking terminal. Open `/setup`, create the initial administrator, then
sign in at `/login`. Identity administration is under `/admin/`; personal
credentials and sessions are under `/account`.

Keep the master key. It encrypts TOTP seeds and OIDC signing private keys. Changing
or losing it makes those encrypted values unreadable.

For production, use separate PostgreSQL migration/owner and runtime roles. The
runtime role needs DML but not schema ownership/CREATE privileges; see
`deploy/postgresql/README.md` and `deploy/postgresql/runtime-grants.sql`. Run
`authd migrate` with the migration connection before switching `DATABASE_URL` to
the runtime login for bootstrap and the daemon.

When authd is behind a reverse proxy, leave forwarded-header trust disabled unless the
direct proxy addresses are known. Configure only those networks, for example:

```sh
export AUTHD_TRUSTED_PROXIES='127.0.0.1/32,::1/128'
```

`X-Forwarded-For` is ignored from every other peer. For a trusted proxy chain, authd
walks right-to-left and uses the nearest untrusted address as the client source. Login
rate limits remain process-local, so a multi-instance deployment requires a different
rate-limit design rather than merely widening this proxy list.

### Register bdcmaps

After signing in as an administrator:

1. Open **Clients**.
2. Register a confidential client with client ID `bdcmaps`.
3. Register the exact `https://<bdcmaps-origin>/auth/callback` redirect.
4. Allow `openid`, `profile`, `email`, and `groups`.
5. Copy the one-time secret into bdcmaps' existing `OIDC_CLIENT_SECRET` runtime
   secret and configure its issuer/client/redirect settings.

The current bdcmaps code sends the secret using `client_secret_post`; authd accepts
that for compatibility. New clients should prefer `client_secret_basic` when their
OIDC library supports it. See `docs/BDCMAPS_INTEGRATION.md`.

## Verification

Full qualification requires **real dependencies and a marked disposable
PostgreSQL database**:

```sh
export AUTHD_TEST_DISPOSABLE=1
export AUTHD_TEST_DATABASE_URL='postgres://authd:authd-dev-only@127.0.0.1:55432/authd?sslmode=disable'
make verify
```

On OpenBSD/amd64, where the Go race detector is unavailable, use:

```sh
make verify-openbsd
```

A release still requires `make race` on a Go platform that supports the race detector.

The database suite creates and removes a unique `authd_it_*` schema. Missing test
configuration is a failure, never a skip. In addition to the v0.4 identity cases,
the integration source now covers client registration, durable authorization
requests, one-use codes, refresh rotation/reuse-family revocation, token audit
events, refusal of `system.admin` as an application scope, and signing-key
rotation/retired-private-key destruction.

`make offline-check` is deliberately partial. It runs the real stdlib-only unit,
race and vet paths plus SQL integration-body typechecking, but it cannot replace a
real pgx/Argon2 build or execute PostgreSQL transactions. The OIDC HTTP tests do
exercise real RSA signing/JWK/JWT code and in-memory protocol persistence, including
the bdcmaps-shaped `client_secret_post` + S256 flow. Details: `VALIDATION.md`.

## Current limits

- Real PostgreSQL/dependency-backed qualification has not run in this authoring
  environment, and actual bdcmaps interoperability remains an external gate.
- There is no user consent screen; registered applications are trusted internal
  clients and authorization is based on their configured scope allow-list.
- Signing-key inventory and manual rotation are implemented; automatic rotation and
  an explicit public-key deletion/retention schedule remain.
- Pagination, TOTP QR rendering, safe break-glass recovery, backup/restore, and
  master-key rotation remain. Admin edit forms carry row versions and stale concurrent
  saves are rejected transactionally.
- JWT access tokens intentionally remain valid until their short expiry after a
  user/session change; refresh and new authorization re-evaluate current grants.
- Rate limits are process-local and deployments currently assume one active authd
  instance. Forwarded IPs are honored only through the explicit trusted-proxy CIDR
  configuration described above.
- OIDC conformance-suite and independent third-party client coverage remain
  qualification work; passing our protocol tests is not a conformance certificate.

## Next delivery

Exercise the actual `yellowman/bdcmaps` callback against authd, then qualify the
production-facing OpenBSD path: HTTPS/nginx/secure cookies/trusted proxy headers,
runtime-role separation, and live TOTP step-up. Run the race suite on a supported
Go platform and an independent OIDC interoperability/conformance suite before a
production candidate. RADIUS remains PAP-first unless a concrete device forces
explicit legacy credential support.

## Repository map

```text
cmd/authd/            server and explicit bootstrap command
internal/identity/    identity service, contracts, validation, rate limits
internal/password/    Argon2id verifier and bounded encoding parser
internal/cryptoutil/  random tokens, hashes, CSRF MAC, authenticated encryption
internal/db/          PostgreSQL repositories, migrations, integration tests
internal/totp/        OTP encoding and verification
internal/web/         provider-operated forms and security middleware
internal/oidc/        OIDC/OAuth protocol, JWT/JWK, tokens, client administration
internal/protocol/    future AAA adapter boundary
```

`SPEC.md` is the product contract. `TODO.md` distinguishes implemented source from
qualification and later operational work. `DESIGN_LANGUAGE.md` defines the adapted
Liminal UI language.
