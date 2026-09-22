# authd

A small Go identity and access service backed by PostgreSQL. Own users, primary
credentials, roles, permissions, MFA, provider sessions, and OIDC once; let many
applications consume the same identity. The first relying-party target is
`yellowman/bdcmaps`.

## v0.5 — OIDC provider implementation

v0.5 adds the protocol path on top of the v0.4 local-identity implementation.
**This is implemented source, not production qualification.** The authoring
environment cannot run PostgreSQL, download the selected Go 1.25 toolchain/modules,
or run the actual private bdcmaps application. See `VALIDATION.md` for the exact
evidence boundary.

Implemented in this revision:

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

The v0.4 identity functionality remains: one-time bootstrap, Argon2id passwords,
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

Use the project Go 1.25 toolchain (or a compatible newer version) and PostgreSQL.
Resolve the pinned modules on a networked development machine and review/commit the
resulting `go.sum`:

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
./bin/authd bootstrap
./bin/authd
```

`authd bootstrap` applies migrations and prints a one-time 30-minute setup token
to the invoking terminal. Open `/setup`, create the initial administrator, then
sign in at `/login`. Identity administration is under `/admin/`; personal
credentials and sessions are under `/account`.

Keep the master key. It encrypts TOTP seeds and OIDC signing private keys. Changing
or losing it makes those encrypted values unreadable.

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
- Signing-key rotation is implemented in the service/store but does not yet have
  an administrator button or automatic rotation schedule.
- User/role/permission deletion, permission editing, pagination, optimistic admin
  concurrency, administrative MFA reset, recovery-code regeneration, QR rendering,
  profile self-editing, expired-row cleanup, and backup/master-key rotation remain.
- JWT access tokens intentionally remain valid until their short expiry after a
  user/session change; refresh and new authorization re-evaluate current grants.
- Rate limits are process-local and deployments currently assume one active authd
  instance. Forwarded IP headers are intentionally ignored until trusted-proxy
  handling is explicit.
- OIDC conformance-suite and independent third-party client coverage remain
  qualification work; passing our protocol tests is not a conformance certificate.

## Next delivery

Run the real Go 1.25 + pgx/x/crypto + PostgreSQL gate and exercise the actual
`yellowman/bdcmaps` client. Fix any interoperability findings before adding RADIUS
or TACACS+. RADIUS remains PAP-first unless a concrete device forces explicit
legacy credential support.

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
