# authd

A small Go identity and access service backed by PostgreSQL. Own users, primary
credentials, roles, permissions, and MFA once; let applications consume that
identity through OIDC. The first planned relying party is `yellowman/bdcmaps`.

## v0.4 — local identity implementation

This version replaces the login/admin shell with implemented handlers and a
transactional PostgreSQL repository. **It is not yet a functioning OIDC provider
or a production-qualified authentication service.** Authorization, token issuance,
refresh, UserInfo, and RP-initiated logout remain explicit 501 endpoints. Discovery
is a development contract preview, not a conformance claim. See `VALIDATION.md`.

Implemented in this source revision:

- One-time administrator bootstrap, with a permanent installation-state guard.
- Password login; current enabled state and password snapshot rechecked before
  inserting a session. Zero-role accounts can sign in without receiving privileges.
- Hashed provider sessions, session-bound CSRF, idle/absolute expiry, local logout,
  per-session revocation, and logout of other sessions.
- User creation/editing, role assignment, enable/disable, password change/reset,
  forced password change, role editing, and permission creation.
- `system.admin` checks at the HTTP boundary and again inside write transactions;
  recent authentication for privileged writes; final-administrator protection.
- Encrypted TOTP enrollment, confirmation, mandatory second-factor verification
  for enrolled users, single-use recovery codes, and authenticated MFA removal.
- Transactional audit records; password/MFA changes revoke provider sessions,
  outstanding authorization codes, and existing refresh-token families.
- Explicit email verification, cleared when the normalized address changes.
- Bounded password-hash work and hash parsing, process-local rate limits, strict
  deployment configuration, and server-rendered responsive account/admin forms.

These are source implementation statements. The PostgreSQL paths still need the
real integration gate described below; the authoring environment could not run it.

## Dependencies and boundaries

Only two direct external Go modules remain:

```text
github.com/jackc/pgx/v5    PostgreSQL database/sql driver
golang.org/x/crypto        Argon2id
```

The HTTP and identity layers use standard-library interfaces. The executable
registers pgx's SQL driver; `internal/db` owns SQL and transactions, not an ORM.
There is no frontend package manager or external asset fetch. OIDC and future
RADIUS/TACACS+ adapters consume the same identity model, with separate protocol
registrations. No recoverable primary passwords or NT hashes were introduced.

## Build and first use

Use the project Go 1.25 toolchain (or a compatible newer version) and PostgreSQL.
The package does not include downloaded dependencies or an invented `go.sum`.
Resolve the pinned modules on a networked development machine, review and commit
the resulting `go.mod`/`go.sum`, then build:

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

`authd bootstrap` applies migrations, issues one token, and prints it to the local
terminal. It does not create a user or print the token into the running daemon's
logs. Open `http://127.0.0.1:8080/setup`, enter that token and the first account,
then sign in at `/login`. Ordinary identity work happens in `/admin/`; personal
credentials and sessions are at `/account`.

The token expires after 30 minutes. Issuing another token invalidates earlier
ones. Setup remains permanently closed after completion, even if an operator
later removes all users. Keep the master key: changing or losing it invalidates
CSRF proofs and makes existing encrypted authenticator seeds unreadable.

Development mode requires both a loopback issuer and loopback listener. Outside
development, an HTTPS reverse proxy must terminate TLS in front of authd's HTTP
listener. The application does not implement direct TLS termination. Master-key
files must be owner-only regular files. Do not use the development database
password or disabled database TLS in production. Example settings are not loaded
from `.env` automatically; use your shell or service manager.

## Verification

Full checks require **real dependencies and a marked disposable PostgreSQL DB**:

```sh
export AUTHD_TEST_DISPOSABLE=1
export AUTHD_TEST_DATABASE_URL='postgres://authd:authd-dev-only@127.0.0.1:55432/authd?sslmode=disable'
make verify
```

The database test creates and removes a unique `authd_it_*` schema, and ensures
`pgcrypto` exists in `public`. Use only a disposable database; the explicit marker
is required. Tests cover migration re-entry, bootstrap races, backend access
checks, current grants, email verification, last-admin rollback, password-reset
races, enrollment binding, OTP/recovery replay, and failed-transaction rollback.
Missing test configuration is a failure, never a skip. The checked-in GitHub
Actions workflow runs the same gate with PostgreSQL 18; it has not run merely
because the YAML exists.

`make offline-check` is an explicitly partial fallback: real stdlib-only unit and
race tests, vet, bounded-hash-parser tests, and SQL-test-body typechecking. It does
not replace the normal gate, build the executable, validate Argon2, or execute SQL.
It uses no substitute modules. Details and actual local results: `VALIDATION.md`.

## Current limits

Administrative forms fail closed above 200 users, roles, or permissions rather
than silently dropping assignments from a truncated list. Sessions/audit show the
latest 200 rows. User/role/permission deletion, permission editing, client CRUD,
MFA reset/recovery regeneration, QR generation, self-service profile edits,
expired-row cleanup, trusted-proxy IP parsing, and application-session revocation
propagation remain work items. Fresh sign-in (within ten minutes) is required for
admin writes and MFA enrollment/removal. Rate limits are per process, not a
multi-replica service. Proxy users currently share the proxy's IP rate bucket;
forwarded headers are intentionally ignored.

## Next delivery

Finish real PostgreSQL/dependency qualification, then implement signing keys,
JWKS, authorization transactions and one-use code exchange. Preserve the existing
`bdcmaps` requirements: PKCE S256, `client_secret_post`, and requested/client-allowed
`groups` claims. Login compatibility is not the same as migrating bdcmaps' own
role/session enforcement; see `docs/BDCMAPS_INTEGRATION.md`.

## Repository map

```text
cmd/authd/            server and explicit bootstrap command
internal/identity/    identity service, contracts, validation, rate limits
internal/password/    actual Argon2id verifier and bounded encoding parser
internal/cryptoutil/  random tokens, hashes, CSRF MAC, authenticated encryption
internal/db/          PostgreSQL transactions, migrations, integration tests
internal/totp/        OTP encoding and verification
internal/web/         real provider-operated forms and security middleware
internal/oidc/        discovery and unimplemented protocol endpoints
internal/protocol/    future AAA adapter boundary
```

`SPEC.md` is the product contract. `TODO.md` separates delivered code from pending
functionality. `DESIGN_LANGUAGE.md` defines the Liminal adaptation.
