# authd

**authd is a self-hosted OpenID Connect (OIDC) provider and OAuth 2.0
authorization server for human sign-in to applications.** Built in Go and backed
by PostgreSQL, it provides one place to manage people, passwords, MFA, clients,
and access grants. Its account and administration pages are server-rendered; it
requires no LDAP, user YAML, frontend build system, or external policy service.

## Start here

| What you are trying to do | Read / open |
|---|---|
| Understand the app and connect the first application | [Adding an app](docs/ADDING_AN_APP.md), or **Administration → Start here** in the browser |
| Install from a new PostgreSQL host | [Deployment guide](DEPLOYMENT.md) |
| Browse all documentation / explain a field | **Administration → Documentation**, [field reference](docs/FIELD_REFERENCE.md) |
| Use a Unix socket behind nginx | [Unix sockets](docs/UNIX_SOCKET.md) |
| Integrate another application | [RP integration contract](docs/RP_INTEGRATION.md) |
| Design a new application's scopes, roles and access checks | [Application integration blueprint](docs/APPLICATION_INTEGRATION.md) |
| Upgrade an installed server | [Upgrade procedure](DEPLOYMENT.md#13-updating-an-existing-installation) |
| Find changes and test coverage | [Changelog](CHANGELOG.md), [validation record](VALIDATION.md) |

## What it does

Applications connect through OIDC and OAuth 2.0. authd supports discovery,
Authorization Code with PKCE, signed ID and access tokens with public verification
keys (JWKS), UserInfo, consent, and rotating refresh tokens where enabled. People
sign in with a password and, when required, a TOTP authenticator or recovery code.
Administrators manage users, clients, sessions, signing keys, and audit history
from the web interface.

Create a **user** for each person and register a **client** for each application.
**Roles** bundle permissions; **groups** assign roles to people, who may also hold
roles directly. An application requests OAuth scopes. authd grants an application
permission scope only when the client requests it, the client is allowed to
request it, and the user holds it. Applications can instead map role names to
their own roles. In either case, the application enforces its own access rules
for customers, projects, records, and other resources.

```text
Person opens an application
  → application redirects to authd
  → person signs in (password + optional authenticator)
  → application receives and verifies an OIDC result
  → application applies its own access policy
```

A role-name integration does **not** require a new permission catalog. authd's
`system-admin` role manages authd, not every application. A client secret belongs in the application's backend configuration, not a user's login.
The browser UI explains those distinctions beside the controls.

Standard OAuth Dynamic Client Registration lets applications register through
discovery and declare scopes. authd's explicit extension can turn
application-prefixed scopes into permissions and create initial role and group
templates. Registration does not assign any person to a role or group. See
[Building an OIDC client](docs/APP_CREATOR_OIDC.md) for the standard protocol
and authd-specific behavior.

Identity is `(issuer, subject)`, never email alone. Customer/tenant/PBX/project/room
membership stays in the application. An enabled account is not automatically a
member of every app. Conversely, a client that requests only identity may
authenticate any enabled authd user; there is no separate client allowed-users
list. Read the [operator guide](OPERATOR_GUIDE.md) before choosing a policy.

## Documentation and validation

Start here renders a generic **Adding an app to authd** workflow from Markdown.
Documentation is an authenticated portal for the complete shipped product docs,
with full-text search, heading navigation, original source and internal links.
The index lists the actual Markdown filenames grouped by directory. Titles
come from Markdown headings; new or renamed files need no catalog-code edit.
Client forms and saved connection help are generic for every application, with
no client-ID-specific links or configuration advice.

**One complete application integration is verified: bdcmaps.** The operator
reported a successful full login through the real application after v0.9.3.
[Recorded evidence](docs/validation/v0.9.3/external-bdcmaps-report.md) distinguishes
that completed RP login from provider-only tests and independent conformance.

## Build and test

Go 1.26+ is required by the pinned dependency graph. The only direct Go
dependencies are `pgx/v5` and `golang.org/x/crypto`; see `go.mod` / `go.sum`.
The isolated Markdown parser source and license are bundled; its Unicode folding
uses the already-pinned indirect `x/text` module. See [THIRD_PARTY.md](THIRD_PARTY.md).

```sh
make deps
make build
make test
```

Full qualification needs a disposable PostgreSQL instance and its explicitly
marked test environment, as described in `DEPLOYMENT.md`:

```sh
make verify-openbsd     # native OpenBSD checks; no unsupported -race
make verify-linux       # unit/race/vet/build/real PostgreSQL + unit-file syntax
make browser-check     # separate native-form Chromium gate; needs Python Playwright
```

The browser tests use the actual HTTP handlers and templates with synthetic
persistence/credentials. They do not replace real PostgreSQL, the Argon2 KDF,
nginx, or an actual application's callback. Browser tooling is a test dependency only;
authd serves its normal UI without JavaScript or a browser-testing runtime.
See [browser test instructions](docs/BROWSER_TESTS.md) and `VALIDATION.md`.

Install and update with `make install-openbsd` or `make install-linux` on the
corresponding host. Active configuration, database credentials, and the master key
are preserved. `authd migrate` is a separate owner-credential command; the daemon
runs as `_authd` with `authd_runtime` database rights. Follow `DEPLOYMENT.md` rather
than using these targets as a substitute for initial database/service setup.

## Boundaries

authd is not a customer-membership database or a replacement for application
authorization. It does not currently provide LDAP synchronization, upstream
identity federation, SAML, RADIUS/TACACS+, passkeys, machine-identity grants,
or back-channel logout. Other apps may accept their own trusted providers
directly. RP-initiated logout is implemented.

`SPEC.md` states the contract; `ARCHITECTURE.md` describes ownership boundaries;
`DESIGN_LANGUAGE.md` guides UI changes. The prior externally reported v0.9.0
PostgreSQL/live-provider pass, full bdcmaps application login and local UI checks have separate evidence in
`VALIDATION.md`. No OpenID certification or production approval is implied.
