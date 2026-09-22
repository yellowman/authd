# authd

**One place to manage people, passwords, MFA, and application sign-in.**
A small Go service backed by PostgreSQL, with a server-rendered administration UI.
No LDAP, user YAML, frontend build system, or external policy service.

## Start here

| What you are trying to do | Read / open |
|---|---|
| Understand the app and connect the first application | [Operator guide](OPERATOR_GUIDE.md), or **Administration → Start here** in the browser |
| Install from a new PostgreSQL host | [Deployment guide](DEPLOYMENT.md) |
| Connect BDC Maps | [Two-sided BDC walkthrough](docs/BDCMAPS_INTEGRATION.md) |
| Use a Unix socket behind nginx | [Unix sockets](docs/UNIX_SOCKET.md) |
| Integrate another application | [RP integration contract](docs/RP_INTEGRATION.md) |
| Upgrade an installed server | [Upgrade procedure](DEPLOYMENT.md#13-updating-an-existing-installation) |
| Find changes and test coverage | [Changelog](CHANGELOG.md), [validation record](VALIDATION.md) |

## What it does

Create a **user** for each person. Register a **client** for each application.
Assign **roles** to people. Applications can either map those role names to their
own roles, or request/check fine-grained **permission scopes**.

```text
Person opens an application
  → application redirects to authd
  → person signs in (password + optional authenticator)
  → application receives and verifies an OIDC result
  → application applies its own access policy
```

The first BDC Maps integration uses group/role mapping; it does **not** require a
new permission catalog. authd's `system-admin` role manages authd, not BDC. A client
secret belongs in the application's backend configuration, not a user's login.
The browser UI explains those distinctions beside the controls.

Identity is `(issuer, subject)`, never email alone. Customer/tenant/PBX/project/room
membership stays in the application. An enabled account is not automatically a
member of every app. Conversely, a client that requests only identity may
authenticate any enabled authd user; there is no separate client allowed-users
list. Read the [operator guide](OPERATOR_GUIDE.md) before choosing a policy.

## Current release: v0.9.3

Includes the reported native-form fix (`Referrer-Policy: origin`), an operator-first
admin landing page, explanatory field help, saved client connection details, and
an installed daily-use guide. Origin and CSRF validation remain in place. There
is no database migration, dependency update, transport change, or automatic
reconfiguration of BDC. This is a code/template change: build/install/restart to
serve it; reopening a previously loaded page is also required.

## Build and test

Go 1.26+ is required by the pinned dependency graph. The only direct Go
dependencies are `pgx/v5` and `golang.org/x/crypto`; see `go.mod` / `go.sum`.

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
nginx, or the actual BDC callback. Browser tooling is a test dependency only;
authd serves its normal UI without JavaScript or a browser-testing runtime.
See [browser test instructions](docs/BROWSER_TESTS.md) and `VALIDATION.md`.

Install and update with `make install-openbsd` or `make install-linux` on the
corresponding host. Active configuration, database credentials, and the master key
are preserved. `authd migrate` is a separate owner-credential command; the daemon
runs as `_authd` with `authd_runtime` database rights. Follow `DEPLOYMENT.md` rather
than using these targets as a substitute for initial database/service setup.

## Boundaries

Authorization Code + PKCE, RS256, TOTP/recovery, consent, rotating refresh tokens,
UserInfo, and RP-initiated logout are implemented. Back-channel logout, upstream
OIDC/SAML federation, RADIUS/TACACS, passkeys, and machine-identity grants are not
implemented. Other apps may accept their own trusted providers directly.

`SPEC.md` states the contract; `ARCHITECTURE.md` describes ownership boundaries;
`DESIGN_LANGUAGE.md` guides UI changes. The prior externally reported v0.9.0
PostgreSQL/live-provider pass and later local checks have separate evidence in
`VALIDATION.md`. No OpenID certification or production approval is implied.
