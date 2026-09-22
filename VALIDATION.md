# Validation record — v0.9.1 documentation / v0.9.0 runtime

This is test evidence, not a production approval or OpenID certification. The
v0.9.0 audit base was `db7cae8` (v0.8.4); its delivered revision was `b8d336d`.
v0.9.1 changes documentation, evidence records and SQL helper comments/messages
only. Runtime source, dependency locks, migrations, SQL privilege statements,
Makefile and native service definitions are unchanged.

## External v0.9.0 qualification — reported PASS

The user supplied the following summary on 2026-09-22. It is retained
[verbatim](docs/validation/v0.9.0/external-openbsd-report.md). No raw command log,
tested Git SHA, PostgreSQL version or compiler version accompanied this report.
These are reported external results, not tests rerun in the authoring container.

| Check | Reported result and boundary |
|---|---|
| `make verify-openbsd` | PASS: formatting, tests, vet, build, PostgreSQL integration, deployment syntax |
| Greenfield PostgreSQL setup | PASS: database/roles, owner migration, runtime grants and runtime bootstrap |
| Live OIDC provider | PASS: discovery, bootstrap, consent, PKCE, `client_secret_post`, ID-token claims, UserInfo, refresh rotation, code-replay protection |
| Actual bdcmaps callback at maps.ykwc.com | NOT EXERCISED |
| Production HTTPS / proxy behavior | NOT EXERCISED |
| Native service installation | NOT EXERCISED; syntax validation is not service startup |
| Live MFA | NOT EXERCISED |
| Linux race / systemd qualification | NOT EXERCISED |

This closes the initial v0.9.0 real-PostgreSQL execution gap. It does not establish
restored-database migration, independent OIDC conformance, production throughput,
backup/restore/failover, master-key rotation or multi-instance behavior. The report
establishes positive owner/runtime setup, not an explicit negative-privilege
matrix (runtime DDL and owner-role assumption refusal). Those unreported checks
remain open. The revised psql/password documentation has not been rerun by that
tester.

## Original v0.9.0 authoring-environment evidence

The following records retain what was executed at source-delivery time. Their
local limitations are not a claim that the later external tests never ran.

### Executed at source delivery

Environment: Linux/amd64, Go 1.23.2. Production module minimum: Go 1.26.0.

| Check | Result and boundary |
|---|---|
| Six initial protocol regression groups against baseline | Failed as expected; original defects reproduced |
| 102 named top-level tests in stdlib-only packages | PASS; actual config/crypto/identity/db/oidc/TOTP/web code, protocol store fixtures |
| Two standalone password-encoding tests | PASS; bounds/parser only, not Argon2 derivation |
| Race detector | PASS for the available real component suites, not pgx/SQL/full executable |
| Vet | PASS for available stdlib-only packages |
| Strict JSON fuzzing | PASS; 74,839 executions in five seconds with two workers |
| SQL integration test source | Compiles/typechecks; NOT executed |
| Format and diff whitespace checks | PASS |
| Shared environment example parity | PASS |
| Shell syntax for scripts/*.sh | PASS |
| systemd-analyze verify | PASS with source-tree executable/env path substitutions; not service startup |
| Applied migrations 001–004 | Byte-identical to baseline |
| Missing disposable database gate | Fails with nonzero status, not a skipped success |
| Production-module test attempt | Blocked before compilation: Go 1.26 minimum versus local Go 1.23.2 |

`./scripts/check-offline.sh` uses a temporary Go 1.23 modfile outside the repo,
with network/module download disabled. It does not change committed module files,
provide stub dependencies, exercise the Argon2 KDF, or register pgx. It compiles
the real integration test bodies with an explicit file list but never runs them.
The in-memory OIDC HTTP fixture uses real RSA/JWT/JWK/PKCE paths; it is not an
independent relying party or a SQL transaction simulator.

## Retained logs

Trailing whitespace is normalized in the checked-in logs; results and measured values are unchanged.

- [Original reproduced failures](docs/validation/v0.9.0/before-fixes.log).
- [Component/race/vet/SQL-typecheck gate](docs/validation/v0.9.0/final-offline-gate.log).
- [Fuzz execution](docs/validation/v0.9.0/fuzz.log).
- [Environment, full-test refusal and static checks](docs/validation/v0.9.0/environment-and-static.log).
- [Before CPU benchmark](docs/validation/v0.9.0/benchmark-before.log).
- [After CPU benchmark](docs/validation/v0.9.0/benchmark-after.log).

The benchmark fixtures use no database or network. UserInfo's median CPU-handler
time fell from 368.474 to 192.634 microseconds; token-pair encoding from 6.582 to
6.055 milliseconds. UserInfo allocation count increased even though time and
allocated bytes fell. All numbers and limitations are in `docs/OIDC_AUDIT.md`.

### SQL not executed in the original authoring environment

The real integration suite now contains code and refresh signing-failure rollback,
code/refresh replay and client-proof binding, unrelated-grant concurrency,
exactly-one code winner, revocation-versus-grant commit, natural session expiry
versus explicit revocation, browser/consent binding, narrowing/absolute expiry,
cleanup replay retention, reserved permission constraints, migration-prefix
validation and session-touch throttling. This is a significant replacement of the
old grant implementation. The later external report above states that the new
v0.9.0 PostgreSQL integration gate passed; an older revision's tests alone would
not have qualified it.

No PostgreSQL server/client binaries or usable container runtime exist here.
Network/DNS attempts to obtain the production toolchain/modules failed. Thus the
full executable build, actual Argon2 round trip, SQL syntax/query plans/locking,
runtime-role grants and all five migrations remain unexecuted in this environment.

## Historical external evidence — earlier version only

The user supplied a test report for a separate OpenBSD/amd64 Go 1.27 test copy.
After fixing the stale migration-count assertion and refresh timestamp casts,
that copy passed unit/vet/format, real disposable-PostgreSQL lifecycle tests, and
a live provider flow through setup/login, client creation, code+PKCE,
`client_secret_post`, ID-token claims, UserInfo and refresh rotation. Its dependency
lock state was accepted in v0.8.1 and is unchanged by this audit.

That report did not cover the real BDC callback/deployment, production HTTPS,
proxy/cookie behavior, runtime-role separation, native service boot, live MFA,
independent conformance, race tests, master-key rotation/restore or failover.
It does not validate this revision's new grant transactions, migration 005 or
concurrency changes. Earlier installer preservation evidence also remains
historical; service-manager operation was not rerun here.

## Remaining qualification gates

On a supported networked Linux test host:

```sh
make deps
make dev-db
export AUTHD_TEST_DISPOSABLE=1
export AUTHD_TEST_DATABASE_URL='postgres://authd:authd-dev-only@127.0.0.1:55432/authd?sslmode=disable'
make verify
make linux-deploy-check
```

The external report states that `make verify-openbsd` passed for v0.9.0. Rerun it
when runtime changes; full race testing remains a separate supported-platform
requirement. Run migration against a restored existing database as well
as a fresh one. Read the v0.9.0 upgrade section in DEPLOYMENT.md before doing so.

Then execute the actual `bdcmaps` RP callback and an independent OIDC conformance
runner. Qualify production issuer/TLS/proxy headers, secure cookies, live TOTP,
public/Basic clients, revocation, all logout contexts, native service install/start/
stop, owner/runtime separation, persistent keys and backup/restore. No production
schema, production user credentials or production tenant data were accessed here.


## v0.9.1 local documentation checks

See `docs/validation/v0.9.1/documentation-checks.log` for checks performed on this
update: exact runtime/dependency/migration/service equivalence to v0.9.0,
unchanged executable SQL (ignoring comments and the operator-facing echo),
deployment shell-block syntax, local documentation links and diff whitespace.
No new live database, OpenBSD service or independent RP run is claimed.
