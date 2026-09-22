# v0.4 validation record

This record supersedes the previous scaffold's substitute-module checks. **No
replacement pgx or x/crypto module was used to validate v0.4.** This is an identity
source delivery, not a production signoff or completed OIDC implementation.

## Executed here

| Check | Result and scope |
|---|---|
| `gofmt` check and `git diff --check` | PASS |
| Shell script syntax | PASS |
| Unit suite for the real stdlib-only packages | PASS: 42 top-level tests across the package suite and standalone verifier parser; 78 test/subtest pass events |
| Race detector | PASS for those same real packages and parser |
| `go vet` | PASS for config, cryptoutil, identity, db, oidc, protocol, totp, web |
| Bounded Argon2id encoded-record parser | PASS, including oversized/unsafe parameters, malformed encodings, and canonical-base64 checks |
| Parser fuzzing | PASS: 6,259 executions during the short authoring run |
| PostgreSQL integration test body | Typechecks with its real SQL code; **not executed against PostgreSQL** |
| Missing-database qualification guard | PASS as a negative witness: `make integration` without explicit disposable-DB configuration exits nonzero (make status 2) |
| Embedded HTML templates/HTTP security handlers | PASS with explicit test-only identity/password doubles |
| Chromium rendering of template output | Reviewed desktop/mobile fixture output for login, setup, account, MFA and administration; eight viewport/page combinations had no page-level horizontal overflow |

The `internal/protocol` package has no tests; Go reports a package-level skip for
that reason. No individual unit test was skipped. The SQL tests are selected only
by the explicit integration build tag and are not counted as passing unit tests.

`./scripts/check-offline.sh` reproduces the partial checks on the installed Go
1.23.2 toolchain. It creates a temporary dependency-free modfile outside the
repository to compile packages that do not import pgx or Argon2. It does not alter
the production Go 1.25 module, add replace directives, install stubs, or pretend
the production executable was built. It prints the untested components explicitly.

The unit doubles prove HTTP/service orchestration, not PostgreSQL atomicity or
Argon2 correctness. AES-GCM, SHA/HMAC, randomness, TOTP calculation and replay
orchestration use the actual local production code in those tests. The real
`internal/password` KDF test remains in the ordinary dependency-backed test suite.

For UI review, Chromium rendered actual template output with representative
fixture data and inline copies of the production CSS. Browser navigation to the
local HTTP fixture was blocked by the environment, so this was static rendering,
not an end-to-end browser login test. A cramped mobile table was corrected to
scroll inside its keyboard-focusable panel instead of breaking labels into tiny
fragments. Images are not shipped as dependencies in the source repository.

## Attempted but blocked / not qualified

A normal `go test ./...` attempted to download `go1.25.0`, then failed because the
sandbox could not resolve/reach `proxy.golang.org`. The installed compiler is Go
1.23.2, and the needed real module downloads are unavailable here. PostgreSQL and
a usable container runtime are also unavailable.

The following have **NOT passed** in this environment:

- the full executable build using the selected toolchain and real pgx/x/crypto;
- the actual Argon2 KDF round-trip test;
- execution of migrations 001/002 or identity SQL against PostgreSQL;
- transaction/race/revocation/recovery assertions on the real database;
- browser actions against the actual daemon plus PostgreSQL;
- OIDC conformance or bdcmaps login (issuance endpoints remain 501);
- the newly added GitHub Actions workflow, backup/restore, or production deployment.

The repository retains its direct dependency pins, but the new artifact contains
no fabricated dependency checksums. Resolve modules, review/commit the resulting
`go.mod`/`go.sum`, and run the real gate on a networked development machine.

## Required full gate

```sh
make deps
export AUTHD_TEST_DISPOSABLE=1
export AUTHD_TEST_DATABASE_URL='postgres://USER:PASSWORD@HOST:5432/DISPOSABLE_DB?sslmode=verify-full'
make verify
```

For the loopback-only development container, use the development connection URL
in README.md. Do not mark a production database disposable. The test creates its
own `authd_it_*` schema and removes that schema, and may install pgcrypto in public.

`make verify` includes formatting, real unit/KDF tests, race, vet, full build, and
the explicit database suite. `.github/workflows/test.yml` defines the same gate
with a disposable PostgreSQL 18 service. A missing environment variable, missing
driver, failed connection, failed migration, or failed assertion is a failure;
none is converted into a successful skip.

The real SQL suite is designed to exercise bootstrap races/sticky completion,
current grants, unauthorized writes, email-verification changes, built-in/final
admin protection, password-reset credential races, forced-change restrictions,
MFA enrollment binding, transactional OTP/audit rollback, concurrent OTP use,
recovery replay, and credential-change revocation. Those are test intentions,
not completed real-database evidence until the gate runs.
