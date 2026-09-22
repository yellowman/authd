# OIDC, correctness and performance audit — v0.9.0

Date: 2026-09-22. Baseline: v0.8.4, Git `db7cae8`. Input archive SHA-256:
`003bb1ff1ca81cd40e6dd7caf2efd7bf79a82547b9939ddeb585a2c6b9628f54`.

## Outcome and evidence boundary

This is a substantive source correction, not a conformance certificate. The audit
changed protocol handling, browser binding, the database issuance boundary,
revocation, session lifecycle and hot-path resource use. It did not add an identity
broker, tenant engine, LDAP, another database or runtime dependencies.

Six initial regression groups failed on the original runtime, including POST
authorization, reserved request parameters/response mode, voluntary ACR semantics,
Basic encoding, false-success revocation and non-OIDC UserInfo admission. The
[before log](validation/v0.9.0/before-fixes.log) is retained; its codes/secrets are
throwaway in-memory fixture values, not deployment credentials. Those tests now
pass. Additional source findings have separate regressions and SQL integration
witnesses; a unit fixture is not proof of PostgreSQL transaction behavior.

At source-delivery time, the authoring environment executed 104 named top-level
tests (102 in stdlib-only packages and two standalone password-encoding tests),
race checks for those real components, vet, fuzzing, and CPU benchmarks. The new
PostgreSQL tests were typechecked but not executed in that environment.

**Subsequent external evidence, recorded with v0.9.1:** the user reports that
v0.9.0 passed `make verify-openbsd`, including actual PostgreSQL integration;
fresh database/role creation, owner migration and runtime grants/bootstrap; and a
live consent/PKCE/client_secret_post/claims/UserInfo/refresh/code-replay flow.
The [verbatim report](validation/v0.9.0/external-openbsd-report.md) contains the
reported boundary. Raw execution logs were not supplied. Actual bdcmaps, HTTPS/
proxy, native service installation, live MFA and Linux race/systemd execution
remain open, as do independent conformance and restored-database/load testing.
Full current record: [VALIDATION.md](../VALIDATION.md).

## Findings and implemented corrections

### 1. High: a successful-looking flow did not have one grant commit

**Before:** authorization-code consumption, signing and refresh-family creation
were separate operations. A later failure could burn a code without returning
usable tokens, or an authority change could occur before its family appeared.
Refresh rotation happened before signing; a failed response could consume the old
token and make a retry look like theft.

**After:** `internal/db/grants.go` owns `RedeemCode` and `RedeemRefresh`. The grant
transaction validates current authority, selects the active signing key, invokes
a pure response/signing callback, writes consumption/replacement/family state,
records audit and commits. The service returns material only after commit.
Precommit signing/storage/audit failure rolls back consumption. The callback has
no database, network or password-KDF work. This is a structural transaction
change, not a compensating best-effort cleanup.

**Witnesses:** `TestPostgresGrantSigningFailureRollsBack`,
`TestPostgresOneCodeHasOneWinner`, `TestPostgresRevocationSerializesWithGrantCommit`
in `internal/db/oidc_integration_test.go` (source/typechecked; real SQL run pending).
In-memory oversized-response rejection also leaves the grant unused.

**Limit:** database COMMIT and HTTP delivery cannot be made one local transaction.
An ambiguous connection failure or lost response may require a new login. There
is intentionally no replay grace window that accepts a consumed refresh token.

### 2. High: stale client proof, live-session gaps and replay side effects

**Before:** a secret validated outside redemption was not rechecked against
intervening secret rotation. Code redemption did not consistently require the
originating live browser session. Code replay lacked a descendant-family link.
Consumed-refresh handling could run before establishing the right client binding.

**After:** recheck the authenticated client's ID, type, enabled state and secret
hash within the grant transaction. Code redemption validates its originating
session and current user/client scopes. Check client/redirect/PKCE binding before
any code-replay side effect; check client binding before refresh-family reuse
revocation. Correctly bound code replay revokes the recorded descendant family.
The family lock serializes rotation, replay and revocation. Consumed-token hashes
and code witnesses survive while their related offline grant remains usable.

Explicit session revocation now removes unused codes and revokes associated
families in the same mutation. Natural session expiry does not destroy consented
offline access. Fresh login atomically replaces the presented browser session;
ordinary reauthentication preserves earlier offline grants. Password/MFA reset
and disabled users retain stronger user-wide revocation.

**Witnesses:** `TestPostgresGrantReplayAndCredentialBoundaries`,
`TestPostgresSessionRetirementAndOfflineLifetime`,
`TestPostgresRefreshNarrowingAndAbsoluteExpiry`,
`TestPostgresCleanupRetainsCodeReplayWitness`. Already-issued access JWTs still
expire naturally; this change is not online introspection.

### 3. High: an authorization continuation was an unbound bearer handle

**Before:** the standard `request` parameter was repurposed as an internal
continuation, and the continuation was not independently bound to its browser.
POST authorization was missing; several reserved/unsupported parameters were
ignored while a code was issued.

**After:** separate `/authorize/resume?flow=...` from the protocol endpoint.
Hash-bind the flow to a dedicated random HttpOnly browser cookie. Bind consent to
both that browser and the current provider session. Accept GET and form POST;
reject malformed percent encoding, duplicates and oversized values. Reject
unsupported Request Objects, request URIs, registration and response modes with
appropriate protocol errors only after establishing a trusted redirect. Unknown
ordinary optional parameters do not acquire authority.

**Witnesses:** `TestAuditAuthorizationPost`, `TestAuditProtocolParameters`,
`TestBrowserBoundAuthorizationContinuation`, `TestConsentCSRFAndDenial`, and
`TestPostgresBrowserConsentBinding`. Password-change handling now returns to the
pending OIDC flow rather than repeatedly sending the user back to login.

### 4. Medium: ACR preference was advertised as a hard security promise

The old spec and implementation were wrong to treat `acr_values` alone as a
mandatory context requirement. The standard distinguishes voluntary ACR
preferences from essential ACR claim requests. Authd now supports both.

`acr_values` and nonessential `acr` selectors express preferences. The mandatory
cases are client `require_mfa` or an essential `claims.id_token.acr` selector.
An unachievable essential requirement fails; an unknown voluntary value need not.
The RP guide now uses an essential MFA selector plus `max_age` and instructs the
RP to validate the resulting identity, ACR and authentication time.

Freshness is evaluated at completion, not frozen when the flow starts.
`prompt=login`, `select_account`, and `max_age=0` require a new ceremony; refresh
never updates authentication age. Actual `amr` and stable originating `sid` remain.
Normal profile claim selectors are destination-specific, client-allowlisted and
value-filtered; nonmatching normal claims are omitted rather than fabricated.
The `sub` selector constrains the authenticating account. Roles/groups still
require their request scopes; there is no arbitrary claim-policy engine.

**Witnesses:** `TestAuditUnknownACRIsVoluntary`,
`TestEssentialACRAndSubjectSelectors`, `TestAuthenticationFreshnessAtCompletion`,
`TestSelectiveClaimsDoNotReleaseEntireScope`,
`TestClaimValueConstraintsNeverFabricateClaims`.

### 5. High: revocation failure could report success; outages became bad credentials

**Before:** the revocation handler discarded a storage error and returned 200.
Other paths conflated unavailable infrastructure with invalid client/grant state.
That could leave live credentials behind a successful revoke response or make an
RP discard a valid session during a temporary outage.

**After:** genuine invalid-client/grant cases remain OAuth denials; infrastructure
failure returns 503 with bounded public text and request correlation. Unknown or
foreign tokens remain nondisclosing revocation successes, but a failed database
operation does not. Basic credentials use OAuth form-decoding and cannot be
combined with body credentials, including an explicitly empty second secret.
Source-IP audit now uses the shared trusted-proxy resolver rather than ignoring it.

**Witnesses:** `TestAuditRevocationFailureIsNotSuccess`,
`TestDependencyFailuresStayRetryableAndRedacted`, `TestAuditBasicUsesFormEncoding`,
`TestEmptySecondClientAuthenticationMethodRejected`. These error-path witnesses execute with injected storage failures.

### 6. Medium/high: JWT purpose, claim release and logout were too permissive

Access tokens now use `typ=at+jwt`; ID tokens use `typ=JWT`. UserInfo requires an
access token carrying `openid`, not any valid signed token. Logout requires an
ID-token hint, not an access token. `at_hash` accompanies the ID token. JSON
security objects reject duplicate members, unsupported `crit`/`b64`, malformed
base64 and inconsistent RSA key metadata. Token issuance and validation share
a 16 KiB ceiling. Startup validates/decrypts the active private key against JWKS.

UserInfo supports GET/POST and the permitted form-token transport, rejects
ambiguous/header-plus-body credentials and query-string tokens, and performs
one signature verification. Selective claim requests do not leak a whole profile.
A permission named `openid`, `email`, or another protocol control scope is rejected
by service validation and the new database constraint, closing the gap between
the earlier specification and enforcement.

Bare or cross-session logout now asks for explicit CSRF-protected confirmation.
Otherwise-valid expired hints can identify the current/recent session. A failed
logout does not clear the browser cookie or redirect as if it succeeded.
No back-channel logout has been added or advertised.

**Witnesses:** UserInfo transport/type tests; independently signed RSA fixture
checks for critical headers and duplicate JSON; mismatched key/master-key tests;
`TestLogoutFailureDoesNotClearBrowserOrRedirect`; scope-reservation unit and SQL
constraint tests. See the executable test names in `contract_regression_test.go`.

### 7. Performance: remove global grant serialization and repeated work

The old exclusive advisory gate serialized unrelated grant exchanges and some
read-only administration. Now security mutations take the exclusive gate, while
grants share it and lock only their own code/family. This retains an understandable
lock order without giving every token exchange a deployment-wide exclusive lock.
A concurrent-grant SQL witness ensures two unrelated issuance callbacks can both
enter before either is released. It has NOT yet run on PostgreSQL here.

Read-only admin queries use repeatable-read snapshots. Session authority stays
live, but `last_seen_at`/idle writes are throttled to min(60 seconds, idle TTL/4).
Parsed RSA private/public key caches are bounded and keyed by material; selecting
the active key and checking current authority still happen in the database.
UserInfo no longer verifies the same signature twice. Public-client origin checks
use a targeted existence query rather than a truncated full client catalog.
Reverse-FK and expiry indexes are added in migration 005.

Cleanup is broken into 256-row transactions, with a two-second pass budget and
short lock waits. Expired family children are removed in batches before parent
cascade. Remaining work is explicit, not silently called complete. Key retention
and the 200-record admin catalog ceiling remain separate unfinished operations.

### 8. Correctness: migration and build gates must not drift

The migrator now rejects an ahead, renamed or gapped recorded history before
applying pending migrations; startup still requires the exact names/versions.
This does not attest file checksums or physical schema integrity. Migration 005
leaves 001–004 byte-identical and intentionally restarts old pending flows, while
preserving installed identities/credentials/keys/offline families.

CI obtains its Go version from `go.mod` rather than pinning an older incompatible
compiler. Dependency resolution downloads/verifies the committed graph instead
of silently tidying it; build/test gates use `-mod=readonly`. No new runtime
dependency was introduced. The actual CI workflow has not run in this environment.

## Measured CPU/allocation results

Go 1.23.2, Linux/amd64, AMD EPYC 9V74; same in-memory fixture and benchmark on the
original runtime versus modified runtime. Three one-second samples per benchmark;
median shown. Fixture signing keys are RSA-3072. Baseline test helper alone was
generalized from `*testing.T` to `testing.TB` to reuse identical fixture setup;
baseline runtime was unchanged. No PostgreSQL, HTTP network, TLS, proxy or KDF cost
is represented here.

| Benchmark | Before | After | Change |
|---|---:|---:|---:|
| ID+access token encoding | 6.582 ms/op | 6.055 ms/op | about 8.0% less time |
| Encoding allocation bytes | 108,622 B/op | 71,463 B/op | about 34.2% less |
| Encoding allocations | 334/op | 176/op | about 47.3% fewer |
| UserInfo HTTP handler | 368.474 µs/op | 192.634 µs/op | about 47.7% less time |
| UserInfo allocation bytes | 99,055 B/op | 58,490 B/op | about 41.0% less |
| UserInfo allocations | 326/op | 515/op | about 58.0% MORE |

The higher UserInfo allocation count is a real tradeoff from stricter streaming
JSON member validation, not omitted evidence. Total allocated bytes and time both
fell, but this is a remaining optimization opportunity. Three samples do not
establish a general throughput guarantee. The token benchmark is dominated by
RSA signing, so eliminating parsing helps less than eliminating UserInfo's
second verification. Logs: [before](validation/v0.9.0/benchmark-before.log) and
[after](validation/v0.9.0/benchmark-after.log). Reproduction:

```sh
go test ./internal/oidc -run '^$' \
  -bench 'Benchmark(TokenEncoding|UserInfoHTTP)$' -benchmem -benchtime=1s -count=3
```

Run the benchmark with the production compiler too. A database load test must
measure concurrent sessions, same-family contention, administrative revocation
latency, SQL query plans, key rotation, cleanup backlog and database growth before
claiming deployment capacity.

## Qualification and upgrade gates

1. Run `make deps && make verify` on Linux with the actual pinned Go modules and
   a disposable PostgreSQL database. The integration test must not be skipped.
2. Run migration 005 against a restored pre-upgrade database and verify users,
   keys, offline families, exact grant rollback and reserved-scope preflight.
3. Test the actual BDC callback plus a genuinely independent OIDC RP/conformance
   runner, production HTTPS/cookies/proxies, MFA, logout and secret rotation.
4. Exercise native rc.d/systemd installation and runtime-role separation, and
   perform a matched database/master-key restore drill.

The externally reported v0.9.0 OpenBSD/database/live-provider pass closes the
initial real-database execution gap. The Linux/race run, restored-database upgrade,
actual BDC/conformance/proxy/MFA tests, native service operation, negative runtime
privilege checks and restore drill above remain open. See VALIDATION.md rather
than interpreting the original source-delivery limitations as the latest status.

## Primary protocol references

- [OIDC Core 1.0, errata 2](https://openid.net/specs/openid-connect-core-1_0.html),
  particularly authorization transport, claims, ACR and offline-access sections.
- [OAuth 2.0](https://www.rfc-editor.org/rfc/rfc6749.html), client authentication
  and code/refresh behavior.
- [PKCE](https://www.rfc-editor.org/rfc/rfc7636.html), including the fixed S256 vector.
- [OAuth security BCP](https://www.rfc-editor.org/rfc/rfc9700.html), grant binding
  and replay considerations.
- [Token revocation](https://www.rfc-editor.org/rfc/rfc7009.html), nondisclosing
  success versus unavailable-service behavior.
- [JWT access-token profile](https://www.rfc-editor.org/rfc/rfc9068.html), explicit
  access-token typing. No separate resource-server registration is claimed.
- [RP-Initiated Logout](https://openid.net/specs/openid-connect-rpinitiated-1_0.html).
- [Unmet Authentication Requirements](https://openid.net/specs/openid-connect-unmet-authentication-requirements-1_0-final.html).
- [PostgreSQL explicit locking](https://www.postgresql.org/docs/current/explicit-locking.html),
  shared/exclusive advisory lock behavior. Our application lock protocol is a
  design choice, not a standard requirement.
