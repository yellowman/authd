# v0.8 validation record

This is a source-delivery validation record, not a production signoff or an OIDC
conformance certificate. No replacement pgx or x/crypto module is used by the
reported checks.

## Executed in the authoring environment

The installed toolchain is Go 1.23.2. The production module requires Go 1.25 and
its selected pgx/x/crypto modules are not available for download in this sandbox.
Within that boundary, the following checks passed on the current v0.8 tree:

| Check | Result and scope |
|---|---|
| `gofmt` cleanliness | PASS for all `cmd`/`internal` Go source |
| `git diff --check` | PASS |
| shell syntax | PASS for `scripts/*.sh` |
| `./scripts/check-offline.sh` | PASS |
| race detector | PASS for config, cryptoutil, identity, db, oidc, requestid, totp, web and standalone password-encoding parser |
| `go vet` | PASS for those same real stdlib-only packages |
| OIDC HTTP/service suite | PASS using real RSA/JWT/JWK/PKCE/TOTP-independent production code and an in-memory protocol store |
| OIDC SQL integration source | Typechecks together with the existing real-PostgreSQL integration body; not executed |
| embedded HTML templates | PASS parsing/rendering tests, including the OIDC-client administration and one-time-secret templates |
| missing-database gate | PASS negative witness: `make integration` without explicit disposable-DB consent exits nonzero (make status 2) |

The OIDC regression suite now exercises, among other cases:

- discovery metadata required by the current bdcmaps OIDC client;
- Authorization Code + S256 PKCE;
- opaque server-side authorization continuations;
- `state`, `nonce`, and RFC 9207 `iss` response handling;
- current-bdcmaps `client_secret_post` plus `client_secret_basic`;
- public-client `none` plus registered-origin-only CORS preflight/token/UserInfo coverage;
- RS256 ID/access-token issuance and UserInfo role/group projection;
- one-use authorization codes;
- wrong-PKCE failure without consuming an otherwise valid code;
- opaque refresh-token rotation and whole-family replay revocation;
- persistent refresh-scope narrowing and failed broadening without consumption;
- malformed/ambiguous client authentication failure;
- RP logout with exact registered post-logout redirects;
- bare and cross-subject logout requests cannot terminate the current provider session;
- signed expired ID-token hints remain accepted for current-subject RP logout;
- discovery advertises `acr_values_supported` and `acr`/`sid`;
- MFA `acr_values` requests force step-up rather than issuing a weaker context;
- unsupported ACR requirements return `unmet_authentication_requirements` to an already-trusted redirect;
- ID Tokens emit actual `acr`/`amr` and provider-session `sid`; refresh preserves the same `sid`;
- a valid same-subject logout hint for a different `sid` cannot terminate the current provider session;
- duplicate logout security-parameter rejection before session destruction;
- bounded JWT input;
- signing-key rotation while old public verification remains available;
- RFC 7009 request rejection when the required token is absent.


The v0.7 lifecycle/deployment regression source additionally covers:

- final-administrator protection on user and role deletion;
- soft user deletion removing primary credential, role grants, sessions and refresh capability;
- reference-safe permission rename/delete;
- MFA recovery-code replacement and administrative authenticator reset;
- destructive OIDC-client deletion and grant-state cascades;
- admin signing-key listing without private ciphertext and audited key rotation;
- expiration cleanup for sessions, pending enrollment, bootstrap state, grant state and bounded audit retention;
- self-service profile routing plus fresh-session database enforcement source;
- trusted-proxy source resolution, including untrusted-peer spoof rejection and malformed-chain fail-closed behavior.
- stale user, role, permission, and OIDC-client edit versions rejected by the PostgreSQL transaction source.
- embedded migration-manifest ordering plus real-PostgreSQL source coverage rejecting altered migration history.
- safe internal HTTP failure correlation: request references and bounded error classes without raw secret/DSN leakage.

The real-PostgreSQL integration source additionally covers durable authorization
requests, one-use code consumption, refresh rotation/reuse revocation, token audit
events, refusal to grant `system.admin` as an application permission, and signing
key rotation with retired private-key ciphertext destruction plus key-lifecycle
audit events.

`./scripts/check-offline.sh` creates a temporary dependency-free modfile outside
the repository. It does not alter `go.mod`, add a `replace`, provide a fake pgx or
Argon2 implementation, or build a substitute executable. The integration source
is typechecked without the separate pgx driver-registration test file; therefore
that step proves Go-level interface/type coherence, not SQL execution.

## Explicitly blocked / not qualified here

A direct full-suite attempt with the installed compiler fails before compilation:

```text
go: go.mod requires go >= 1.25.0 (running go 1.23.2; GOTOOLCHAIN=local)
```

PostgreSQL and a usable container runtime are also unavailable in this authoring
environment. Therefore the following have **not** passed here:

- full executable build using Go 1.25 and the real pgx/x/crypto modules;
- the actual Argon2id KDF round trip;
- migrations 001/002/003/004 executed against PostgreSQL;
- PostgreSQL transaction/concurrency assertions in the integration build tag;
- the live daemon against a real PostgreSQL database;
- the actual private `yellowman/bdcmaps` application logging into authd;
- an independent OIDC/OAuth conformance/interoperability suite;
- current client-admin browser interaction against the live daemon;
- backup/restore, master-key rotation, HA or production deployment qualification.

The prior v0.4 Chromium fixture review covered the base Liminal-derived login,
account and administration layout. v0.8's lifecycle/Clients/Keys/ACR branches is covered
by template rendering tests here, but it has not been re-reviewed in a live
browser/daemon environment and is not claimed as such.

## Required full gate

On a supported networked development machine:

```sh
make deps
make build
make dev-db
export AUTHD_TEST_DISPOSABLE=1
export AUTHD_TEST_DATABASE_URL='postgres://authd:authd-dev-only@127.0.0.1:55432/authd?sslmode=disable'
make verify
```

Then run `docs/BDCMAPS_INTEGRATION.md` against an actual bdcmaps instance. The
first production candidate should not be cut until both the real database gate
and the relying-party interoperability path pass.
