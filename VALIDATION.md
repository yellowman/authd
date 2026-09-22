# v0.8.1 validation record

## External OpenBSD/PostgreSQL qualification — 2026-09-22

An independent test copy was built and exercised on OpenBSD/amd64 with Go 1.27 and a disposable real PostgreSQL schema. The test found two repository defects that are fixed in v0.8.1: the integration helper had a stale hard-coded migration count after migration 004, and PostgreSQL required explicit `timestamptz` casts for the two parameters passed to `LEAST` when inserting refresh-token idle expiry. The migration-count duplication was removed rather than changed from 3 to 4 because `CheckSchema` already validates the exact embedded manifest.

Exercised successfully after those fixes:

- OpenBSD/amd64 build with Go 1.27;
- unit tests for identity, password parsing, crypto, OIDC, web, TOTP, configuration, and database code;
- `go vet` and formatting checks;
- real PostgreSQL migrations/schema validation and identity/user/role/permission lifecycle;
- sessions, bootstrap, cleanup, MFA recovery state, OIDC client registration, authorization continuations and one-use codes;
- refresh rotation/replay/revocation, signing-key rotation, and client deletion cascades;
- live authd process with PostgreSQL: bootstrap CLI, setup/login forms, admin client registration, discovery, login redirect, Authorization Code + PKCE, `client_secret_post`, ID-token claims, UserInfo, and refresh-token rotation.

Not exercised by that run:

- actual bdcmaps callback or the deployment at `maps.ykwc.com`;
- HTTPS/nginx/certificates/secure production cookies/DNS/reverse-proxy headers;
- non-loopback production issuer;
- PostgreSQL runtime-role separation, TLS, backup/restore/failover;
- OpenBSD `rc.d` installation/boot;
- live MFA/TOTP enrollment/login;
- live public-client or `client_secret_basic` flows (provider tests only);
- external OIDC conformance testing;
- race detector (`-race` is unsupported on OpenBSD/amd64);
- master-key persistence/rotation and multi-instance behavior;
- production bdcmaps schema/data.

The external run generated the dependency lock state now committed as `go.sum`. The module minimum is Go 1.26 because `golang.org/x/crypto v0.57.0` declares Go 1.26.


This is a source-delivery validation record, not a production signoff or an OIDC
conformance certificate. No replacement pgx or x/crypto module is used by the
reported checks.

## Executed in the authoring environment

The authoring container toolchain is Go 1.23.2. The production module requires Go 1.26 and
its selected pgx/x/crypto modules are not available for download in this sandbox.
Within that boundary, the following checks passed on the current v0.8.1 tree:

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
go: go.mod requires go >= 1.26.0 (running go 1.23.2; GOTOOLCHAIN=local)
```

PostgreSQL and a usable container runtime are also unavailable in this authoring
environment. Therefore the following have **not** passed here:

- full executable build using Go 1.26+ and the real pgx/x/crypto modules in this authoring container;
- the actual Argon2id KDF round trip;
- migrations 001/002/003/004 executed against PostgreSQL in this authoring container;
- PostgreSQL transaction/concurrency assertions in the integration build tag in this authoring container;
- the live daemon against a real PostgreSQL database in this authoring container;
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
