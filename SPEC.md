# authd — Identity, OIDC, and Access Service

## Specification (current implementation; historical sections retain version labels)

Status: binding product design, extended with groups and Dynamic Client Registration. See `docs/APP_CREATOR_OIDC.md` for the current registration wire contract, `docs/OIDC_AUDIT.md` for the earlier protocol audit, and `VALIDATION.md` for dated evidence. This is not an OpenID certification or production signoff.

## 1. Purpose

`authd` is a small, self-contained identity and access service for an organization that builds multiple internal and operational applications and does not want every application to reinvent users, passwords, roles, permissions, MFA, and login flows.

The primary product is:

```text
local users + local credentials + groups + roles + permissions
                         │
                         └── OIDC/OAuth provider
                                  │
                                  └── many web applications
```

The first client is `yellowman/bdcmaps`, which already contains an OIDC client.

The identity model is protocol-neutral by design so future adapters such as RADIUS or TACACS+ can authenticate and authorize against the same users, roles, and permissions without creating a second identity database.

The server shall provide:

- OpenID Connect authentication;
- OAuth 2.0 Authorization Code flow;
- PKCE for every client;
- local username/password accounts;
- optional local TOTP MFA;
- local groups, roles and permissions;
- OIDC/OAuth clients configured through the web UI or Dynamic Client Registration;
- short-lived signed JWT access tokens;
- rotating opaque refresh tokens;
- provider session management;
- RP-initiated logout;
- a local web UI for users, groups, roles, permissions, clients, sessions, audit, and keys;
- a self-service account page;
- an explicit internal boundary for future protocol frontends such as RADIUS and TACACS+.

The complete v1 system runs as one Go process backed by PostgreSQL. It requires no Redis, message bus, frontend build system, LDAP directory, or external policy service.

---

# 2. Product Principle

The reason for `authd` is not merely to centralize login. It is to make identity and authorization reusable across applications.

A new application should normally need only:

```text
1. Register OIDC client.
2. Define application permissions.
3. Allow those permissions for the client.
4. Add the permissions to existing or new roles.
5. Use OIDC claims/scopes in the application.
```

It should not need to create:

```text
users table
password reset flow
MFA enrollment
role editor
permission editor
session inventory
OIDC client logic beyond normal RP integration
audit UI for identity changes
```

---

# 3. Explicit Non-Goals for v1

Version 1 MUST NOT attempt to become a general enterprise IAM platform.

Out of scope unless promoted by a concrete requirement:

- LDAP;
- Active Directory;
- NIS/YP;
- external user directories;
- SAML;
- SCIM;
- social login;
- upstream OIDC identity brokering;
- OIDC federation;
- directory synchronization;
- multi-tenancy;
- organizations;
- nested groups;
- nested roles;
- role inheritance;
- negative/deny permissions;
- ABAC;
- Rego/OPA;
- CEL or another policy language;
- YAML-defined users;
- YAML-defined roles;
- YAML-defined authorization rules;
- OAuth implicit flow;
- OAuth hybrid flow;
- Resource Owner Password Credentials grant;
- token exchange;
- CAPTCHA;
- SMS authentication;
- WebAuthn/passkeys in the first implementation;
- Redis;
- Kafka;
- a distributed session cache;
- microservices;
- a generic plugin framework.

RADIUS and TACACS+ are planned extension directions, but they are not v1 completion requirements. When implemented, they are protocol adapters over the same identity core, not separate products with separate users or authorization models.

---

# 4. Implementation Shape

Recommended and selected implementation:

```text
Go
PostgreSQL
pgx/v5
net/http
html/template
embedded HTML/CSS/JS
Argon2id via golang.org/x/crypto
```

One repository.

One normal server executable:

```text
authd
```

The repository MUST avoid framework dependencies when the standard library already supplies the needed behavior.

Initial runtime Go dependencies are limited to:

```text
github.com/jackc/pgx/v5
golang.org/x/crypto
```

Additional dependencies require a specific documented reason.

## 4.1 Cryptographic implementation boundary

`authd` MUST NOT implement cryptographic primitives. RSA operations, SHA/HMAC, symmetric encryption, secure randomness, Argon2id, and constant-time comparison come from the Go standard library or `golang.org/x/crypto`.

Narrow protocol encodings MAY be implemented locally when doing so avoids a large dependency and the implementation is small and testable. Examples include JWT compact serialization, JWK JSON representation, PKCE encoding, and RFC 6238 TOTP calculation. Such code MUST use library cryptographic primitives exclusively and MUST have specification test vectors and/or independent interoperability coverage.

A dependency is preferred over local code when the alternative would require implementing substantial security-critical protocol machinery rather than merely encoding data around standard cryptographic primitives.

---

# 5. Authorization Model

The authorization model is deliberately simple.

```text
User → direct Roles ────────────────────────┐
    └→ Groups → group-granted Roles ────────┴→ effective Roles → Permissions
```

A user's effective permissions are:

```text
effective_permissions(user) =
    UNION(permissions of every direct or group-derived role)
```

There are no denies.

There is no precedence.

There is no role inheritance or nesting; group membership is a flat additional
source of assigned roles.

There are no nested roles or groups.

Permissions MUST NOT be assigned directly to users in v1.

The core authorization concepts are:

```text
users
groups
roles
permissions
```

Administrative groups are real user-to-role assignments. Separately, the optional
OIDC `groups` claim remains a compatibility alias containing **effective role
names**, not the names of administrative groups.

Authentication and authorization are distinct. An enabled user with a valid credential and zero roles MAY authenticate to an OIDC client requesting only identity scopes. A zero-role user has zero application permissions and cannot access `system.admin`; role membership is not a prerequisite for proving identity.

---

# 6. Permission Names

Permissions are administrator-created strings.

Recommended naming convention:

```text
<application>.<resource>.<action>
```

Examples:

```text
bdcmaps.network.read
bdcmaps.plan.write
bdcmaps.reports.export
bdcmaps.admin

liminal.models.read
liminal.models.execute

billing.invoices.read
billing.invoices.write
```

Permission names MUST match:

```text
[a-z0-9][a-z0-9._:-]*
```

Permission names are globally unique. The identity/control scope names `openid`, `profile`, `email`, `groups`, `roles`, and `offline_access` are reserved and cannot be application permissions.

Reserved provider permission:

```text
system.admin
```

Possession of `system.admin` permits access to provider administration operations.

Applications SHOULD NOT be granted `system.admin` as an application scope. It is a provider-administration permission.

---

# 7. Roles

Examples:

```text
viewer
operator
support
network-admin
billing-admin
system-admin
```

A role contains:

```text
id
name
description
permissions[]
created_at
updated_at
```

Built-in role:

```text
system-admin
```

contains:

```text
system.admin
```

`system-admin` cannot be deleted.

Role names are globally unique and are the strings exposed through `groups` and/or `roles` claims when those claims are requested.

Applications SHOULD authorize stable operations against permissions/scopes rather than hard-coding broad role names whenever practical.

---

# 8. Users

A user record contains conceptually:

```text
id                    UUID
username              string
display_name          string
email                 string | null
email_verified        bool
enabled               bool
force_password_change bool
created_at
updated_at
last_login_at
deleted_at            nullable
```

`id` is immutable.

OIDC `sub` is derived from this immutable identifier.

Changing username or email MUST NOT change `sub`.

Deleted IDs MUST never be reused.

Credentials are separate records owned by the identity core rather than fields that define the user object. A user MAY exist without a primary password credential, but local password authentication requires one. This separation is intentional so future protocol-specific credentials can be added without making the canonical user record or primary SSO password protocol-specific.

## 8.1 Username

Username comparison is case-insensitive.

The original normalized display form may be retained.

Usernames are unique among non-deleted users.

### 8.1.1 Email verification state

`email_verified` defaults to `false`. Version 1 has no email-delivered verification workflow. An administrator MAY explicitly assert an email as verified; absent that assertion, `authd` MUST NOT emit `email_verified=true`.

Changing a user's email address to a different normalized value MUST clear `email_verified` to `false`. Clearing the email removes both `email` and `email_verified` from claims that depend on the `email` scope.

## 8.2 Primary Password Credential

The canonical local password credential uses Argon2id and is stored separately from the `users` row.

The encoded password record contains the parameters needed for verification and future upgrades.

Initial target parameters:

```text
memory      64 MiB
iterations  3
parallelism 2 unless host sizing justifies another value
salt        16 bytes or more
output      32 bytes or more
```

Parameters are configurable in code/deployment defaults, not per-user policy UI.

Successful login SHOULD transparently replace a hash whose parameters are weaker than the current configured parameters.

Minimum accepted password length:

```text
12 characters
```

Maximum accepted password length MUST be at least:

```text
128 characters
```

There are no arbitrary uppercase/lowercase/symbol composition rules.

## 8.3 Password Reset

There is no email password-reset service in v1.

An administrator may:

```text
Set Password
Force Password Change
```

A logged-in user may change their own password after supplying their current password.

Changing a password MUST revoke all refresh-token families for that user.

An administrator password reset defaults to revoking provider sessions as well.

Disabling a user MUST revoke all provider sessions and refresh-token families automatically.

## 8.4 Credential capabilities and legacy AAA methods

Argon2id is the canonical verifier for the primary password. It is a one-way verifier, not recoverable password material. Protocol adapters MUST declare what credential material each authentication method requires.

Methods that deliver the submitted password to `authd` MAY verify it directly against the canonical Argon2id credential. This includes local web login and RADIUS PAP after the RADIUS server has recovered the submitted `User-Password`. EAP methods that intentionally deliver a password inside a protected tunnel may use the same verifier when their protocol implementation is explicitly supported.

Methods that require computation from the original password cannot be satisfied from an Argon2id verifier. Classic CHAP is therefore unsupported by the canonical password credential. Methods such as MS-CHAPv2 require NT-hash/password-equivalent material and are likewise unsupported by default.

`authd` MUST NOT silently generate or retain weaker password-equivalent material for every user merely to advertise protocol compatibility. If a concrete deployment requires additional credential material, it MUST be modeled as an explicit credential type with all of the following:

```text
explicit enrollment
explicit supported protocol/authentication method
documented storage representation
administrative visibility
audit events
independent revocation
security warning when weaker than the canonical Argon2id credential
```

Where practical, a separate network-access credential SHOULD be enrolled rather than making the user's primary SSO password recoverable or retaining an NT hash for it. Reversible protocol-specific secrets MUST be encrypted under deployment master-key material and MUST never replace the canonical Argon2id verifier.

---

# 9. MFA

Version 1 supports optional TOTP.

WebAuthn/passkeys are deferred.

Each user may enroll one TOTP authenticator in v1.

Enrollment:

```text
1. Generate cryptographically random TOTP secret.
2. Display otpauth URI/QR and textual secret.
3. Require a valid TOTP response.
4. Generate recovery codes.
5. Mark MFA enabled only after successful confirmation.
```

Recovery codes:

- are random;
- are single-use;
- are stored only as hashes;
- are displayed once;
- may be regenerated.

TOTP secrets require reversible storage and therefore MUST be encrypted at rest under a deployment master key held outside PostgreSQL.

The provider MUST retain the most recently accepted TOTP counter and reject a
counter that has already been accepted. Counter/recovery-code consumption and
session insertion MUST share a transaction, so failure cannot leave a consumed
factor without the corresponding committed session. Enrollment is unconfirmed,
encrypted, session-bound state expiring after ten minutes. Enrollment/removal
requires the current password and a sign-in within the preceding ten minutes.
Removal also requires a session authenticated with OTP or a recovery code.
Credential changes revoke provider sessions and refresh-token families.

Authentication Method References use at least:

```text
pwd
otp
recovery
```

An MFA login may produce:

```json
{
  "amr": ["pwd", "otp"]
}
```

Clients have:

```text
require_mfa: true | false
```

If a client requires MFA and the existing provider session is password-only, authorization performs MFA step-up before issuing a code.

---

# 10. OAuth Scopes and Application Permissions

Application permissions double as OAuth scopes.

Example:

```text
scope=openid profile email groups bdcmaps.network.read bdcmaps.reports.export
```

Two classes of scopes exist.

Identity/control scopes:

```text
openid
profile
email
groups
roles
offline_access
```

Application permission scopes:

```text
bdcmaps.network.read
bdcmaps.reports.export
...
```

Each registered client has an explicit allow-list of application permission scopes.

For an authorization request, the provider validates:

```text
requested scope
    │
    ├── recognized identity/control scope?
    │
    ├── application scope allowed for this client?
    │
    └── application scope possessed by this user?
```

If the client requests an unknown or disallowed scope:

```text
error=invalid_scope
```

If a manually configured client requests an allowed application permission the
user does not possess, authorization fails. Dynamically registered clients
instead receive a narrowed grant containing only requested permissions the user
holds. In both cases the token response reports the actual grant; clients MUST
check it rather than infer authorization from requested scope.

The provider MUST NOT grant an application scope that the client did not request.

## 10.1 groups and roles

`groups` and `roles` are claim-request scopes over the same role membership. Neither claim is released merely because a user has roles. The corresponding scope MUST be both requested by the client and explicitly allowed for that client.

If `groups` is requested and allowed:

```json
{
  "groups": ["bdcmaps-admin", "network-operator"]
}
```

If `roles` is requested and allowed:

```json
{
  "roles": ["bdcmaps-admin", "network-operator"]
}
```

A client may request either or both.

If both scopes are requested and allowed, both claims MAY be emitted and MUST represent the same current effective role membership, including group-derived roles. Client input can never inject role names into either claim.

This compatibility alias is intentional for older role-name clients. New clients
SHOULD authorize operations with granted access-token scopes. Claim values are
not the names of authd's administrative groups.

---

# 11. OIDC/OAuth Clients

Clients are created manually through the administration interface or with
discovery-advertised Dynamic Client Registration using a one-use,
prefix-limited initial token. The standard registration `scope` metadata is
interpreted by authd as an application permission catalog; optional
`authd_role_templates` and `authd_group_templates` are authd-specific and do
not assign users. Dynamic clients currently are confidential code/PKCE clients
without refresh tokens. See `docs/APP_CREATOR_OIDC.md` for the precise protocol
and management limitations. OIDC/OAuth client registrations are not a
polymorphic registry for future RADIUS/TACACS+ peers.

A client record contains:

```text
id
client_id
name
type
client_secret_hash
enabled
dynamic_registration
redirect_uris[]
post_logout_redirect_uris[]
allowed_identity_scopes[]
allowed_permissions[]
require_mfa
access_token_ttl
refresh_token_enabled
created_at
updated_at
```

Client type:

```text
public
confidential
```

## 11.1 Public Clients

Public clients have no client secret.

Token endpoint auth method:

```text
none
```

PKCE S256 is mandatory.

## 11.2 Confidential Clients

Confidential clients receive a cryptographically random secret with at least 256 bits of entropy.

The plaintext secret is shown only when created or rotated.

The database stores only a cryptographic hash.

Supported token endpoint authentication methods:

```text
client_secret_basic
client_secret_post
```

`client_secret_basic` is preferred for new clients.

`client_secret_post` is retained for compatibility with clients that send their
secret in the token request body; current dynamic BDC registration uses
`client_secret_basic`.

Confidential clients MUST also use PKCE S256.

## 11.3 Redirect URIs

Every redirect URI is explicitly registered.

Matching uses exact string comparison.

Wildcards are forbidden.

Invalid examples:

```text
https://example.com/*
https://*.example.com/callback
https://example.com/callback?*
```

These are separate entries:

```text
https://example.com/oauth/callback
https://example.com/oauth/callback2
```

The same exact-match rule applies to post-logout redirect URIs.

Loopback redirect handling for native clients may be added later if a real native client is introduced; it is not silently generalized in v1.

## 11.4 Relying-party integration contract

Every RP MUST key an authd identity by the pair:

```text
(issuer, sub)
```

Email, username, `preferred_username`, `groups`, `roles`, display name, and other mutable claims MUST NOT be used as the durable identity key. Existing local accounts MUST NOT be silently linked to an authd subject merely because an email address matches. Linking an existing account requires an explicit administrator migration or an authenticated account-linking ceremony. After linking, `(issuer, sub)` is authoritative and email is profile data.

Authentication by authd establishes the user's external identity, authentication context, and any explicitly requested authd-managed application-wide entitlements. It does not, by itself, establish tenant, organization, customer, PBX, extension, project, room, case, boundary, workspace, or other application-local membership. Such authority remains the responsibility of the RP unless a specific integration contract explicitly says otherwise.

Three RP integration modes are supported as design patterns over the same OIDC protocol:

```text
identity-only
    authd proves the person; RP owns all authorization

hybrid
    authd proves identity and selected application-wide entitlements;
    RP owns tenant/resource membership and domain authorization

authd-authorized
    authd roles/permissions are sufficient for the RP's authorization model
```

An RP MAY retain application-local human identities, device identities, API keys, service credentials, PBX-local identities, extension credentials, or other principals that are outside authd. OIDC adoption does not require every credential-bearing principal in an application to become an authd user.

`authd` is an organizational identity provider, not a mandatory identity authority for every application or customer. A relying party MAY trust another OIDC or SAML identity provider directly where its deployment, tenant, or customer model requires it. `authd` MUST NOT require external identities to be proxied or federated through authd merely to achieve a uniform issuer. Provider selection, tenant-to-provider routing, and customer federation belong to the relying application or its gateway unless upstream federation becomes an explicit authd product requirement.

This is particularly important for products such as Evident, where one common gateway serves many target applications with divergent customer populations and can bind a customer deployment directly to that customer's IdP while retaining local tenant/boundary/purpose authority.

---

# 12. Supported Protocol Flow

Interactive login supports:

```text
Authorization Code + PKCE S256
```

Supported authorization response type:

```text
code
```

The provider MUST NOT implement:

```text
response_type=token
response_type=id_token
hybrid response types
```

Supported token grant types:

```text
authorization_code
refresh_token
```

---

# 13. Public HTTP Endpoints

Required OIDC/OAuth endpoints:

```text
GET  /.well-known/openid-configuration
GET  /.well-known/oauth-authorization-server
GET  /authorize
POST /authorize
POST /token
GET  /jwks.json
GET  /userinfo
POST /userinfo
POST /revoke
GET  /logout
POST /logout
```

Provider UI endpoints:

```text
GET  /login
POST /login
GET  /login/mfa
POST /login/mfa
GET  /account
GET  /admin/
GET  /healthz
```

Additional UI routes live beneath `/account/` and `/admin/`. Browser-only OIDC continuations use `GET /authorize/resume?flow=...`; consent uses `POST /authorize/consent`. The standard `request` parameter is never an internal handle.

---

# 14. Discovery

`/.well-known/openid-configuration` advertises only implemented behavior.

Required fields include:

```json
{
  "issuer": "https://auth.example.com",
  "authorization_endpoint": "https://auth.example.com/authorize",
  "token_endpoint": "https://auth.example.com/token",
  "userinfo_endpoint": "https://auth.example.com/userinfo",
  "jwks_uri": "https://auth.example.com/jwks.json",
  "revocation_endpoint": "https://auth.example.com/revoke",
  "end_session_endpoint": "https://auth.example.com/logout",
  "response_types_supported": ["code"],
  "response_modes_supported": ["query"],
  "claim_types_supported": ["normal"],
  "claims_parameter_supported": true,
  "request_parameter_supported": false,
  "request_uri_parameter_supported": false,
  "grant_types_supported": ["authorization_code", "refresh_token"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["RS256"],
  "token_endpoint_auth_methods_supported": [
    "client_secret_basic",
    "client_secret_post",
    "none"
  ],
  "code_challenge_methods_supported": ["S256"],
  "scopes_supported": [
    "openid",
    "profile",
    "email",
    "groups",
    "roles",
    "offline_access"
  ],
  "claims_supported": [
    "sub",
    "name",
    "preferred_username",
    "email",
    "email_verified",
    "groups",
    "roles",
    "auth_time",
    "acr",
    "amr",
    "sid",
    "at_hash"
  ],
  "acr_values_supported": [
    "urn:authd:acr:pwd",
    "urn:authd:acr:mfa"
  ],
  "authorization_response_iss_parameter_supported": true
}
```

Configured application permissions MAY additionally appear in `scopes_supported`.

The OAuth authorization-server metadata endpoint may use the same underlying metadata builder with the correct well-known path semantics.

---

# 15. Authorization Endpoint

Accept GET query serialization and POST `application/x-www-form-urlencoded`
serialization. The only response type is `code`; only the default/query response
mode is supported. Validate the client and exact registered redirect before
sending any response to an RP. Malformed/ambiguous redirect or client parameters
produce a local error, never a redirect to untrusted input.

Example:

```text
/authorize?response_type=code&client_id=bdcmaps&redirect_uri=...&
scope=openid%20profile%20email%20groups&state=...&nonce=...&
code_challenge=...&code_challenge_method=S256
```

Reject duplicate parameters, malformed percent encoding, invalid PKCE syntax,
unsupported response modes, invalid scope grammar, and oversized input. Unknown
ordinary optional parameters are ignored. `request`, `request_uri`, and
`registration` are reserved standard parameters: because their features are not
implemented, return the corresponding `request_not_supported`,
`request_uri_not_supported`, or `registration_not_supported` error.

## 15.1 Browser transaction

An authorization transaction records client, exact redirect, scopes, state,
nonce, S256 challenge, supported claim selectors, required/preferred ACR,
subject constraints, original `max_age`, prompts, creation and expiry. It is
bound to the hash of an independent random HttpOnly browser cookie. Possession
of the transaction handle alone MUST NOT resume or approve it in another browser.
Transactions expire after ten minutes. Consent additionally binds the current
provider-session ID; changing the authenticated account invalidates that consent.

The transaction handle travels only on the internal resume route as `flow`.
Code issuance consumes the transaction once and binds the resulting code to the
user, provider `sid`, authentication time/method/context, claims and scopes.
Codes are random, hash-only, single-use and valid for at most 60 seconds.
Success and redirectable errors echo `state` unchanged and include issuer `iss`.

## 15.2 Authentication and prompts

Support `none`, `login`, `consent`, and `select_account`. `none` cannot be
combined with another prompt. `select_account` currently uses an explicit
fresh username/password ceremony, not a remembered multi-account picker.
`login` and `max_age=0` require a ceremony after the transaction began. Positive
`max_age` is measured at authentication completion/code issuance, not converted
into a threshold frozen at request creation. Consent time cannot make an old
password proof fresh. NumericDate claims have whole-second resolution.

`prompt=none` never presents a form: missing authentication/required step-up
returns `login_required`. `login_hint` may prefill a username but never proves
identity. A supplied ID-token hint must be signed by this issuer for this client;
its subject constrains which account may satisfy the transaction. A supported
`claims.id_token.sub.value` or `.values` constraint is also enforced.

## 15.3 Authentication context — preference versus requirement

Supported contexts are `urn:authd:acr:pwd` and `urn:authd:acr:mfa`. MFA here means
password plus enrolled TOTP or a single-use recovery code; it is not a claim of
phishing resistance or a standardized assurance level.

`acr_values` is an ordered **preference**, not a mandatory constraint. Authd
attempts a supported preference when possible; an unknown/unavailable voluntary
context does not by itself fail authentication. A nonessential `acr` claim
request has the same voluntary character. RPs MUST inspect the returned `acr`.
The earlier v0.8 rule treating any requested ACR as mandatory was incorrect.

`require_mfa=true` is a mandatory client policy floor. For mandatory per-operation
MFA, send an essential ACR claim selector, for example the URL-encoded JSON:

```json
{"id_token":{"acr":{"essential":true,"value":"urn:authd:acr:mfa"}}}
```

Combine that with `max_age=300` to require recent authentication. Authd refuses an
unachievable essential ACR using `unmet_authentication_requirements`; it never
lowers the client's MFA floor. Essential `values` are alternatives, considered
in order among supported contexts consistent with that floor. An essential ACR
without a value constraint asks for an available ACR, not implicitly for MFA.
When both syntaxes are supplied, an essential claim wins; otherwise a supported
voluntary claim preference precedes `acr_values`. An essential `pwd` can be
satisfied by a stronger ceremony, but the returned exact ACR names that selected
context; `amr` still records the actual factors. Token refresh does not renew
`auth_time` or turn an old proof into fresh MFA.

## 15.4 Normal claim selection

Support bounded `claims` JSON with `id_token` and `userinfo` destinations. A
selector is null or an object; duplicate JSON members at any depth are refused.
Supported selectable profile fields are `name`, `preferred_username`, `email`,
and `email_verified`, plus the special authentication selectors above. Their
release requires the corresponding profile/email capability to be allowed for
the client, but selecting one field does not implicitly grant an entire scope.
Each destination is independent. `value`/`values` constraints filter values;
normal unavailable/nonmatching fields are omitted, never invented. Marking an
ordinary profile field essential is not an authorization error. Subject and
essential ACR constraints have the special semantics described above.

Unknown normal claims are omitted. No arbitrary tenant/permission claim mapping,
claim expression language, aggregated/distributed claims, or language variants
are implemented. `groups`/`roles` still require their explicitly requested and
allowed scopes. Claim selectors persist through code exchange and refresh and
are rechecked against current client claim-release policy.

## 15.5 Consent and offline access

`prompt=consent` displays the client, requested scopes and additionally selected
identity claims. Approval/denial uses a CSRF token bound to transaction, browser,
and provider session. Denial consumes the pending request and returns
`access_denied` without issuing a code. Normal first-party online access may use
administrator-approved client policy without a consent page.

This version has no blanket prior-consent assumption for offline access. Issue a
refresh family only for a client permitting refresh, an OIDC request containing
`offline_access`, and completed explicit `prompt=consent`. Without these
conditions ignore `offline_access`, report actual granted scopes, and issue no
refresh token. Refuse a request with no effective scopes remaining.

---

# 16. Token Endpoint

Accept only form-encoded POST, with `authorization_code` or `refresh_token`.
Confidential clients may use Basic or body authentication; public clients use
`none` and mandatory S256 PKCE. Basic user/password fields follow OAuth form
percent-decoding. Reject multiple authentication mechanisms, including an empty
second `client_secret`, repeated parameters, mixed query/body credentials, and
oversized bodies.

A code exchange supplies `code`, `redirect_uri`, `client_id` as applicable, and
`code_verifier`. Validate current client proof, exact code client/redirect, S256,
expiry, unconsumed state, live originating provider session, enabled user, current
scope/claim permissions and client MFA policy.

## 16.1 One durable issuance boundary

The code row or refresh-family row is locked before grant redemption. Verify
current client-secret state again inside the transaction; an outside-of-transaction
secret check cannot survive intervening rotation. Under the same authority gate,
select the active signing key, prepare and sign the bounded response, consume the
old credential, create the replacement/family, and insert the audit event. Return
credentials only after COMMIT succeeds. Signing, storage and audit failure before
commit rolls back the whole operation. No KDF or external network call occurs
inside a grant transaction.

A correctly bound code replay is rejected and revokes its linked refresh family;
wrong-client/wrong-verifier attempts cannot revoke the legitimate family. Keep
replay tombstones while their issued family can still be used. JWT access tokens
remain independently valid until their short expiry.

## 16.2 Error and transport boundary

Invalid credentials/grants/scopes use the appropriate OAuth error. Dependency
failure is not evidence of invalid credentials: return HTTP 503 `server_error`
with a bounded retry indication, no raw SQL/driver/secret material, and internal
request correlation. Revocation follows the same failure distinction.

Atomic database commit is not atomic HTTP delivery. A connection failure during
COMMIT or loss of an already-committed response leaves the caller uncertain.
There is no insecure refresh replay grace window. RPs serialize refreshes and
must be prepared to perform a new authorization flow after an ambiguous lost
response rather than repeatedly replaying an old refresh credential.

---

# 17. Tokens

## 17.1 Access Token

Access tokens are RS256 JWTs with JOSE `typ=at+jwt`. They are not ID tokens.

Default lifetime:

```text
5 minutes
```

Example:

```json
{
  "iss": "https://auth.example.com",
  "sub": "404c7592-4ae3-4498-b815-2fd3b1dca1bf",
  "aud": "bdcmaps",
  "client_id": "bdcmaps",
  "iat": 1780000000,
  "exp": 1780000300,
  "jti": "06750e46-...",
  "scope": "openid profile email groups bdcmaps.network.read"
}
```

In v1, `aud` is the OIDC/OAuth client ID. Independent resource-server registration is deferred until a client requires an audience different from itself.

## 17.2 ID Token

Example:

```json
{
  "iss": "https://auth.example.com",
  "sub": "404c7592-4ae3-4498-b815-2fd3b1dca1bf",
  "aud": "bdcmaps",
  "iat": 1780000000,
  "exp": 1780000300,
  "auth_time": 1779999900,
  "acr": "urn:authd:acr:mfa",
  "amr": ["pwd", "otp"],
  "sid": "a3d564c1-9fd8-4ea0-94b0-69df15ab95d0",
  "nonce": "...",
  "preferred_username": "alice",
  "name": "Alice Example",
  "email": "alice@example.com",
  "email_verified": true,
  "groups": ["bdcmaps-admin"]
}
```

ID tokens use JOSE `typ=JWT`. They also carry `at_hash`, the base64url-encoded left half of SHA-256 of the associated access token. Claims are included according to requested/allowed scopes and supported destination-specific claim selectors.

`sub` is always included.

`profile` may include:

```text
name
preferred_username
```

`email` may include:

```text
email
email_verified
```

`groups` may include role names under `groups`.

`roles` may include the same role names under `roles`.

`acr` records the authentication context actually satisfied by the provider session; it is not copied from client input.

`amr` records the authentication methods actually used.

`sid` identifies the authd provider login session that authenticated the user. It is stable across authorization-code exchange and refreshes derived from that session. A new provider login receives a new `sid`. RPs that create their own local application session SHOULD retain `(issuer, sub, sid)` with that local session so a future logout mechanism can target the correct RP session.

## 17.3 Signing

v1 emits:

```text
RS256
```

Every signing key has a `kid`.

New RSA keys SHOULD be at least 3072 bits.

Signing private keys are encrypted at rest using deployment master-key material outside PostgreSQL.

Public keys remain in JWKS long enough to validate all non-expired tokens signed by them.

Key retirement and key deletion are separate operations. Only rotation/retirement
is currently implemented; old public keys are retained. Startup must decrypt and
validate the active private key against its advertised public JWK, including when
another process wins first-key creation. Wrong master-key material fails startup.

Verification pins RS256, the configured issuer, token type and expected claim
shape. Reject duplicate JSON members, unsupported JOSE critical/b64 headers,
malformed or inconsistent RSA JWKs, and JWTs exceeding 16 KiB. Issuance uses the
same size limit; oversized role/claim output fails transactionally, not by
truncating authorization. Parsed key caches are bounded and fingerprinted by
key material; they never cache user, client or authorization decisions.

---

# 18. Refresh Tokens

Refresh tokens are opaque random values.

They are not JWTs.

The database stores only a hash.

Suggested defaults:

```text
absolute lifetime: 90 days
idle lifetime:     30 days
```

Refresh tokens are issued only when:

```text
offline_access
```

was requested, the client permits refresh tokens, and the browser completed explicit offline-access consent under §15.5.

Every successful refresh rotates the refresh token:

```text
RT1 -> access token + RT2
RT1 consumed

RT2 -> access token + RT3
RT2 consumed
```

Refresh tokens belong to a family.

If a consumed token is presented again, the provider treats the family as compromised and revokes the whole family.

Refresh state is bound to:

```text
user
client
original granted scope
family
```

Refresh can never expand scope beyond either the original grant or the latest
narrowed token. Rotation cannot extend the family's absolute expiry. Recalculate
current permissions and claim policy each time. Keep the original `auth_time`,
`acr`, authentication methods and `sid`; refresh does not create a new ceremony.
Natural provider-session expiry does not invalidate an explicitly consented
offline grant. Explicit provider-session revocation does.

---

# 19. Authorization Recalculation on Refresh

A refresh token is not a permanent permission snapshot.

Every refresh verifies:

```text
user enabled
client enabled
scope still allowed for client
user still possesses each application permission in the refreshed scope
```

If permission was removed after initial login, refresh MUST NOT perpetuate it.

This ensures role/permission changes propagate without waiting for the long refresh-token lifetime.

---

# 20. Revocation

`POST /revoke` supports refresh-token revocation.

Revoking a refresh token revokes its family. Authenticate and recheck the
requesting client before altering family state. An unknown token or one not owned
by that client returns the nondisclosing success response; a database failure
returns 503, never a false successful revocation.

JWT access tokens are intentionally short-lived and are not required to participate in a global online introspection database.

Administrative revocation semantics:

```text
provider session -> immediate provider logout
refresh family   -> immediate inability to mint new access tokens
access token     -> remains valid until its short expiry
```

With the default TTL, residual validity of already-issued authd access tokens is
approximately five minutes, plus RP clock tolerance. This is NOT a maximum on an
RP's independent application-cookie lifetime; RPs must define their own session
expiry/revalidation policy until a separately implemented logout channel exists.

This is intentional.

---

# 21. UserInfo

Accept GET or POST with a Bearer access token; POST may instead use one
form-encoded `access_token`. Do not accept URL-query tokens or multiple credential
transports. Require a valid issuer-signed `at+jwt` access token with `openid` and
valid client/audience binding; an ID token is not a UserInfo credential.

Verify its signature once. Project the identity snapshot and applicable
per-destination selectors carried in the signed access token. Only corresponding
scoped/selected fields are returned. The `sub` agrees with the associated ID
token. Empty requested role/group memberships encode as arrays, not null.
Invalid tokens return 401, insufficient identity scope 403, malformed credential
transport 400, and dependency failure 503. This endpoint does not extend a token's
expiry or convert an old grant into newly elevated permissions.

---

# 22. Provider Sessions

Provider login sessions use opaque cryptographically random identifiers.

Cookie name:

```text
__Host-authd_session
```

Properties:

```text
Secure
HttpOnly
SameSite=Lax
Path=/
```

The raw cookie contains no identity data.

PostgreSQL stores only a hash of the raw session value.

Session record:

```text
id                 # the value projected as OIDC sid
session_hash
user_id
created_at
last_seen_at
auth_time
auth_methods
expires_at
ip_address
user_agent
```

Suggested defaults:

```text
idle timeout:       12 hours
absolute lifetime:   7 days
```

No permanent remember-me cookie exists in v1. Read session/user authority live.
Throttle only the activity write: at most once per min(60 seconds, idle TTL/4),
with a one-millisecond floor. This reduces write churn; idle expiry is approximate
within that touch interval, not a promise of an exact wall-clock sliding timer.

A successful fresh login atomically creates a new provider session, consumes its
factor proof, and retires the presented prior session and its unused codes.
Ordinary reauthentication does not erase previously consented offline families.
Explicit session revocation/logout revokes that session's unused codes and
refresh families in the same mutation transaction. Password changes, disabling,
and MFA reset retain their stronger user-wide revocation semantics.

---

# 23. Logout

Support GET and POST RP-Initiated Logout, with a signed ID-token hint and an
exactly registered post-logout URI. Preserve `state` on the validated redirect.
Otherwise-valid expired ID-token hints can identify the current/recent session;
access tokens cannot be substituted as hints.

Automatic logout requires the hint to match the current subject and provider
`sid` (when present). Bare, cross-subject, or cross-session requests ask the user
for explicit confirmation instead of silently terminating the session. The POST
confirmation is CSRF-bound to the exact logout parameters and current browser
session. A valid signed hint may still authorize a registered redirect after the
provider session has already gone. Invalid destinations are rejected before any
logout mutation.

Successful local logout commits provider-session and related grant revocation
before clearing cookies or redirecting. A dependency failure leaves the browser
cookie intact and returns 503, rather than claiming logout succeeded. No automatic
front/back-channel logout notification to an RP is implemented or advertised;
existing RP-local sessions are not magically destroyed.

---

# 24. Login UI

Login UI is minimal.

Pages:

```text
/login
/login/mfa
/logout
/account
```

When login is servicing an OIDC request, show the target client name:

```text
Sign in
Continue to the application
```

Authentication failure message remains generic:

```text
Invalid username or password.
```

Responses MUST NOT reveal whether a username exists, is disabled, or has a different MFA state before primary authentication succeeds.

Login attempts are rate-limited using both source IP and normalized username keys. A PostgreSQL-backed implementation is preferred if more than one server instance is ever deployed; a single-process bounded in-memory limiter is acceptable only while explicitly single-instance.

Successes and failures are audited without storing passwords or supplied OTP values.

---

# 25. User Self-Service UI

`/account` provides:

```text
Profile
Password
MFA
Sessions
```

The user may:

- view username;
- update allowed profile fields;
- change password;
- enroll TOTP;
- re-enroll/remove TOTP after reauthentication;
- regenerate recovery codes;
- inspect active provider sessions;
- revoke individual sessions;
- log out all other sessions.

A user cannot assign roles or permissions to themselves.

---

# 26. Administration UI

Administration requires:

```text
system.admin
```

Every admin request verifies the permission server-side. Administrative writes
also recheck the live session and `system.admin` inside the mutation transaction.
They require authentication within the preceding ten minutes. Read-only admin
views remain available to older live sessions. Enabling/disabling users, changing
direct role assignments, or editing roles MUST preserve at least one enabled,
non-deleted **direct** holder of `system.admin`; concurrent mutations MUST
serialize this invariant. Group-derived administration is possible, but it
does not replace the required direct holder for the last-administrator check.

The UI uses server-rendered HTML and embedded static assets.

No SPA framework is required.

Small JavaScript is allowed for:

```text
confirmation dialogs
copy-to-clipboard
search/filter enhancement
TOTP QR setup
progressive form behavior
```

Primary navigation:

```text
Users
Roles
Permissions
Clients
Sessions
Audit
Signing Keys
```

## 26.1 Users

List shows:

```text
Username
Display Name
Email
Email Verified
Enabled
Primary Password
Roles
MFA
Last Login
```

Actions:

```text
Create User
Edit User
Enable
Disable
Set/Replace Primary Password
Force Password Change
Assign Roles
Reset MFA
Revoke Sessions
Delete User
```

## 26.2 Roles

Role page shows:

```text
Name
Description
Permissions
Users assigned
```

Actions:

```text
Create
Rename
Edit description
Add permission
Remove permission
Delete
```

Deleting a referenced role requires explicit consequence confirmation and removes role assignments atomically.

`system-admin` cannot be deleted.

## 26.3 Permissions

Permission page shows:

```text
Name
Description
Roles using it
Clients allowed to request it
```

A permission MUST NOT be deleted while referenced by a role or client. Dependencies must be removed first.

## 26.4 Clients

Client page shows:

```text
Name
Client ID
Public / Confidential
Enabled
Require MFA
Redirect URIs
Logout URIs
Allowed identity scopes
Allowed application permissions
Refresh tokens enabled
Access token TTL
```

Actions:

```text
Create
Edit
Disable
Delete
Rotate Secret
```

A new/rotated client secret is shown exactly once.

## 26.5 Sessions

Administrators may inspect sessions by:

```text
user
created time
last activity
authentication method
IP
user agent
```

Actions:

```text
Revoke session
Revoke all sessions for user
```

## 26.6 Signing Keys

Display:

```text
kid
algorithm
created_at
activated_at
retired_at
```

Actions:

```text
Rotate Signing Key
Retire Key
Delete Retired Key
```

Deletion warns if a key may still be required to validate unexpired tokens.

---

# 27. Bootstrap

A clean database contains no human users.

Bootstrap is initiated explicitly with `authd bootstrap` on the service host.
The command generates at least 256 random bits, records only the token hash with
a 30-minute expiry, invalidates previous unconsumed bootstrap tokens, and prints
the new token to the operator's terminal. The daemon MUST NOT print bootstrap
secrets into its regular logs. The command does not create the administrator.

`/setup` accepts the token and first user's profile/password through a CSRF-
protected form. Token consumption, user/password creation, assignment of
`system-admin`, audit insertion, and marking installation complete MUST be one
PostgreSQL transaction. Concurrent setup submissions can succeed at most once.

A permanent `installation_state.bootstrap_completed` flag closes setup after the
first success. Merely losing the final administrator or deleting users MUST NOT
reopen setup. Upgrading a database with existing users or previously consumed
bootstrap tokens closes bootstrap as well. Bootstrap is not a general recovery
backdoor. An explicit administrative recovery process is separate future work.

Ordinary user creation occurs through the administration interface after setup.

---

# 28. PostgreSQL

PostgreSQL is the only supported database in v1.

Minimum supported PostgreSQL should track the versions supported by the selected current pgx release and project deployment policy. The initial development target is PostgreSQL 15+; tests should run against a current supported release.

The initial schema contains:

```text
users
password_credentials
roles
permissions
user_roles
groups
group_roles
user_groups
role_permissions
clients
initial_registration_tokens
client_registration_credentials
client_role_templates
client_group_templates
client_redirect_uris
client_logout_uris
client_identity_scopes
client_permissions
authorization_codes
refresh_token_families
refresh_tokens
sessions
totp_credentials
recovery_codes
signing_keys
bootstrap_tokens
audit_events
schema_migrations
```

Migrations are embedded in the executable and applied only by the explicit `authd migrate` command, in filename/version order under a transaction-scoped PostgreSQL advisory lock. Migration execution and version records commit together; pooled connections MUST NOT retain a migration lock after cancellation or return. Normal daemon startup and `authd bootstrap` perform no DDL: they verify that the recorded migration versions/names exactly match the embedded migration manifest and fail closed if the schema is absent, behind, ahead, or has altered history.

`authd migrate` is a deployment-only DDL command and MUST require only the migration database connection. It MUST NOT require the OIDC issuer, runtime master key, or other daemon-only secrets. The migration-owner DSN MUST NOT be stored in the normal daemon environment file.

Production deployments SHOULD use a migration/owner PostgreSQL role for `authd migrate` and a separate DML-only runtime role for `authd` and `authd bootstrap`. The runtime role requires database connect, schema usage, table DML, and sequence usage but not table ownership or schema `CREATE`. Future migration-owner objects MUST preserve the runtime grants through reviewed default privileges. The repository provides greenfield PostgreSQL bootstrap SQL that may create the dedicated database and LOGIN roles, plus a reviewed runtime-grant script. PostgreSQL LOGIN passwords MUST remain operator-owned: repository SQL MUST NOT choose, embed, log, or persist those passwords.

Native Unix deployments SHOULD run the daemon as a dedicated unprivileged `_authd` account and use the same runtime file contract on OpenBSD and Linux: `/etc/authd/authd.env`, `/etc/authd/master.key`, and (when used) `/etc/authd/pgpass`. OpenBSD rc.d MUST export the env file in the daemon execution shell after privilege transition; Linux systemd SHOULD use `EnvironmentFile=/etc/authd/authd.env` and run directly as `_authd`. The migration-owner connection MUST remain separate from this runtime environment. When practical, the runtime PostgreSQL password SHOULD be supplied through a daemon-readable `PGPASSFILE` rather than embedded directly in `DATABASE_URL`.

The native installer MAY create missing active env and master-key files on first installation. On subsequent installations it MUST preserve the contents of the active env, pgpass, master key, and PostgreSQL database while replacing versioned program, documentation, example, and service-manager assets. It MUST NOT run schema migration implicitly or require the migration-owner credential. Service start MUST never generate or replace a master key.

No external migration framework is required initially.

---

# 29. Secret Storage

The following MUST never be stored as plaintext in PostgreSQL:

```text
user passwords
client secrets
authorization codes
refresh tokens
provider session tokens
recovery codes
bootstrap tokens
```

High-entropy random bearer values may be stored as SHA-256 hashes because they are already computationally unguessable.

Canonical primary passwords use Argon2id and are stored in `password_credentials`, separate from the `users` row.

The following require reversible encryption and MUST be encrypted with a deployment master key held outside PostgreSQL:

```text
TOTP seeds
signing private keys
future protocol shared secrets if the service ever owns them
explicitly enrolled protocol-specific recoverable credentials, if any
```

The master key file MUST be readable only by the service account.

---

# 30. Random Values

All security-sensitive randomness comes from `crypto/rand` / the operating system CSPRNG.

This includes:

```text
sessions
authorization codes
refresh tokens
client secrets
bootstrap tokens
recovery codes
TOTP seeds
JWT IDs
signing keys
CSRF tokens
```

---

# 31. CSRF

All state-changing provider-operated HTML forms use CSRF protection.

This includes:

```text
login continuation where appropriate
password changes
MFA changes
admin operations
logout POST
setup/bootstrap operations
```

CSRF tokens are bound to browser state/session and compared in constant time.

OIDC `state` is not a replacement for provider-side CSRF protection.

---

# 32. HTTP Security

Production issuer URLs use HTTPS.

The issuer is configured explicitly and is never inferred blindly from arbitrary `Host` or `X-Forwarded-*` headers.

For TCP, forwarded addresses are trusted only from explicitly configured
reverse-proxy CIDR prefixes. If the direct peer is not trusted, `X-Forwarded-For`
is ignored. For a trusted chain, authd walks addresses from the direct peer toward
the client and uses the nearest untrusted address. Malformed, duplicate or
oversized chains fall back to the direct TCP peer.

Unix connections have no client IP; peer socket names MUST NOT be interpreted as
IP addresses. Forwarded addresses on Unix connections are ignored unless
`AUTHD_TRUST_UNIX_PROXY=true`. That explicit option trusts the filesystem-restricted
Unix hop, not every TCP peer. Transport identity MUST come from the actual accepted
connection, never an HTTP header or a peer-selected name. Invalid/missing forwarded
chains remain unknown/empty, including in OIDC audit events, and use the shared
unknown-IP rate-limit bucket. The proxy MUST overwrite browser-supplied forwarding
headers. Additional proxy CIDRs may describe upstream TCP hops but MUST NOT
implicitly trust Unix peers. This trust conveys source-IP attribution only, never
an authenticated user or an authorization grant.

Recommended security headers:

```text
Content-Security-Policy
X-Content-Type-Options: nosniff
Referrer-Policy: origin
Permissions-Policy
```

Login/admin pages cannot be framed by arbitrary sites.

Sensitive responses use:

```text
Cache-Control: no-store
```

Development mode may permit an HTTP issuer only when explicitly enabled.

---

# 33. CORS

No endpoint uses unrestricted:

```text
Access-Control-Allow-Origin: *
```

If browser public clients require cross-origin `/token`, `/userinfo`, or `/revoke`, allowed origins derive from exact registered client origins.

No arbitrary origin reflection.

Server-side clients such as `bdcmaps` do not require CORS for token exchange.

---

# 34. Audit Log

Security and administrative events are recorded.

At minimum:

```text
login.success
login.failure
logout
mfa.success
mfa.failure
mfa.enrolled
mfa.removed
mfa.reset
recovery_codes.regenerated

user.created
user.updated
user.profile_updated
user.enabled
user.disabled
user.deleted
user.password_reset
credential.enrolled
credential.rotated
credential.revoked

role.created
role.updated
role.deleted

permission.created
permission.updated
permission.deleted

client.created
client.updated
client.disabled
client.deleted
client.secret_rotated

session.revoked
session.others_revoked

token.refresh
token.refresh_reuse_detected
token.revoked

signing_key.created
signing_key.rotated
signing_key.retired
signing_key.deleted

bootstrap.started
bootstrap.completed
```

Audit entry contains:

```text
timestamp
event type
actor user ID when available
target type
target ID
source IP
request ID
structured metadata
```

Audit records are append-only through normal application permissions.

Passwords, OTP values, client secrets, authorization codes, refresh tokens, session tokens, recovery codes, and TOTP secrets never appear in audit metadata.

---

# 35. Effects of Authorization Changes

## User Disabled

Immediately:

```text
provider sessions revoked
refresh families revoked
new authorization denied
```

Existing access tokens expire naturally within their short TTL.

## User Deleted

Deletion is a soft delete of the immutable identity row so audit references and the
OIDC subject identifier remain historically meaningful. Local password credentials,
MFA enrollment/recovery material, role assignments, provider sessions, outstanding
authorization codes, and refresh capability MUST be removed in the same transaction.
The final enabled administrator cannot be deleted. Previously issued short-lived
access/ID tokens expire naturally.

## Role Added/Removed

Immediately affects:

```text
new authorization requests
new refresh operations
new protocol adapter authorization decisions
```

Existing access tokens expire naturally.

## Permission Added/Removed From Role

Same behavior.

Refresh recomputes authorization and cannot retain removed permissions.

## Permission Removed From Client

Client cannot request or refresh that permission scope.

## Client Disabled

Immediately:

```text
new authorization denied
refresh denied
```

Existing access tokens expire naturally.

## Client Deleted

Deletion removes the client registration and all durable state owned by it, including
redirect/logout registrations, allowed scopes, outstanding authorization requests and
codes, and refresh-token families. Already-issued short-lived JWTs are not maintained
in an online revocation list and expire naturally.

---

# 36. Health Endpoint

`GET /healthz` returns only basic operational state.

A healthy response may be:

```json
{
  "status": "ok"
}
```

It MUST NOT expose:

```text
user data
client data
secrets
key material
database DSNs
filesystem paths
build environment
```

If database health is required for readiness, expose it as a boolean/HTTP status, not diagnostic credentials.

---

# 37. Configuration

Deployment configuration contains infrastructure settings, not identities.

Initial environment/configuration surface:

```text
AUTHD_ISSUER
AUTHD_LISTEN
AUTHD_UNIX_MODE
AUTHD_UNIX_GROUP
AUTHD_TRUST_UNIX_PROXY
DATABASE_URL
AUTHD_MASTER_KEY_FILE or AUTHD_MASTER_KEY
AUTHD_DEVELOPMENT
AUTHD_CLEANUP_INTERVAL
AUTHD_AUDIT_RETENTION
AUTHD_TRUSTED_PROXIES
```

Users, roles, permissions, and clients do not live in configuration files.

They live in PostgreSQL and are edited through the web administration interface.

Secrets should be supplied through protected files or narrowly scoped environment variables only when the secret cannot itself be managed through encrypted application storage.

## 37.1 Native HTTP listener contract

`AUTHD_LISTEN` selects exactly one HTTP transport. Existing TCP `host:port`
configuration remains supported and remains the default. `unix:/absolute/path`
and bare absolute socket paths select filesystem Unix stream sockets on Linux
and OpenBSD. Relative, abstract, non-clean and overlong paths MUST fail validation.
`unix://` URL syntax is not supported. Binding failure MUST stop the service;
there is no automatic TCP fallback.

The issuer and advertised OIDC endpoints MUST remain the configured public HTTPS
origin regardless of listener transport. Production cookie, CSRF, Origin, token,
client and issuer checks are not relaxed for an internal Unix connection.

The Unix parent directory MUST already exist, be owned by the daemon, and not be
group/world writable. Its ancestors must be controlled by root/the daemon.
Native service definitions MAY provision an explicitly supported dedicated runtime
directory. Go listener code MUST NOT recursively create directories, change
service-account groups, or repair arbitrary directory ownership.

`AUTHD_UNIX_MODE` defaults to `0600`; only `0600` and `0660` are accepted.
`AUTHD_UNIX_GROUP` optionally selects the socket's group. The daemon must have
permission to set that group; failures MUST NOT fall back to a weaker mode.
Reverse proxies SHOULD use a distinct socket-sharing group, not `_authd`, which
also governs access to private runtime configuration. The parent is normally
`_authd:_authd 0711`; it permits traversal while socket mode gates connections.

Startup MUST serialize publication with a lifetime filesystem lock, reject live
listeners, and refuse to overwrite non-sockets, symlinks or foreign-owned sockets.
Only an owned socket with an `ECONNREFUSED` connection probe may be removed as
stale. Permission failures, timeouts and unknown errors are not evidence of
staleness. Final mode/group MUST be applied in a private staging directory before
publication; no process-wide umask change or permissive public bind window.

Graceful shutdown removes only the listener's own recorded socket inode and drains
HTTP requests with a bounded deadline. A replacement path must be left untouched.
The owned mode-0600 `.lock` file is deliberately retained; the kernel releases its
lock on close/process death. Service scripts MUST NOT unlink sockets or lock files
to bypass a live instance. Linux systemd grants only the dedicated runtime write
path under its existing sandbox; OpenBSD uses standard rc.subr background/start
handling and sources the env after changing to the daemon user.

Unix socket activation, peer-UID authentication, network-filesystem socket state,
and multi-instance service coordination are not implemented. The operator path,
proxy namespace/chroot rules and cutover procedure are in `docs/UNIX_SOCKET.md`.
No database migration is introduced by v0.9.2.

---

# 38. Protocol Adapter Boundary

OIDC is the first protocol frontend, not the identity model itself.

Future protocol frontends use a small shared result model conceptually equivalent to:

```go
type Subject struct {
    ID          string
    Username    string
    DisplayName string
    Email       string
    Roles       []string
    Permissions []string
    AMR         []string
}
```

A protocol frontend may:

```text
authenticate credentials through the identity core
request effective roles/permissions
map those facts into protocol-native attributes/authorization
write protocol-specific audit events
```

A protocol frontend may not:

```text
create its own user database
create its own role hierarchy
silently invent permissions
store plaintext copies of user passwords
bypass account enabled/disabled state
```

## 38.1 Protocol-specific client registrations

Protocol peers are not OIDC clients merely because they authenticate users. Each protocol gets the smallest registration model required by that protocol. For example:

```text
OIDC/OAuth client
    client_id
    client authentication method/secret
    redirect URIs
    logout URIs
    allowed scopes/permissions

RADIUS NAS / peer
    source identity/address or TLS identity
    transport profile
    RADIUS shared secret when the selected transport requires one
    allowed authentication methods
    role/permission -> attribute mappings

TACACS+ client
    source/TLS identity
    transport profile
    shared secret only when the selected transport requires it
    service/command mappings
```

Future schema SHOULD therefore use separate records such as `radius_clients` and `tacacs_clients`. Do not add a `protocol` discriminator to the OIDC `clients` table and turn it into a generic configuration bag.

## 38.2 RADIUS Direction

Potential uses:

```text
VPN/Wi-Fi/network access
router administrative login where RADIUS is appropriate
role/permission -> VLAN/filter/vendor attributes
```

RADIUS implementation MUST explicitly choose supported authentication methods. The initial credential matrix is:

```text
method                 canonical Argon2id credential
RADIUS PAP             supported
classic CHAP           not supported
MS-CHAP / MS-CHAPv2    not supported
EAP-TTLS with inner PAP potentially supported by a future explicit EAP implementation
EAP-TLS                certificate credential; separate future credential type
```

For PAP, the NAS does not need to understand Argon2id. The RADIUS frontend recovers the submitted password from the RADIUS request and asks the identity core to verify that candidate password against the Argon2id verifier.

Classic CHAP requires access to the original password to compute the expected challenge response and therefore cannot use the canonical verifier. MS-CHAP-family methods require weaker password-equivalent material such as an NT hash and are disabled unless a concrete deployment explicitly introduces the corresponding separate credential type.

Protected RADIUS transport SHOULD be preferred where deployment support permits it. Implementations SHOULD evaluate RADIUS/TLS and RADIUS/1.1 rather than assuming classic RADIUS/UDP with its legacy shared-secret/MD5 construction is the desired transport.

RADIUS authorization attributes are declarative mappings from current roles/permissions to protocol attributes. They are not executable policy code.

## 38.3 TACACS+ Direction

Potential uses:

```text
router/switch administrator authentication
command authorization
accounting
```

Command authorization should map explicit configured role/permission facts into TACACS+ authorization results. Do not add a general-purpose policy language unless real command policy cannot be represented cleanly by data rows.

Where both client and server support it, TACACS+ over TLS 1.3 SHOULD be preferred over the legacy TACACS+ obfuscation mechanism.

---

# 39. Application Integration Profile

An application MUST validate the OIDC sign-in result and the granted
access-token scopes, then enforce its own resource and admission rules. The
application supplies exact callback URLs and an operation-scope catalog; authd
supplies identity, optional MFA, roles/groups and eligible OAuth grants.
Registration does not assign anyone access. The reusable operator/developer
contract is in `docs/APPLICATION_INTEGRATION.md`, with wire-level details in
`docs/APP_CREATOR_OIDC.md` and the identity/tenancy boundary in
`docs/RP_INTEGRATION.md`. Application-specific manifests and deployment steps
belong in that application's repository. Dated integration evidence remains in
`VALIDATION.md` and does not automatically qualify later app revisions.

---

# 40. Liminal-Derived UI Contract

The binding UI adaptation lives in `DESIGN_LANGUAGE.md`.

Key constraints:

```text
thin modern surfaces
hairline separators
row grammar over card grids
compact left navigation rail
server-rendered HTML
no frontend framework requirement
one global focus-visible treatment
color used for state/action, not decoration
explicit security consequences in confirmation text
one-time secret reveal surfaces
```

The authentication page is intentionally quieter than the administration console.

---

# 41. Required Security Invariants

The following are release-blocking.

1. Redirects occur only to exactly registered URIs.
2. Authorization codes can be consumed once.
3. Every authorization-code exchange uses PKCE S256.
4. A code issued to Client A cannot be exchanged by Client B.
5. A refresh token issued to Client A cannot be used by Client B.
6. Reuse of a consumed refresh token revokes its token family.
7. A client cannot receive a scope not allowed for that client.
8. A user cannot receive an application permission scope not granted through their roles.
9. Disabling a user immediately destroys provider sessions and refresh capability.
10. Removing permission prevents that permission from surviving the next refresh.
11. No credential/bearer secret appears in logs.
12. No plaintext password, refresh token, client secret, session value, authorization code, recovery code, or bootstrap token is stored in PostgreSQL.
13. An unprivileged user cannot perform any `system.admin` operation.
14. Client-supplied parameters cannot create an open redirect.
15. OIDC `sub` does not change when username/email changes.
16. `groups` and `roles` contain local role names current at issuance/refresh, never client-injected names; an already-issued token remains a short-lived snapshot.
17. `groups` or `roles` is emitted only when its scope was both requested and allowed for the client.
18. A zero-role enabled user may authenticate for identity-only use, but receives no application permissions and no administrative access.
19. The canonical primary password is never stored reversibly and has no NT-hash/password-equivalent companion by default.
20. Additional weaker or recoverable protocol credentials require explicit enrollment and cannot be silently derived during normal password changes.
21. A future RADIUS/TACACS+ adapter cannot bypass the same enabled/disabled user state and role/permission resolver.
22. RADIUS and TACACS+ peer registrations remain protocol-specific and cannot be smuggled into the OIDC client model.
23. RPs key authd identities by `(iss, sub)`, never by email, username, display name, role, or group claims.
24. Matching email addresses never silently link an existing RP account to an authd identity.
25. Authd authentication alone never creates application-local tenant, organization, customer, PBX, extension, project, room, case, boundary, workspace, or resource membership.
26. An ID Token's `acr` reflects the authentication context actually satisfied; client input cannot inject or upgrade it.
27. `sid` identifies the provider login session and survives token refresh for that session; a fresh provider login receives a different `sid`.
28. Client-required MFA and essential MFA selectors cannot receive a password-context ID Token; voluntary `acr_values` is not an essential requirement.
29. Applications may trust other IdPs directly; authd does not require identity brokering through authd.
30. Grant signing, code/refresh consumption, replacement/family creation and audit share one commit boundary.
31. Another client or wrong PKCE verifier cannot revoke the legitimate grant by replay probing.
32. Unknown infrastructure state is not invalid credentials or successful revocation; failures remain explicit.
33. Authorization continuation and consent are bound to the initiating browser, and consent to the current provider session.
34. Voluntary claims never become mandatory authority; normal nonmatching claim values are omitted, not manufactured.
35. A token for one purpose cannot be accepted for another simply because its JWT signature is valid.
36. Security-critical mutation paths exclude grant commit; read-only paths do not serialize unrelated grants.

---

# 42. Required Interoperability Tests

Before v1 completion, test against at least:

```text
yellowman/bdcmaps existing OIDC client
a generic server-side Go OIDC client or equivalent independent implementation
a browser public client using PKCE
one common reverse-proxy/framework OIDC integration
```

Coverage includes:

```text
discovery
JWKS
login
login_hint
PKCE
ID token validation
nonce
voluntary acr_values and essential claims password/MFA requests
max_age combined with MFA step-up
unmet_authentication_requirements
acr/amr claims
stable sid across refresh and new sid after a new provider login
email claims, including verified/unverified transitions
groups claim requested+allowed release
roles claim requested+allowed release
zero-role identity-only authentication
userinfo
refresh
refresh rotation
logout
invalid redirect
invalid client
invalid scope
permission denied
disabled user
disabled client
expired code
replayed code
replayed refresh token
client_secret_basic
client_secret_post
signing key rotation
```

---

# 43. Definition of v1 Complete

An administrator can:

```text
1. Start a new provider against PostgreSQL.
2. Bootstrap the first administrator.
3. Log into /admin.
4. Create permissions.
5. Create roles containing permissions.
6. Create groups containing roles, and users with direct roles or group memberships.
7. Create an OIDC client.
8. Add exact redirect URIs.
9. Select allowed identity scopes.
10. Select application permissions the client may request.
11. Configure MFA requirement.
12. Rotate a client secret.
13. Revoke sessions.
14. Rotate signing keys safely.
```

An application can:

```text
1. Discover the provider.
2. Redirect to /authorize.
3. Authenticate with password and optional TOTP.
4. Exchange a code using PKCE.
5. Validate an RS256 ID token from JWKS.
6. Receive short-lived access token scopes.
7. Receive groups/roles claims when requested.
8. Express ACR preferences through `acr_values`, mandatory context through essential `claims`, and validate the returned authentication context.
9. Retain `(iss, sub, sid)` with its local application session.
10. For a manually configured client with offline access, refresh using rotating refresh tokens without losing `acr`/`sid` correlation.
11. Use /userinfo when needed.
12. Perform RP-initiated logout.
```

An app can register dynamically and check granted access-token scopes without
an authd-specific sign-in library; role/group template metadata is optional
authd-specific registration behavior.

That is the v1 product.

RADIUS/TACACS+ may be developed after the central OIDC path is proven, but their future needs are already prevented from forcing a second identity model.

---

# 44. Normative Protocol References

Implementation should conform to applicable portions of:

```text
OpenID Connect Core 1.0
OpenID Connect Discovery 1.0
OpenID Connect RP-Initiated Logout 1.0
OpenID Connect Core Error Code unmet_authentication_requirements 1.0
OpenID Connect Back-Channel Logout 1.0 (future logout design; back-channel delivery is not v1)

OAuth 2.0 / RFC 6749
OAuth Token Revocation / RFC 7009
PKCE / RFC 7636
OAuth Authorization Server Metadata / RFC 8414
OAuth Authorization Server Issuer Identification / RFC 9207
OAuth 2.0 Security Best Current Practice / RFC 9700

Future protocol adapters, when implemented:
RADIUS / RFC 2865 plus applicable updates
EAP-TTLS / RFC 5281 when that method is implemented
RADIUS/TLS / RFC 6614 plus applicable updates including RFC 9765
TACACS+ / RFC 8907 plus applicable updates
TACACS+ over TLS 1.3 / RFC 9887 when supported
```

Where `authd` intentionally supports only a subset of optional protocol behavior, discovery metadata MUST describe the implemented subset accurately.


# 45. v0.9.0 implementation limits and evidence

The source implements local identity/bootstrap/MFA/administration and the limited
code-flow OIDC profile described above. No OpenID certification, production
signoff, external RP acceptance, or measured PostgreSQL throughput is claimed.
At the original v0.9.0 audit handoff, the earlier tester report did not qualify
those new transactions. A subsequent user-supplied v0.9.0 OpenBSD/PostgreSQL/live
provider pass is recorded in VALIDATION.md. Later UI/transport changes retain
their own evidence boundaries; none implies an actual BDC callback pass.

Security-changing identity/client/key operations use an exclusive transaction
advisory gate. Unrelated grant transactions share that gate and lock their own
request/code/family rows, allowing concurrent grants while excluding privilege
changes through the issuance commit. All application writers must obey that
contract. Direct DBA changes are outside it. Read-only admin views use a
consistent read transaction without taking the global writer gate.

Cleanup works in bounded 256-row batches with a two-second pass budget and short
lock wait. Expired family children are batched before parent removal. Consumed
code/token witnesses remain while a related offline family can be used. Retired
public signing keys are never automatically deleted. Reverse-FK and expiry
indexes support these operations; actual query plans, storage growth and latency
still require deployment-scale PostgreSQL measurements.

The initial admin catalog retains a 200-record fail-closed editing ceiling;
pagination is unfinished. Other deliberate limits include four concurrent KDF
operations, bounded process-local rate buckets, 64 scopes, 32 registered redirect
URIs per client, 8 KiB claims JSON, 16 KiB JWTs, and bounded key caches. No distributed
rate limiter, multi-instance production qualification, or arbitrary client/audience
resource-server registry is implied.

Migration 005 preserves users, credentials, keys, existing sessions and established
refresh families; it restarts pending browser authorizations and unused codes
which lack the new browser binding. An existing permission whose name shadows an
OIDC control scope makes the migration fail atomically until explicitly renamed
or removed. The original migrations remain unchanged. Normal startup checks exact
recorded migration names/versions; the migrator permits only a valid manifest
prefix. This is not a checksum or physical-DDL integrity attestation.

The native OpenBSD/Linux install contract remains repeatable and preserves the
deployment's env, master key, pgpass and database. DDL is explicit with the owner
credential, never the runtime daemon credential. Backup/restore, master-key
rotation, native service-manager operation and full dependency/SQL/conformance
tests remain required deployment gates. See `VALIDATION.md` for exactly which
checks ran, and `docs/OIDC_AUDIT.md` for before/after findings and measurements.

---


# 46. Operator guidance and native form contract (v0.9.3)

The admin landing view MUST offer a first-application procedure and navigation to
users, roles, clients, and troubleshooting. Section/field help MUST distinguish
people, roles/groups, application permissions, registered clients, public issuer,
callback URI, client secret, signing keys, master key, and PostgreSQL identities.
An allowed scope is not implicitly requested or granted. Role-name mapping MUST
be distinguished from scope-based permission enforcement without singling out
any application in built-in help or form behavior.

Saved client connection details MUST derive from persisted client state and the
configured public issuer, not request Host or client-supplied help text. They MUST
NOT reveal a stored secret. A one-time creation response MAY show the newly issued
secret together with connection instructions. User editing SHOULD show issuer +
stable subject for explicit RP account linking, not suggest email-only linking.

`OPERATOR_GUIDE.md` is installed alongside `DEPLOYMENT.md`. Operational help MUST
state implemented limitations (no per-client allowed-user list or role-name filter,
no back-channel logout, no email delivery) rather than invent missing features.
Help routes remain protected by the existing admin authorization boundary.

HTML form responses, including OIDC consent/logout interaction pages, use
`Referrer-Policy: origin`. Native non-CORS form navigation with `no-referrer` may
serialize an opaque `Origin: null`, incompatible with the UI's same-origin check.
The origin-only policy omits path/query data from Referer. The implementation MUST
NOT weaken CSRF or allow opaque/foreign origins to work around document policy.
The separate browser gate exercises native submission without supplying synthetic
Origin headers. It is distinct from HTTP unit tests and real database/RP gates.

Reference: Fetch Standard, “append a request Origin header”, and W3C Referrer Policy.


# 47. Documentation portal and navigation (v0.9.4)

Administration starts with the generic `docs/ADDING_AN_APP.md` workflow, rendered
from its original Markdown. All built-in guidance MUST be application-neutral.
A client ID MUST NOT select application-specific text, links, fields or defaults.
Saved names and settings remain ordinary escaped data. Named integration evidence
may exist in source documents, but MUST NOT receive special interface behavior.
The guide explains client registration, callback/issuer values, identity-only
versus role-name versus permission-scope use, role assignment, client secrets,
app-side configuration and an actual end-to-end login test.

`GET /admin/docs` lists/searches the release documentation. `?doc=<catalog name>`
selects a rendered Markdown document. `GET /admin/docs/raw?doc=<catalog name>`
returns its source or linked embedded evidence as plain text. All three surfaces
MUST use the same live `system.admin` authorization as the admin UI and retain
no-store/security headers. The portal MUST NOT expose runtime files, credentials,
source code, repository internals, arbitrary file paths or remote URL fetching.

The catalog includes product Markdown at the repository root, under `docs/`, and
the recursive `deploy/` tree. Content is embedded in the binary from those
original files and rendered once into an immutable catalog. The index MUST be
derived by walking those directories, listing Markdown filenames alphabetically
within their actual directory, and reading titles from Markdown headings. Files
without headings use their filename. There MUST NOT be a filename/title/category
registry, per-platform README list or per-application catalog logic. Adding,
renaming or deleting a Markdown file MUST be reflected at the next build without
an index-code edit. Tests MUST detect a product Markdown file absent from the
catalog and verify previously unseen nested directories. Tables, fenced code, nested lists,
reference links and heading navigation must remain readable. Raw HTML must be
escaped and links restricted to safe schemes or known local destinations. Images
must not load remote resources automatically. Search and navigation work without
JavaScript or a CDN. Changes require rebuilding/restarting the binary, not a
migration or mutable online wiki.

Sidebar navigation MUST use local inline outline SVGs, accessible link names and
aria-current selection. Normal, hover and selected links have no shaded button
backgrounds or shadows. Selection uses an edge line; focus remains visible. Short
viewports must retain access to every destination and the account link.

An operator-reported full application login counts as completed real RP integration
for that named app. It MUST NOT be relabeled as provider-only testing, nor be
expanded into unreported conformance, MFA, negative-access, recovery or throughput
qualification. Validation records retain the evidence source and scope.
