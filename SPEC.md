# authd — Identity, OIDC, and Access Service

## Specification v0.2

Status: initial binding design for implementation.

## 1. Purpose

`authd` is a small, self-contained identity and access service for an organization that builds multiple internal and operational applications and does not want every application to reinvent users, passwords, roles, permissions, MFA, and login flows.

The primary product is:

```text
local users + local credentials + roles + permissions
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
- local roles and permissions;
- OIDC/OAuth clients configured through the web UI;
- short-lived signed JWT access tokens;
- rotating opaque refresh tokens;
- provider session management;
- RP-initiated logout;
- a local web UI for users, roles, permissions, clients, sessions, audit, and keys;
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
- Dynamic Client Registration;
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

---

# 5. Authorization Model

The authorization model is deliberately simple.

```text
User
  │
  └── has zero or more Roles
                         │
                         └── contains zero or more Permissions
```

A user's effective permissions are:

```text
effective_permissions(user) =
    UNION(permissions of every role assigned to user)
```

There are no denies.

There is no precedence.

There is no inheritance.

There are no nested roles.

Permissions MUST NOT be assigned directly to users in v1.

The three core authorization concepts are:

```text
users
roles
permissions
```

The word `groups` is supported as an OIDC claim alias for role names because existing clients commonly consume a `groups` claim. It does not create a fourth authorization object.

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

Permission names are globally unique.

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
password_hash         string
enabled               bool
force_password_change bool
created_at
updated_at
last_login_at
password_changed_at
deleted_at            nullable
```

`id` is immutable.

OIDC `sub` is derived from this immutable identifier.

Changing username or email MUST NOT change `sub`.

Deleted IDs MUST never be reused.

## 8.1 Username

Username comparison is case-insensitive.

The original normalized display form may be retained.

Usernames are unique among non-deleted users.

## 8.2 Password Storage

Passwords use Argon2id.

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

The provider SHOULD retain the most recently accepted TOTP counter and reject immediate replay of the same time step.

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

If a client is allowed to request an application permission but the user does not possess it, authorization fails rather than silently pretending the requested authorization succeeded.

The provider MUST NOT grant an application scope that the client did not request.

## 10.1 groups and roles

`groups` and `roles` are claim-request scopes over the same role membership.

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

This compatibility alias is intentional. It allows applications such as `bdcmaps` to consume conventional `groups` without introducing a separate group-management model.

---

# 11. Clients

Clients are created manually through the administration interface.

There is no Dynamic Client Registration endpoint in v1.

A client record contains:

```text
id
client_id
name
type
client_secret_hash
enabled
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

`client_secret_post` is retained because the first target, `bdcmaps`, currently sends its client secret in the token request body.

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

Additional UI routes live beneath `/account/` and `/admin/`.

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
    "amr"
  ],
  "authorization_response_iss_parameter_supported": true
}
```

Configured application permissions MAY additionally appear in `scopes_supported`.

The OAuth authorization-server metadata endpoint may use the same underlying metadata builder with the correct well-known path semantics.

---

# 15. Authorization Endpoint

Example:

```text
GET /authorize?
    response_type=code&
    client_id=bdcmaps&
    redirect_uri=https%3A%2F%2Fbdc.example%2Fauth%2Fcallback&
    scope=openid%20profile%20email%20groups&
    state=...&
    nonce=...&
    code_challenge=...&
    code_challenge_method=S256&
    login_hint=user%40example.com
```

The server validates the request before presenting a login form.

Validation includes:

```text
client exists
client enabled
response_type == code
redirect_uri exact match
requested scopes recognized/allowed
code_challenge present
code_challenge_method == S256
```

The authorization transaction is bound to:

```text
client_id
redirect_uri
requested scope
state
nonce
code_challenge
login_hint (advisory only)
created_at
```

The eventual authorization code is additionally bound to:

```text
user_id
auth_time
authentication methods
granted scope
```

Authorization codes are:

```text
single-use
cryptographically random
stored only as hashes
lifetime <= 60 seconds
```

Successful response:

```text
302 Location:
https://client.example/callback?
    code=...&
    state=...&
    iss=https%3A%2F%2Fauth.example.com
```

`state` is returned unchanged when supplied.

The authorization response includes `iss`.

## 15.1 Existing Provider Session

A valid provider session may satisfy another client without re-entering credentials unless:

- `prompt=login` is supplied;
- `max_age` requires reauthentication;
- target client requires MFA and current session is not MFA-authenticated;
- security policy requires reauthentication for the requested operation.

## 15.2 prompt

v1 supports:

```text
prompt=none
prompt=login
```

For `prompt=none`, if interaction is required:

```text
error=login_required
```

## 15.3 nonce

If supplied, `nonce` is cryptographically bound to the transaction and returned unchanged in the ID token.

## 15.4 login_hint

`login_hint` may prefill the username/email field but MUST NOT bypass authentication or reveal whether the hinted account exists.

---

# 16. Token Endpoint

Supported grants:

```text
authorization_code
refresh_token
```

## 16.1 Authorization Code Exchange

Example confidential-body-auth request compatible with the current `bdcmaps` client:

```text
POST /token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&
code=...&
redirect_uri=https%3A%2F%2Fbdc.example%2Fauth%2Fcallback&
client_id=bdcmaps&
client_secret=...&
code_verifier=...
```

The server verifies:

```text
authorization code exists
authorization code unused
authorization code unexpired
client authentication valid
client matches code
redirect URI matches code
PKCE verifier matches
user still enabled
client still enabled
currently granted permissions still satisfy issued scope
```

The code becomes unusable atomically with successful exchange.

Replay fails.

---

# 17. Tokens

## 17.1 Access Token

Access tokens are signed JWTs.

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
  "nonce": "...",
  "amr": ["pwd", "otp"],
  "preferred_username": "alice",
  "name": "Alice Example",
  "email": "alice@example.com",
  "email_verified": true,
  "groups": ["bdcmaps-admin"]
}
```

Claims are included according to requested/allowed scopes.

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

## 17.3 Signing

v1 emits:

```text
RS256
```

Every signing key has a `kid`.

New RSA keys SHOULD be at least 3072 bits.

Signing private keys are encrypted at rest using deployment master-key material outside PostgreSQL.

Public keys remain in JWKS long enough to validate all non-expired tokens signed by them.

Key retirement and key deletion are separate operations.

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

was requested and the client permits refresh tokens.

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

Refresh can never expand scope beyond the original grant.

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

Revoking a refresh token SHOULD revoke its family.

JWT access tokens are intentionally short-lived and are not required to participate in a global online introspection database.

Administrative revocation semantics:

```text
provider session -> immediate provider logout
refresh family   -> immediate inability to mint new access tokens
access token     -> remains valid until its short expiry
```

With the default TTL, maximum residual access authorization is approximately five minutes.

This is intentional.

---

# 21. UserInfo

`/userinfo` accepts a bearer access token and returns identity claims according to the originally granted scopes.

Example:

```json
{
  "sub": "404c7592-4ae3-4498-b815-2fd3b1dca1bf",
  "preferred_username": "alice",
  "name": "Alice Example",
  "email": "alice@example.com",
  "email_verified": true,
  "groups": ["bdcmaps-admin"]
}
```

A token without the corresponding identity scope does not receive that claim.

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
id
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

No permanent remember-me cookie exists in v1.

---

# 23. Logout

The provider supports RP-Initiated Logout.

Example:

```text
GET /logout?
    id_token_hint=...&
    post_logout_redirect_uri=https%3A%2F%2Fapp.example%2F&
    state=...
```

Post-logout redirect URI uses exact registered matching.

Logout destroys the provider login session.

A request without trustworthy client/session context MUST NOT redirect to arbitrary destinations.

Front-channel and back-channel RP logout propagation are deferred.

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
Continue to BDC Maps
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

Every admin request verifies the permission server-side.

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
Enabled
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
Set Password
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

If no administrator exists:

1. Generate a random one-time bootstrap token.
2. Print the setup URL and token to the service console.
3. Enable `/setup` for bootstrap only.
4. Allow creation of exactly one initial administrator.
5. Assign `system-admin`.
6. Invalidate the token atomically.
7. Disable bootstrap once an administrator exists.

Token requirements:

```text
>= 256 bits entropy
single-use
expires in 30 minutes
stored only as a hash
```

Ordinary user creation occurs through the administration interface after bootstrap.

A deployment may alternatively provide a one-shot administrative bootstrap command later, but it must obey the same one-time semantics and must not introduce long-lived admin credentials into environment variables.

---

# 28. PostgreSQL

PostgreSQL is the only supported database in v1.

Minimum supported PostgreSQL should track the versions supported by the selected current pgx release and project deployment policy. The initial development target is PostgreSQL 15+; tests should run against a current supported release.

The initial schema contains:

```text
users
roles
permissions
user_roles
role_permissions
clients
client_redirect_uris
client_post_logout_uris
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

Migrations are embedded in the executable and applied in filename/version order while holding a PostgreSQL advisory lock.

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

User passwords use Argon2id.

The following require reversible encryption and MUST be encrypted with a deployment master key held outside PostgreSQL:

```text
TOTP seeds
signing private keys
future protocol shared secrets if the service ever owns them
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

Forwarded headers are trusted only from explicitly configured reverse proxies if that support is added.

Recommended security headers:

```text
Content-Security-Policy
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer
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

user.created
user.updated
user.enabled
user.disabled
user.deleted
user.password_reset

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
DATABASE_URL
AUTHD_MASTER_KEY_FILE or AUTHD_MASTER_KEY
AUTHD_DEVELOPMENT
```

Users, roles, permissions, and clients do not live in configuration files.

They live in PostgreSQL and are edited through the web administration interface.

Secrets should be supplied through protected files or narrowly scoped environment variables only when the secret cannot itself be managed through encrypted application storage.

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

## 38.1 RADIUS Direction

Potential uses:

```text
VPN/Wi-Fi/network access
router administrative login where RADIUS is appropriate
role/permission -> VLAN/filter/vendor attributes
```

RADIUS implementation must explicitly choose supported authentication methods. `authd` will not weaken Argon2id password storage to satisfy legacy methods that require recoverable passwords or NT hashes without an explicit separate security decision.

RADIUS over TLS/RadSec should be preferred where deployment support permits it.

## 38.2 TACACS+ Direction

Potential uses:

```text
router/switch administrator authentication
command authorization
accounting
```

Command authorization should map explicit configured role/permission facts into TACACS+ authorization results. Do not add a general-purpose policy language unless real command policy cannot be represented cleanly by data rows.

---

# 39. bdcmaps Compatibility Profile

The first client is the existing `yellowman/bdcmaps` OIDC implementation.

Observed client behavior that `authd` MUST support:

```text
OIDC discovery at /.well-known/openid-configuration
Authorization Code flow
PKCE S256
nonce validation
login_hint
JWKS validation
RS256 ID tokens
fresh-database configured scopes default to: openid profile email
client-code fallback scopes (when no scopes are supplied): openid profile email groups
email/email_verified claims
groups claim is available for application role mapping when requested
client_secret supplied in token request body
```

Therefore the first `bdcmaps` client should be registered approximately as:

```text
name: BDC Maps
client_id: bdcmaps
type: confidential
redirect URI: https://<bdcmaps-origin>/auth/callback
identity scopes: openid profile email groups
client auth: client_secret_post accepted
PKCE: required
```

The exact production origin is deployment-specific and MUST NOT be guessed or built into `authd`.

`bdcmaps` currently maps configured `groups` claim values to its own application roles. `authd` role names can be selected to match the desired BDC group configuration without changing the OIDC client.

Longer-term, `bdcmaps` may migrate authorization from broad group-to-role mapping toward application permission scopes, but first integration does not require that rewrite.

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
16. `groups` and `roles` claims contain only current local role names and cannot be injected by client input.
17. A future RADIUS/TACACS+ adapter cannot bypass the same enabled/disabled user state and role/permission resolver.

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
email claims
groups claim
roles claim
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
6. Create users and assign roles.
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
8. Refresh using rotating refresh tokens.
9. Use /userinfo when needed.
10. Perform RP-initiated logout.
```

`bdcmaps` can complete its existing OIDC flow without a provider-specific client-code fork.

That is the v1 product.

RADIUS/TACACS+ may be developed after the central OIDC path is proven, but their future needs are already prevented from forcing a second identity model.

---

# 44. Normative Protocol References

Implementation should conform to applicable portions of:

```text
OpenID Connect Core 1.0
OpenID Connect Discovery 1.0
OpenID Connect RP-Initiated Logout 1.0

OAuth 2.0 / RFC 6749
OAuth Token Revocation / RFC 7009
PKCE / RFC 7636
OAuth Authorization Server Metadata / RFC 8414
OAuth Authorization Server Issuer Identification / RFC 9207
OAuth 2.0 Security Best Current Practice / RFC 9700
```

Where `authd` intentionally supports only a subset of optional protocol behavior, discovery metadata MUST describe the implemented subset accurately.
