# Application integration blueprint

Use this guide to turn an application's access model into an authd-backed
sign-in flow. It applies to a new application regardless of its domain. For
the exact OIDC request, registration metadata, and token checks, use
[Building an OIDC client](APP_CREATOR_OIDC.md). For the operator's forms, use
[Adding an app](ADDING_AN_APP.md).

## Divide responsibility before registering

The application defines operations it can actually enforce. For example, an
inventory application might define `inventory.records.read` and
`inventory.records.write`. authd stores those as application permissions and
may grant them as OAuth scopes. authd also owns human accounts, sign-in, MFA,
and optional shared roles/groups. The application still decides which inventory
records, customers, or projects a signed-in person can access.

```text
app's operations → permission scopes → authd roles → optional authd groups/users
        ↑                 │
        └── enforce granted access-token scopes plus local resource rules
```

A role bundles permissions; a group grants roles to its member users. A user
may also hold roles directly. Multiple assignments combine. Neither creating
a permission nor registering a client gives anyone access by itself.

## Register and grant

1. Choose a stable application namespace and a small set of exact operation
   scopes. Do not use `system.admin` or identity scopes as app permissions.
2. Register a confidential Authorization Code + PKCE client with exact HTTPS
   callback, allowed identity scopes, and the app's permission scopes. Manual
   registration is available in Administration. Dynamic Client Registration
   uses the discovery-advertised endpoint and a one-use, prefix-limited token.
   The standard `scope` metadata lists what the client may request; authd's
   permission-catalog interpretation is local behavior.
3. Optionally submit authd-specific role/group templates with dynamic
   registration, or have an administrator create them afterward. Templates
   create no user memberships. Have an administrator review role permissions
   and assign roles directly or add users to groups.
4. Store the returned client ID and, for a confidential client, its one-time
   client secret separately in protected application configuration. The client
   secret is not the person's password. An optional registration-management
   credential is different again; it updates the existing client's allowed
   scope list and refresh opt-in, not user assignments.

For example, `inventory.viewer` could contain `inventory.records.read`, while
`inventory.editor` could contain read and write. A group named
`inventory.operations` could grant `inventory.editor` to its members. The
application need not know this group or role model; it checks the granted
`inventory.records.write` scope before a write, then its own record-level rule.

## Sign in and enforce

Start login from the application using OIDC discovery, Authorization Code,
PKCE S256, fresh state and nonce. Verify the ID token's signature, issuer,
audience, expiry and nonce. Link a local account only by the stable
`(issuer, subject)` pair, not by matching an email address. Do not treat the ID
token as an authorization grant.

Verify the signed access token's purpose, issuer, audience, time bounds and
exact `scope` tokens before using it for an operation. A dynamically registered
client can receive fewer application scopes than it requested when the user
lacks permissions; manually created clients currently reject that request
instead. In both cases, the application must use the **granted** scopes, never
the requested list or an authd role name, for operation authorization.

The optional `groups` and `roles` OIDC claims contain effective **role names**,
not authd group names. They exist for applications that intentionally use
legacy role-name mapping; new scope-based integrations need neither claim.
Application-local memberships and ownership checks still apply after a scope
check. An enabled, zero-role user can sign in to an identity-only client, so
the application must define its own admission rule.

## Keep grants current without reloading the application

Refresh is optional and off by default. Dynamic clients opt in with standard
`grant_types: ["authorization_code", "refresh_token"]` and `offline_access`
in `scope`; request `prompt=consent` during login. This is OAuth/OIDC behavior,
not the authd-specific role/group-template extension. Older authd versions
reject the opt-in, and other providers may grant less than requested: inspect
the returned registration metadata and token response.

authd compares each consent request with the person's last explicit approval
for that client. New access is shown first; prior access can be expanded.
This changes only the provider's presentation, not the standard client flow,
granted scopes, or the meaning of `prompt=consent`.

Without refresh, end the application's session when its access token expires.
With refresh, keep a separately bounded local session, but allow operations
only while its access-token grants remain current. Refresh on the backend,
validate the new token against the same issuer, client and subject, and replace
the granted permissions. Serialize rotation across requests and processes;
store each replacement token atomically with the grants in protected storage.
Never place refresh tokens in the browser or extend expired grants during an
outage. Revocation, reuse, and lost/ambiguous refresh responses can require a
new sign-in. See [the complete refresh contract](APP_CREATOR_OIDC.md#optional-server-side-refresh).

## Qualify the actual application

Test a fresh login from the application through its real callback, not just
authd's login page. Check a permitted user, a restricted user, a denied write,
and a user with no app permission. Confirm the application sees only granted
scopes and enforces local record rules. Re-test after changing a role or group:
already-issued grants are snapshots until the access token expires or is
replaced. For refresh-enabled clients, test concurrent requests, rotation,
permission removal, user/session revocation, provider outage, local session
limits, and logout. Confirm long-lived streams also stop using expired or
revoked grants. Record the app revision, client
registration, callback, token behavior, and negative-access results. A provider
unit test or one successful login alone does not qualify all authorization
paths.

For the general relying-party identity and tenancy boundary, see
[RP integration](RP_INTEGRATION.md). For exact standard-versus-authd extension
details and management limitations, see [Building an OIDC client](APP_CREATOR_OIDC.md).
