# Building an OIDC client for authd

This document is sufficient to register an application, sign in a user, and
authorize an application operation with authd using an ordinary OIDC client
library. No authd-specific registration API is needed. The one local extension
is that authd turns application-prefixed values in the standard registration
`scope` field into permission names visible to its administrator. Registration
does **not** assign those permissions to any user.

## What is standard, and what is authd-specific

OIDC discovery, Authorization Code with PKCE, JWT validation, and OAuth
[Dynamic Client Registration](https://www.rfc-editor.org/rfc/rfc7591.html)
are standard protocol features. The registration request's `scope` property
is standard client metadata. A generic OIDC client library can handle sign-in
and token validation; its DCR support, if present, can send this metadata.

authd's interpretation of an application-prefixed registration scope as a
permission in its administrator catalog is **authd-specific**. So are the
`authd registration-token` command, prefix-limited one-use token policy,
groups/roles that grant those permissions, and partial grants based on those
roles. These are server policy built on standard OAuth scope values, not
features guaranteed by every DCR or OIDC provider. With another provider,
check how that provider registers scopes and assigns them to users; do not
assume it creates a permission catalog or group assignments from `scope`.

## 1. Choose the application's permission scopes

Use stable, lowercase, application-prefixed names such as
`inventory.items.read` and `inventory.items.write`. A scope should mean one
operation your application will actually check. Keep `openid`, `profile`, and
`email` as OIDC identity scopes; do not use `groups` or role names as a
substitute for application permission checks. authd currently sends **role
names**, not group names, in its optional `groups` claim for older clients.

An authd administrator gives the app creator a one-use initial registration
token restricted to its prefix. On the authd host, with `DATABASE_URL` set to
the authd runtime database, the operator runs:

```sh
authd registration-token inventory.
```

The command prints a 256-bit bearer token once. It expires in 15 minutes and
can register exactly one client. Deliver it privately; do not put it in source
control, logs, or a process argument. The operator must first install authd's
current database migrations (`authd migrate` as the migration owner, then the
documented runtime grants) before using this command.

## 2. Discover and register the client

Fetch `https://AUTH_HOST/.well-known/openid-configuration` over HTTPS and use
its `registration_endpoint`. The current endpoint is `/register`. Send the
initial token as `Authorization: Bearer ...` and JSON using the standard
[RFC 7591](https://www.rfc-editor.org/rfc/rfc7591.html) field names:

```json
{
  "client_name": "Inventory",
  "redirect_uris": ["https://inventory.example.com/oidc/callback"],
  "grant_types": ["authorization_code"],
  "response_types": ["code"],
  "token_endpoint_auth_method": "client_secret_basic",
  "scope": "openid profile email inventory.items.read inventory.items.write"
}
```

The redirect URI must match the deployed callback **exactly**. Use HTTPS;
loopback HTTP is accepted only for local development. authd currently
registers confidential Authorization Code clients with PKCE (S256). It accepts
`client_secret_basic` and `client_secret_post`; use Basic unless your library
requires the latter. Public DCR clients, implicit/hybrid flows, and RFC 7592
registration updates are not implemented. The registration request may omit
`grant_types`, `response_types`, and `token_endpoint_auth_method` to get the
values above. Do not request `offline_access`: dynamically registered clients
do not currently receive refresh tokens.

On success, authd returns HTTP 201 JSON with `client_id`, a one-time
`client_secret`, and the registered metadata. Store the secret in the
application's protected runtime configuration, not its repository. The
initial registration token is consumed atomically, including scope catalog
creation and client registration. A second use fails. Changes to a registered
client currently require an authd administrator to edit its client and
permissions; obtain a new token to register a new client instance.

The token's namespace is enforced server-side: an `inventory.` token cannot
register `otherapp.items.write` or `system.admin`. authd creates each allowed
application permission but does not put it in a role or assign it to a user.

## 3. Have the administrator grant permissions

In authd Administration, create roles containing selected permissions, for
example `inventory.viewer` with `inventory.items.read` and
`inventory.operator` with both scopes. Assign a role directly to a user, or
create a group, put those roles in the group, and add users as members. A user
can have direct roles and belong to several groups; effective permissions are
their union. A registered scope is grantable only when **both** this client
allows it and the user's effective roles contain it.

Group membership is authd administration state, not a required claim or
protocol dependency of the application. The client can ignore `groups` and
`roles` entirely.

## 4. Sign in with a standard OIDC library

Use the discovery document's authorization, token, and JWKS endpoints. Start
the Authorization Code flow with the returned `client_id`, an exact registered
`redirect_uri`, `response_type=code`, a fresh unpredictable `state` and
`nonce`, and PKCE `code_challenge_method=S256`. Request `openid profile email`
plus the application scopes your client understands. On callback, verify
`state`, exchange the code at `token_endpoint` using the client secret and
original PKCE verifier, and validate the ID token's signature, issuer,
audience, expiry, and nonce with your library.

The ID token identifies the user. Use the stable pair `(iss, sub)` as the
external identity key; do not link a local account solely by an unverified
email address. The ID token is **not** an authorization grant.

For dynamically registered clients, authd narrows requested application
scopes to those the signed-in user currently holds. It retains the requested
identity scopes. For example, if the client requests both
`inventory.items.read` and `inventory.items.write` but Alice has only read,
her access token and token response contain read, not write. Existing manually
configured clients retain their prior all-or-deny behavior. Check the **granted
scope** in the token response/access token, never assume a requested scope was
granted.

## 5. Authorize each protected operation

authd issues a signed JWT access token. A resource server must verify its
signature against `jwks_uri`, allow the expected signing algorithm, verify
exact `iss`, intended `aud`/`client_id`, `exp` and other time claims, then
inspect the space-separated `scope` claim. Check exact tokens, not substring
matches:

```go
if !accessToken.HasScope("inventory.items.write") {
    // 403 Forbidden; do not perform the write.
}
```

Never treat the ID token's `groups`, `roles`, or email as equivalent to an
application permission. Verify the token before reading its scope. If the
application creates its own cookie session from a validated access token,
carry only the validated grants into that session and expire it **no later
than the access token**. The default dynamic-client access token lifetime is
one hour; a shorter lifetime can be set in authd's client administration.
Without refresh-token support, re-run the code flow when it expires. Role
changes do not retract an already-issued JWT; the maximum stale-grant window
is the remaining token/session lifetime.

## 6. Minimal end-to-end check

1. Register a client with one read and one write permission. Keep its returned
   client ID and secret private.
2. Create a role with read only, assign it through a group to a test user, and
   complete a fresh OIDC code flow. The access token must contain read but not
   write, and the application's write endpoint must return 403.
3. Add write to that role. A **new** sign-in must receive both scopes; the
   write endpoint can then proceed. Remove write and repeat after the old
   token/session expires to verify revocation latency.
4. Attempt to register a scope outside the initial token's prefix or reuse the
   token. Both requests must fail without creating a client or permission.
