# Building an OIDC client for authd

This document is sufficient to register an application, sign in a user, and
authorize an application operation with authd using an ordinary OIDC client
library. No separate authd-specific registration endpoint is needed. One local
behavior is that authd turns application-prefixed values in the standard registration
`scope` field into permission names visible to its administrator. An optional
authd extension can also create role and group templates. Registration never
assigns a user to a role or group.

## What is standard, and what is authd-specific

OIDC discovery, Authorization Code with PKCE, JWT validation, and OAuth
[Dynamic Client Registration](https://www.rfc-editor.org/rfc/rfc7591.html)
are standard protocol features. The registration request's `scope` property
is standard client metadata. A generic OIDC client library can handle sign-in
and token validation; its DCR support, if present, can send this metadata.

authd's interpretation of an application-prefixed registration scope as a
permission in its administrator catalog and the `authd_role_templates` and
`authd_group_templates` metadata are **authd-specific**. So are the
`authd registration-token` command, prefix-limited one-use token policy,
groups/roles that grant those permissions, and partial grants based on those
roles. These are server policy built on standard OAuth scope values, not
features guaranteed by every DCR or OIDC provider. With another provider,
check how that provider registers scopes and assigns them to users; do not
assume it creates a permission catalog, roles, or groups from registration.

| Capability | Protocol status |
| --- | --- |
| OIDC discovery, code + PKCE, token validation | Standard OIDC/OAuth |
| DCR `scope`, `redirect_uris`, `client_name` | Standard [RFC 7591](https://www.rfc-editor.org/rfc/rfc7591.html) metadata |
| Per-client read/update URI and bearer management token | [RFC 7592](https://www.rfc-editor.org/rfc/rfc7592.html) shape; authd implements read, application-scope replacement, and refresh opt-in/out, not delete or arbitrary metadata editing |
| Treat app-prefixed scopes as permissions | authd-specific policy |
| `authd_role_templates`, `authd_group_templates`, groups, memberships | authd-specific extension; other OIDC servers need not support it |

## 1. Choose the application's permission scopes

Use stable, lowercase, application-prefixed names such as
`networkmap.site.read`, `networkmap.site.write`, and
`networkmap.coverage.run`. A scope should mean one
operation your application will actually check. Keep `openid`, `profile`, and
`email` as OIDC identity scopes; do not use `groups` or role names as a
substitute for application permission checks. authd currently sends **role
names**, not group names, in its optional `groups` claim for older clients.

An authd administrator gives the app creator a one-use initial registration
token restricted to its prefix. On the authd host, with `DATABASE_URL` set to
the authd runtime database, the operator runs:

```sh
authd registration-token networkmap.
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
  "client_name": "Network Map",
  "redirect_uris": ["https://map.example.com/oidc/callback"],
  "grant_types": ["authorization_code"],
  "response_types": ["code"],
  "token_endpoint_auth_method": "client_secret_basic",
  "scope": "openid profile email networkmap.site.read networkmap.site.write networkmap.coverage.run",
  "authd_role_templates": [
    {"name": "networkmap.viewer", "description": "Read sites", "scopes": ["networkmap.site.read"]},
    {"name": "networkmap.planner", "description": "Edit sites and run coverage", "scopes": ["networkmap.site.read", "networkmap.site.write", "networkmap.coverage.run"]}
  ],
  "authd_group_templates": [
    {"name": "networkmap.engineering", "description": "Map engineers", "roles": ["networkmap.planner"]}
  ]
}
```

The two `authd_*_templates` keys are **not** standard DCR metadata. Omit them
for a portable registration request. authd creates only new names inside the
token's namespace; a collision with an existing role or group rejects the
transaction. Role scopes must be among this request's application scopes,
and group roles must be among its submitted role templates. The transaction
creates no user membership. Other OIDC providers may ignore these keys, so a
client must not assume template creation unless it receives an authd response
and the administrator verifies the result.

The redirect URI must match the deployed callback **exactly**. Use HTTPS;
loopback HTTP is accepted only for local development. authd currently
registers confidential Authorization Code clients with PKCE (S256). It accepts
`client_secret_basic` and `client_secret_post`; use Basic unless your library
requires the latter. Public DCR clients and implicit/hybrid flows are not
implemented. The registration request may omit
`grant_types`, `response_types`, and `token_endpoint_auth_method` to get the
values above: refresh is off by default. To opt in, request both
`"grant_types": ["authorization_code", "refresh_token"]` and `offline_access`
in `scope`. Requesting only one of the pair is rejected. This uses standard
RFC 7591 metadata and OIDC offline access, not an authd extension. Older authd
versions reject both; make refresh an explicit deployment option rather than
assuming every provider accepts it. Inspect the registration response's actual
`grant_types` and `scope`; discovery advertising refresh support is not a grant
to this particular client.
authd records the chosen client authentication method and requires that same
method at its token and revocation endpoints. Scope updates do not change it.
Registrations created before method recording retain their previous Basic/POST
compatibility; their management response omits the unknown method.

On success, authd returns HTTP 201 JSON with `client_id`, a one-time
`client_secret`, `registration_client_uri`, `registration_access_token`, and the
registered metadata. Store both secrets in the
application's protected runtime configuration, not its repository. The
initial registration token is consumed atomically, including permission and
template creation and client registration. A second use fails. The management
token belongs only to this client, not to its users or an authd administrator.

The token's namespace is enforced server-side: a `networkmap.` token cannot
register `otherapp.items.write` or `system.admin`. Without role templates,
authd creates each permission but puts it in no role.

## 3. Have the administrator grant permissions

If the client registered templates, inspect them in authd Administration;
otherwise create roles containing selected permissions and groups containing
those roles there. Assign a role directly to a user or add users as group
members. A user
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
`networkmap.site.read` and `networkmap.site.write` but Alice has only read,
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
if !accessToken.HasScope("networkmap.site.write") {
    // 403 Forbidden; do not perform the write.
}
```

Never treat the ID token's `groups`, `roles`, or email as equivalent to an
application permission. Verify the token before reading its scope. If the
application creates its own cookie session from a validated access token,
carry only the validated grants into that session. Those grants must expire
**no later than the access token**. Without refresh, the local session must end
then too. The default dynamic-client access token lifetime is five minutes;
a different lifetime can be set in authd's client administration. With refresh,
the cookie session may last longer, bounded by the application's absolute
session limit, but every operation must have an unexpired, validated grant.
Role changes do not retract an already-issued JWT; the maximum stale-grant
window is the remaining access-token lifetime, not the longer cookie lifetime.

### Optional server-side refresh

1. Register `authorization_code` plus `refresh_token`, with `openid` and
   `offline_access` alongside the application's scopes. Existing managed clients
   can opt in using the full metadata `PUT` described in section 7. No schema
   upgrade or new client secret is needed just for this opt-in.
2. Start the normal Code + S256 PKCE flow with `scope` including
   `offline_access` and `prompt=consent`. authd requires explicit consent;
   without it, offline access is removed. Inspect the actual token response:
   requesting refresh does not guarantee receiving a `refresh_token`.
3. Keep the refresh credential in protected backend storage, never in browser
   JavaScript, URLs, logs, or the session cookie. Send a form-encoded request to
   discovery's `token_endpoint` with `grant_type=refresh_token` and the latest
   `refresh_token`, authenticating with the client's registered Basic or POST
   method. Omit `scope` to retain the grant; an explicit scope may only narrow it.
4. Validate the new access token's signature, issuer, audience/client binding,
   subject, expiry, and actual scope. Replace the session's grants and grant
   expiry; never extend old grants merely because a refresh request succeeded.
   authd rechecks user/client state, session revocation, and current permissions.
   If the refreshed scope set includes a permission the user or client no
   longer holds, authd rejects it with `invalid_grant`; it does not silently
   shrink that set. A fresh dynamic-client login can obtain a narrower grant.
   Do not use refresh as recent authentication or step-up.
5. Serialize refresh for each local session across tabs, requests **and app
   processes**. Atomically persist the replacement refresh token with the new
   grants. authd rotates on every successful refresh; reuse revokes the family.
   A lost response or ambiguous storage commit can require a new sign-in. Do
   not blindly retry the old token.
6. On `invalid_grant`, revoked access, or invalid token validation, discard the
   local refresh credential and require a new sign-in. During provider outages,
   never serve requests using expired grants. Logout should remove the local
   credential and attempt revocation through the discovered revocation endpoint.
   Refresh idle/absolute limits and explicit provider-session revocation still
   apply. Natural expiry of authd's browser session does not itself revoke a
   previously consented offline grant.

authd's consent screen compares the request with that person's last explicit
approval for the client: additions are prominent, prior access is collapsed,
and omitted items are labeled as not requested rather than revoked. This is
presentation history, not a permission grant or a bypass of `prompt=consent`.
An upgrade starts with no recorded approvals. Standard clients need no new
endpoint, parameter, or authd extension for this comparison.

These are standard [OAuth refresh requests](https://www.rfc-editor.org/rfc/rfc6749#section-6)
and [OIDC offline access](https://openid.net/specs/openid-connect-core-1_0.html#OfflineAccess).
The paired registration opt-in, explicit-consent requirement, JWT scope contract,
and rotation policy are authd's documented provider behavior; no custom refresh
grant or `authd_*` field is required. Providers may differ, so check responses.

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

## 7. On-demand registration updates

Keep the `registration_client_uri` and `registration_access_token` returned by
the initial registration. Send `GET` to that URI with the management token as
`Authorization: Bearer ...` to inspect the current client. To replace its
allowed application scopes, send `PUT` to the **same URI** with the token and
the full supported client metadata: unchanged `client_id`, `client_name`,
`redirect_uris`, `response_types`, and
`token_endpoint_auth_method`, plus the new complete `scope` string. Include
the original `client_secret` so authd can verify it without storing plaintext.
Supply `grant_types` too: retain `authorization_code` and add or remove
`refresh_token` together with `offline_access` in `scope` to opt in or out.
Other identity scopes remain unchanged. Opting out revokes existing refresh
families; opting back in requires a fresh consented login. Updates reject a
concurrent policy change rather than overwriting it; re-read metadata and retry.
The existing client ID and secret remain valid. Roles and group memberships
are not auto-granted or changed by a scope update; newly created permissions
must be assigned separately. A changed scope list takes effect on a fresh
authorization flow, not retroactively in already-issued tokens.

For a client registered before management tokens were available, an authd
operator can issue one for that existing dynamic client without replacing it:

```sh
authd registration-management-token CLIENT_ID networkmap.
```

Run this with authd's runtime database configuration and `AUTHD_ISSUER`. It
prints the management URI and token once. Reissuing rotates and invalidates
the previous management token. The current management endpoint supports
application-scope replacement and refresh opt-in/out; role/group templates may be submitted during initial
registration but cannot yet be edited through this endpoint. That is a
deliberate authd limitation, not a general OIDC feature.
