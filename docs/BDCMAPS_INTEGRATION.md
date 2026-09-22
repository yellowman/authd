# bdcmaps integration profile

This document records the first real relying-party contract for `authd`.
It is based on the current `yellowman/bdcmaps` `main` branch inspected on
2026-09-21, rather than on a hypothetical OIDC client.

## First login, in operator order

Read [Using authd](../OPERATOR_GUIDE.md#4-connect-bdc-maps-first) for the complete
walkthrough. The authd browser has the same starting point at **Administration →
Start here**. Do not configure every section just to connect BDC.

1. **authd Roles:** create the four `bdcmaps-…` roles below; no permission
   checkboxes are required for BDC group mapping.
2. **authd Users:** enter the person's email and assign the intended role. A
   forced password change must be completed at Account before retrying BDC.
3. **authd Clients:** create `bdcmaps`, confidential, 300-second access tokens,
   exact callback, and allowed `openid profile email groups`. Initially keep
   refresh/offline access off. Enroll MFA before enabling a required-MFA policy.
4. **BDC backend:** set `OIDC_CLIENT_SECRET` to the one-time generated secret.
   Use authd's saved **Copy into BDC Maps** details for issuer/client/callback.
5. **BDC OIDC settings:** request the same four scopes, set `group_claim=groups`,
   and configure the four exact name mappings. Those settings are not pushed by
   authd.
6. **Test from BDC:** sign in as an administrator and as a restricted person;
   inspect the role inside BDC. Provider login alone does not prove its callback.

For the named deployment, the exact callback would be
`https://maps.ykwc.com/auth/callback`; it is not a verified live deployment claim.
Keep authd's issuer as its public HTTPS origin, never its Unix-socket address.

### New BDC installation versus an existing one

The reviewed BDC tree's `deploy/production/bootstrap-oidc.sql` configures the first
OIDC settings and explicitly links the initial administrator by issuer + subject.
It is a **BDC** installer operation, not an authd command. Edit the authd user to
find the stable subject shown in **Identity used by applications**. For an existing
BDC installation, use its own OIDC administration/settings and an explicit account
linking/provisioning procedure; do not run a fresh-install seed against existing
users or join identities merely by email.

The reviewed BDC schema starts with `auto_provision=false` and a `viewer` default
role. The callback may admit a mapped administrator and otherwise applies its
configured provisioning policy. Missing group mapping can fall back to the default
role rather than deny login. Verify both admission and resulting role: authd has
no per-client allowed-users list, and `groups` is not a complete admission policy.

## What bdcmaps already does

`bdcmaps` already implements the useful parts of a modern OIDC relying party:

- provider discovery from `/.well-known/openid-configuration`;
- Authorization Code flow;
- PKCE with `S256`;
- `state` verification;
- `nonce` generation and ID-token verification;
- JWKS retrieval and signature verification;
- issuer and audience validation;
- optional `login_hint`;
- configurable required `amr` values;
- a configurable role/group claim;
- local session creation after the OIDC login completes.

Its callback endpoint is:

```text
/auth/callback
```

The exact full redirect URI depends on the deployment origin and MUST be
registered literally in `authd`.

## authd client record

Create the first client with approximately this shape:

```text
name:                   BDC Maps
client_id:              bdcmaps
type:                   confidential
redirect_uri:           https://<bdcmaps-origin>/auth/callback
identity scopes:        openid profile email groups
refresh tokens:         disabled initially
require MFA:            deployment decision
```

`authd` supports both `client_secret_basic` and `client_secret_post`.
`client_secret_post` is required for compatibility with the current bdcmaps
client, which sends `client_secret` in the token request form body. New clients
should prefer `client_secret_basic` when their library supports it.

## bdcmaps settings

The current fresh bdcmaps schema defaults its OIDC scopes to:

```text
openid
profile
email
```

and defaults the role/group claim name to:

```text
groups
```

For authd role mapping, add `groups` to the requested scopes:

```text
openid
profile
email
groups
```

Configure:

```text
issuer_url    = https://<authd-origin>
client_id     = bdcmaps
redirect_url  = https://<bdcmaps-origin>/auth/callback
group_claim   = groups
```

Place the generated client secret in bdcmaps' existing
`OIDC_CLIENT_SECRET` runtime secret.

## Roles for the first deployment

`bdcmaps` maps configured group/role names to its internal role ladder:

```text
administrator
reviewer
planner
viewer
```

A clean authd convention is:

```text
bdcmaps-administrator
bdcmaps-reviewer
bdcmaps-planner
bdcmaps-viewer
```

These are ordinary authd roles, not a second "group" object type.
When the OIDC `groups` scope is requested, authd emits the user's assigned role
names in the `groups` claim. The `roles` scope/claim is an equivalent modern
alias over the same role set.

Configure bdcmaps' administrator/reviewer/planner/viewer group lists with the
corresponding authd role names.

## Permissions versus bdcmaps' current role model

The first integration does not need a bdcmaps rewrite. Its existing local role
mapping can consume the `groups` claim immediately.

For new applications, authd permissions should normally be the authorization
contract and should be requested as OAuth scopes, for example:

```text
bdcmaps.map.read
bdcmaps.plan.write
bdcmaps.filing.review
bdcmaps.junos.authorize
```

Roles are operator-managed bundles of those permissions. Applications should
not have to understand the organization-wide meaning of a role name when an
atomic permission can express the capability directly.

bdcmaps can move toward permission-scope authorization later if useful; it is
not a prerequisite for the first login.

## Compatibility acceptance test

Before calling the first integration complete, exercise this exact sequence:

```text
1. bdcmaps discovers authd.
2. bdcmaps sends an authorization request with state, nonce, and PKCE S256.
3. authd authenticates a local user.
4. authd returns a one-use authorization code.
5. bdcmaps exchanges the code using client_secret_post and the PKCE verifier.
6. bdcmaps validates authd's RS256 ID token against JWKS.
7. ID token contains email and the configured groups claim.
8. bdcmaps maps a group to viewer/planner/reviewer/administrator.
9. A changed authd role is reflected at the next bdcmaps login.
10. Disabled authd users cannot establish new bdcmaps sessions.
```

## v0.9.0 qualification additions

The configured `openid profile email groups` code-flow profile remains valid.
Do not claim real BDC interoperability from authd's similarly shaped test client.
Run the actual BDC callback with this release. BDC's own local role mapping/session
lifetime still needs an explicit revocation policy; it is not bounded by authd's
five-minute JWT lifetime.

A client that is extended to request refresh tokens must request
`openid offline_access` with `prompt=consent`, handle the provider's consent page,
and serialize refresh-token rotation. Use an essential `acr` claim selector or
client `require_mfa` for mandatory MFA, never `acr_values` alone. For full examples
and validation rules read `RP_INTEGRATION.md`.
