# Form field reference

This reference uses the same concepts as [Adding an app](ADDING_AN_APP.md).
Field explanations stay visible beside the form controls; this page collects
the details in one place. Nothing here changes the protocol or grants access.

## Users

| Field | Meaning and effect |
|---|---|
| Sign-in username | The name the person types at authd. Comparison is case-insensitive. Renaming it does not change their OIDC subject. |
| Display name | A human-readable name exposed through `profile`; not a sign-in name or identifier. |
| Email | Optional to authd, but required by some apps. `email` scope controls release. |
| Initial / new password | Used only at authd. At least 12 characters, with no mandatory composition rules. Distribute an initial password through a trusted channel. |
| Direct roles | Roles assigned on this user form. Group-derived roles are shown as effective roles but are managed in Groups. Creating a role alone assigns nobody. |
| Account enabled | Disabling blocks authentication and revokes authd sessions and refresh grants. An app's independent cookie may survive until that app revokes it. |
| Email verified | An explicit administrator assertion, not a checkbox to make login work. Changing the email clears it; authd sends no verification mail. |
| Require password change | The person must set their own password on Account before using apps or administration. |
| Issuer and subject (`sub`) | Stable external identity pair for deliberate account linking. These are identifiers, not credentials. Do not link by email alone. |

## Groups, roles and permissions

Groups are reusable user-to-role assignments. In **Groups**, select the group's
roles and member users. A person can belong to several groups and have direct
roles; their effective roles are the union. Removing a member or role removes
that source of access at the next grant evaluation. An existing application
session or already-issued access token may remain valid until its own expiry.
Group names are administrative labels; the OIDC `groups` claim contains
**effective role names**, not these labels. Groups cannot contain other groups.

| Field | Meaning and effect |
|---|---|
| Role name | Exact name exposed in `groups` / `roles`. Prefer app-qualified names. Renaming a role can break app-side mappings. |
| Role description | Operator explanation only. It is not sent as a role name and has no permission effect. |
| Included permissions | Operations bundled by this role. Empty is possible for a legacy role-name-claim integration. |
| Permission name | Exact operation scope the app implements and checks, such as `inventory.items.read`. Names are case-sensitive; use lowercase. |
| Permission description | Explain the operation to other operators. The text does not implement access control. |

`system-admin` contains `system.admin` and administers authd itself. Do not use it
as an application's ordinary administrator role or request it as an app scope.
Keep at least one enabled user with this role assigned directly; the
last-administrator safeguard is based on direct assignments.
Permissions cannot be assigned directly to a user; assign the role containing them.

## Clients

| Field | Meaning and effect |
|---|---|
| Client ID | Stable machine identifier copied to the app. Immutable after creation. |
| Application name | Human-facing name, including on consent. Renaming does not change client ID. |
| Confidential | A server-side backend can keep a secret; not a statement that the app is internal/private. |
| Public | Browser/native code cannot protect a shared secret. PKCE is still mandatory. |
| Sign-in callback URLs (redirect URIs) | The app's receiving endpoint. Exact matching; one per line, no wildcards. Do not enter authd's `/login`. |
| After-sign-out return URLs | Optional allow-list for RP-initiated logout redirects; not a front/back-channel logout implementation. |
| Access token lifetime (seconds) | Allowed range 30–3600; 300 is five minutes. It does not set authd's SSO lifetime or the app's session-cookie lifetime. |
| Client enabled | Controls new authorizations and token requests; disabling does not erase already-issued JWTs or app cookies. |
| Require MFA | Client-wide minimum of password plus enrolled TOTP or a recovery code. Enroll users before enabling it. |
| Allow refresh tokens | Permits offline tokens when explicitly requested and consented. The app must serialize refresh and replace each rotated token. |
| Client secret | Backend credential displayed only on creation/rotation. Rotation immediately invalidates the previous secret. Update the app at the same time. |

### Identity scopes

| Scope | What it requests |
|---|---|
| `openid` | OpenID Connect authentication and the stable subject. |
| `profile` | Profile fields such as display name and sign-in username. |
| `email` | Email address and its actual verification state, when an address exists. |
| `groups` | The person's effective authd role names under the conventional `groups` claim; not authd group names. |
| `roles` | The same effective role names under `roles`; not another role directory. |
| `offline_access` | Offline refresh capability, also requiring client permission and consent. Not needed merely to log in. |

The scopes are **allow-lists** at registration. The app must request them.
Application permission scopes additionally require the user to hold them through
a direct or group-derived role. A manually created client denies a request with
a missing user permission. A dynamically registered client returns a narrower
grant instead. Always check the granted scopes. Dynamic registration currently
supports confidential code/PKCE clients with optional, explicitly requested
refresh tokens; see
[the OIDC client guide](APP_CREATOR_OIDC.md).

## Sessions, keys and audit

**Provider sessions** are sign-ins at authd, not every relying app's session. A
session's authentication methods describe what actually happened: `pwd` is
password, `otp` is the authenticator code and `recovery` is a recovery code.
Revocation affects that authd session and associated grants, not arbitrary app cookies.

**Signing keys** sign JWTs; public keys in JWKS let apps verify them. Rotation is
not part of adding an app. Old public keys remain available. The deployment master
key encrypts private signing keys and TOTP seeds and is a different secret.

**Audit events** record authd activity. Request references help correlate failures
without exposing secrets. They are not an application's callback log, and an
`authd` login event alone does not establish a completed application login.
