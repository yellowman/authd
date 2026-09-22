# Adding an app to authd

Connect the application once, then manage people's sign-in and shared access from
here. You do not create a second password for the person in each application.

The application must already support **OpenID Connect (OIDC)**, or its developer
must add that support. Creating a client in authd does not add login code to an app.

## 1. Decide how the app will use access information

Choose the model supported by the application, not whichever has the most fields.

| App integration | What to set up in authd | What remains in the app |
|---|---|---|
| Identity only | A user and a client; start with `openid profile email`. No roles are needed just to prove identity. | Admission, membership and all permissions. |
| Roles / groups | Named roles assigned to users. Allow `groups` (or `roles`) and make the app request it. | A one-time mapping from each incoming role name to what it means in that app, plus local membership checks. |
| Permission scopes | Permissions the app actually checks, bundled in roles and assigned to users. Allow those scopes on the client. | Requests and checks for those scopes, plus ownership, tenant and resource checks. |

These can be combined. A tenant-aware application normally keeps its tenant
membership even when authd supplies shared permissions.

**Do not grant `system-admin` to ordinary application users.** That role manages
authd itself. It is not a universal application-administrator role.

## 2. Collect the application's OIDC settings

Find its authentication settings or integration instructions. Before saving the
client, know its exact **sign-in callback URL**, the identity claims it requires,
and whether its backend can keep a client secret. The callback is an endpoint in
the application, not authd's login page.

For an example application called Inventory, its developer might specify:

```text
Application name: Inventory
Client ID: inventory
Callback: https://inventory.example.com/auth/callback
Requested scopes: openid profile email groups
Client type: confidential (a server-side application)
```

These are examples, not automatic defaults. Use the callback supplied by the app.
A different path, hostname, scheme or trailing slash is a different callback.

## 3. Set up roles and people

For a roles/groups integration, open [Roles](/admin/?view=roles). Create clear,
app-qualified names such as `inventory-viewer` and `inventory-administrator`.
Leave permission checkboxes empty when the app uses role-name mapping only.
The exact role name is what the app receives; the description is for operators.

Open [Users](/admin/?view=users), create or select a person, and assign the intended
role. Merely creating a role does not assign it. Supply an email if the app requires
one. Give an initial password through a trusted channel; authd sends no invitation
email. With **Require password change** selected, the person must change it on
Account before returning to the app.

For a permission-scope integration, first create only the agreed operation names
in [Permissions](/admin/?view=permissions), for example `inventory.items.read`.
Add them to the relevant role, then assign that role to people. Inventing a
permission name here does not implement a permission check in the app.

## 4. Register the application

Open [Clients](/admin/?view=clients) and complete the registration:

| Field | What to enter |
|---|---|
| Client ID | A stable app identifier, for example `inventory`. Copy it exactly to the app. It cannot be renamed later. |
| Application name | A human-readable name shown at consent, for example Inventory. |
| Client type | Confidential for a backend that can protect a secret. Public for a browser/native app that cannot. This is not whether the application is publicly reachable. |
| Sign-in callback URLs | The exact callback from the app's OIDC settings, one complete URL per line. |
| Identity scopes | Allow only the claims the app requests. Add `groups` or `roles` only for an integration that uses role names. |
| Application permission scopes | Only the operation scopes this app actually requests and checks. Empty is normal for identity-only or group-mapping integration. |
| Access token lifetime | Start at 300 seconds. This is token validity, not how long the person stays signed in to the app. |
| Client enabled | On to allow new authorization and token requests. |
| Require MFA | Enable for the required security policy; enroll intended users' authenticators first. |
| Refresh tokens | Leave off unless the app needs them and implements secure rotation. They also require `offline_access` and explicit consent. |
| After-sign-out return URLs | Optional. Use only if the app implements provider logout and requests a redirect afterward. This is not its sign-in callback. |

See the [field reference](FIELD_REFERENCE.md) for more detail. Saving a client
registers it here; it does not configure or test the application.

## 5. Configure the application side

After saving a confidential client, copy the **one-time client secret** into the
application's protected backend configuration. It is not a person's password or
authd's master key. Never put it in browser JavaScript, a URL, a ticket or a screenshot.

The client's saved connection details show the **issuer / provider URL**, discovery
URL, client ID, allowed scopes and callbacks. Copy those into the app as required.
The issuer is authd's public HTTPS address, never its internal Unix socket or TCP
listener. Public clients use no secret. Every client uses Authorization Code with
PKCE S256.

**Allowed, requested and granted are different:** the client's checkboxes permit
requests. The app must actually request the scopes; the user must also have any
requested application permission. If the user lacks a requested permission,
authorization fails. Do not request every admin permission for an ordinary viewer.

For role-name integrations, configure the app's group-to-role mappings. For
existing accounts, link the exact **issuer + subject (`sub`)** deliberately. Never
merge accounts automatically because their emails happen to match. Edit a user
to find their stable subject. Developer details: [RP integration contract](RP_INTEGRATION.md).

## 6. Test from the application

Start a fresh sign-in **from the app**. It should redirect to authd, authenticate
the person, return through the app's callback and establish a usable application
session. Check the role or permission **inside the app**. Then test a restricted
user and a denied operation. A client row, successful authd login or discovery
response alone does not establish that the integration works.

Record which app, release, callback and access checks were exercised. The
[validation record](../VALIDATION.md) separates actual integrated-app results from
provider unit tests and remaining qualification work. Do not rebootstrap or rotate
keys just to add another app.

## Access boundaries to remember

An enabled user with no roles can authenticate to an identity-only client. There
is **no separate per-client allowed-users list** in this release. The app must
apply its own admission policy or require an implemented permission scope.

Clients allowed to request `groups` or `roles` can receive all assigned authd role
names for that person, not just names prefixed with the app's name. Do not release
those claims to an app that should not see them.

An authd login does not create a tenant, organization, PBX, room, project or other
application-local membership. Apps may keep domain-local identities and may trust
other identity providers directly. authd need not own every customer identity.

## When something fails

| Symptom | What to check |
|---|---|
| Form refused before saving | Reload through authd's public address; check Origin, proxy headers and CSRF. Do not disable these checks. |
| Admin page opens but save is denied | Privileged writes require a sign-in within the last 10 minutes. Sign in again and reopen the form. |
| Invalid client / callback | Compare client ID, secret and exact registered callback on both sides. |
| Invalid scope / access denied | Check client allow-lists, requested scopes and the user's role permissions. |
| Sign-in returns but access is wrong | Check the app's role mappings, memberships and default role. Test with a new app session. |
| MFA required but no code is available | Enroll an authenticator on Account or use a remaining recovery code. Resetting MFA does not satisfy an MFA requirement. |
| Disabled here but still signed in there | The app may retain its own cookie. Revoke its local sessions too; back-channel logout is not implemented. |
| Service unavailable / error reference | Correlate the timestamp and request reference with daemon/proxy logs. Keep credentials and token-bearing URLs out of tickets. |

For routine account operations, see [Using authd](../OPERATOR_GUIDE.md).
For installation, sockets, PostgreSQL and upgrades, see [Deployment](../DEPLOYMENT.md).
