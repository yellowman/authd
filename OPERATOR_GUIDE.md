# Using authd

**Start here after the service is installed.** This guide explains the web
interface and the decisions you need to make. It does not require you to read the
OIDC specification. For database creation, Unix sockets, nginx, service startup,
or upgrades, use [DEPLOYMENT.md](DEPLOYMENT.md). Do not reinstall the server just
to add an application or a person.

## 1. What you are setting up

You are setting up a shared sign-in service, not a new copy of each application.

A person has an account in authd. An application, such as an inventory system, has a **client
registration** in authd. The application sends the person to authd to sign in and
then accepts the result. Their password stays with authd. The application still
controls which of its own records and features the person may use.

The normal path is:

```text
Open the app → choose sign in → authenticate at authd → return to the app
```

Opening authd directly takes you to your **Account** page. It does not launch or configure another app automatically. Administrators also see **Administration**;
its **Start here** page describes the first-client workflow.

There is no app launcher, directory synchronization, customer membership engine,
or RADIUS/TACACS listener in this release.

## 2. The words in the interface

| Word | What it means here | What it does not mean |
|---|---|---|
| User | A person who can authenticate at authd. | An application, database role, or SIP device. |
| Role | A named bundle of permissions, assigned directly to users or through groups. | A universal role that every application automatically understands. |
| Group | A reusable set of users that grants them one or more roles. | The OIDC `groups` claim: that legacy claim contains effective **role names**, not group names. |
| Permission | A stable operation name the application has been written to check. | A way to create application behavior by typing a name here. |
| Client | An application registered to ask authd for sign-in. | A person or a customer's account in your billing system. |
| Issuer | authd's exact public HTTPS address. | Its Unix-socket pathname or internal HTTP listener. |
| Callback / redirect URI | The application's endpoint receiving the sign-in result. | An authd login URL or any arbitrary return page. |
| Scope | Something the client requests in a login/token flow. | A grant just because its checkbox is selected. |
| Subject (`sub`) | The user's stable authd identifier, paired with the issuer. | Their email, username, or permission level. |

`system-admin` is the built-in role for administering **authd**; it contains
`system.admin`. It does not automatically make the person an application administrator.
Keep at least one enabled administrator with `system-admin` assigned **directly**:
the last-administrator safeguard checks direct role assignments, not group-only
administration.
PostgreSQL's `postgres`, `authd_owner`, and `authd_runtime` roles are a third,
separate concept used during installation, not in the Users screen.

### The four secrets are not interchangeable

| Secret | Who uses it | What to do with it |
|---|---|---|
| A person's password | The person signing in at authd. | Give an initial password through a trusted channel; require a change. |
| Client secret | The application's backend, authenticating to authd. | Put it in that application's protected configuration. |
| Master key | The authd daemon decrypting stored TOTP/signing-key material. | Keep it in the installed key file and back it up with the database. Never give it to a client. |
| PostgreSQL runtime password | authd connecting to PostgreSQL. | Keep it in the runtime pgpass file, not an OIDC client field. |

A public client has **no** client secret. Do not put a confidential client secret
in browser JavaScript, a mobile binary, a URL, or a support ticket.

## 3. First administrator

If `/setup` is open, run `authd bootstrap` as the installed service user **with its
installed environment**; the exact native commands are in Deployment, section 9.
It prints a one-use token valid for 30 minutes. It does not start a second daemon.
Enter that token on `/setup` and create your administrator account. This account
manages authd. It is not your PostgreSQL login.

After creation, sign in at `/login` and open **Administration → Start here**.
Initial setup closes permanently; subsequent people are created in **Users**.
Deleting accounts does not reopen setup. Do not rebootstrap during an upgrade.

## 4. Add an application

Follow [Adding an app to authd](docs/ADDING_AN_APP.md). It walks through choosing
identity-only, role-name mapping or permission scopes; creating roles and users;
registering the client; copying connection details; and testing from the app.
You only configure the access model that the app actually implements.
For a reusable developer/operator integration model, see
[Application integration blueprint](docs/APPLICATION_INTEGRATION.md).

Administration → Start here renders that same Markdown. Documentation provides
all shipped Markdown files grouped by their actual directory, searchable by
filename and content, with heading navigation and original source. The index
follows the documentation tree automatically at build time. See [Field reference](docs/FIELD_REFERENCE.md) when a form
label needs more explanation.

## 5. When do I use permissions?

Use them when an application actually checks OAuth permission scopes. This is a
different integration path from a role-name mapping.

For example, suppose an application implements `billing.invoices.read`. Create
that permission in authd, include it in a role, assign the role directly or through a group, and
allow that permission on the application's client. The app requests it during
authorization and checks it when handling the operation.

All parts are necessary:

```text
App implements/checks it
  + permission exists
  + user's direct or group-derived role contains it
  + client is allowed to request it
  + app requests it
  = eligible permission scope in an issued access token
```

Allowing a scope on the client does not give it to every user. Assigning it to a
user's role does not automatically send it to every app. A manually created
client denies authorization if the user lacks a requested application permission;
a dynamically registered client instead narrows the grant to permissions the user
holds. In either case, the app must inspect granted scopes, not assume it received
everything it requested.

Do not create `openid`, `profile`, `email`, `groups`, `roles`, or `offline_access`
as application permissions. Those are built-in protocol scopes. Never use
`system.admin` as an application's authorization scope.

### Admission and privacy limits of this release

An enabled zero-role user can authenticate to an identity-only client. There is
no separate per-client allowed-users list. The relying application must enforce
its own admission/membership policy or use an explicitly required permission.

A client allowed to request `groups` or `roles` can receive **all effective role
names** for that user, including roles granted through groups. There is no per-client role-name filter. Omit these scopes
for clients that should not receive that information. `groups` and `roles` are
released only when allowed and requested, but they are not tenant assignments.

Temary/Liminal keep tenant and resource membership locally; Astmgr also keeps
PBX/extension/device credentials locally. Evident may use authd **or a customer's
own provider**. None of those domain memberships belongs in authd merely because
it handles sign-in. See [RP_INTEGRATION.md](docs/RP_INTEGRATION.md).

## 6. Daily operations

### Add or remove someone

Create the user, assign reviewed direct roles or group memberships, and pass on the initial password securely.
With forced password change, have the person visit Account before testing an app.
For departure, **disable** the account to block new authd logins, revoke its authd
sessions/refresh grants, and retain the identity for review. Also remove/revoke
local app sessions when immediate removal is required. Delete only after reviewing
identity links and audit/data-retention requirements; deleting authd does not erase
that person's the app, Temary, or other application data.

### Change an email

Changing to a different normalized address clears verification. There is no
verification email workflow. **I have independently verified this existing email
address** is an administrator's explicit assertion: save the new address first,
then assert it only after verification. Do not use the checkbox merely to silence
an application's error. The issuer + subject remains the identity key.

### Set up MFA

Open **Account → Authenticator → Enroll authenticator**, enter the current
password, and add the displayed **manual setup key** to an authenticator as a
time-based account. The current screen shows a key and provisioning URI, not a
QR code. Its settings are SHA-1, 6 digits, and a 30-second period. Enter the current
six-digit code to confirm. Enrollment expires after 10 minutes.

After confirmation, save the recovery codes immediately. Each works once; the
plaintext list cannot be retrieved again. Enrollment signs out provider sessions.
At the next login, supply your password and an authenticator or recovery code.
Then enable **Require MFA** on clients that need it. An MFA-required client does
not enroll a missing factor automatically.

For a lost authenticator, use a recovery code or have an administrator verify the
person and **Reset MFA**. Reset removes the factor/recovery material and revokes
sessions/grants; the person must enroll again. Regenerating recovery codes replaces
old unused codes and requires a recent MFA-authenticated session.

### Rotate a client secret

Do this when the secret is lost, exposed, or deliberately being rotated. The old
secret stops working immediately. Save the new value in that application's
protected configuration and reload/restart it as its own procedure requires. There
is no dual-secret overlap. This does not change users' passwords or authd's master
key. Public clients do not have this operation.

### Signing keys versus the master key

authd creates its initial RSA signing key automatically. You normally do nothing
on **Signing Keys** to connect the first app. Rotation selects a new signing key;
old public keys remain in JWKS for verification. The UI does not offer safe key
deletion or master-key rotation in this release. Do not replace `master.key` as a
troubleshooting step: existing encrypted secrets need that original key.

### Why a save can stop working after a while

Admin writes require authentication within the past 10 minutes even when the
session remains valid for reading. Use **Sign in again**, then reopen the form.
If the page reports a stale record/conflict, reload it and reconcile the other
edit rather than repeatedly submitting an old form.

## 7. Sessions, consent, and access duration

An authd session is the browser's sign-in at the provider. An application can
create its **own** session after OIDC. A five-minute access token does not limit a
separate 12-hour application cookie. This release does not implement back-channel
logout that would remotely remove all application sessions.

Refresh tokens let an application request new short-lived tokens without another
interactive login. They are optional for manually created clients; dynamically
registered clients do not currently receive them. Issuing them requires the client to allow
refresh, allow/request `openid offline_access`, and complete `prompt=consent`.
Applications must serialize refreshes because tokens rotate once per use; reuse
revokes the family. Do not turn them on just because the checkbox exists.

On the consent page, check the application name and requested access. **Allow and
continue** releases the sign-in result, not your password. **Cancel** refuses that
request. A basic application sign-in does not need offline access.

Explicit authd sign-out/session revocation also revokes the linked offline grants.
Natural session expiry and routine reauthentication are different from explicit
revocation. Apps must still handle their own session lifecycle.

## 8. Troubleshooting by where it stops

| What you see | Check next |
|---|---|
| nginx 502 / socket connection failure | [Unix-socket guide](docs/UNIX_SOCKET.md): daemon running, actual host/chroot path, traversal permissions and separate proxy-group membership. This is before OIDC. |
| Form rejected before save/sign-in | Reload the form from the public issuer. Inspect Origin/cookies and response `Referrer-Policy`. This release needs `origin`, not `no-referrer`, on form pages. Do not allow `Origin: null` or disable CSRF. |
| Admin reads work but saves are denied | Reauthenticate within 10 minutes; verify `system.admin`; reopen the form. |
| `invalid_client` | Enabled registration, exact client ID, matching current secret and correct client authentication method. |
| Redirect rejected | Exact callback registration, including scheme, host, port, path and trailing slash. |
| `invalid_scope` | Client asked for an unknown or disallowed scope. Enabling a checkbox here is only half the configuration. |
| `access_denied` | User declined consent or, for a manually created client, lacks a requested application permission. Check requested scopes and effective roles. Dynamic clients may instead receive a narrower grant. |
| `unmet_authentication_requirements` | An essential authentication requirement or client MFA floor cannot be met. Enroll the factor; do not treat voluntary `acr_values` alone as a mandatory MFA policy. |
| Missing email or role claim at the app | Check user email, client-allowed scopes, app-requested scopes, and effective roles. The optional `groups` claim contains role names, not group names. |
| Wrong access or disabled user still in an app | Check granted scopes and the application's own cookie and admission logic. Revoke its session too. |
| `invalid_grant` during callback or refresh | Expired/consumed code, binding mismatch, revoked grant, or reused refresh token. Restart authorization; never retry a spent credential indefinitely. |
| Failure with a request reference | Correlate that reference and timestamp in authd/proxy logs; share neither secret values nor token-bearing URLs. |

The daemon intentionally avoids logging raw database/credential errors. Report the
operation, timestamp, status/error reference, release commit, and redacted client
settings. An audit entry proves an authd event, not successful authorization by
another application.

## 9. Where the documentation lives

**In the browser:** Administration → Start here for the generic adding-an-app
workflow; **Documentation** for every shipped Markdown guide, searchable contents,
heading links and original source. Section help and field notes link back to the
same documentation. Client connection details show saved registration values. **In a native installation:**
`/usr/local/share/doc/authd/OPERATOR_GUIDE.md`, `DEPLOYMENT.md`, and `docs/`.
**In the source:** the same files, plus `SPEC.md` for binding behavior,
`DESIGN_LANGUAGE.md` for the interface contract, and `VALIDATION.md` for what has
actually been tested. Release history is in `CHANGELOG.md`; it is not the setup
procedure.
