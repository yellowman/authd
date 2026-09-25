# Relying-party integration contract

This document is the integration-side companion to `SPEC.md`. It describes what
authd proves and, just as importantly, what it does **not** prove for an
application.

## Durable identity

Key an authd principal by the immutable pair:

```text
(iss, sub)
```

Do not use email, username, display name, `groups`, or `roles` as the durable
identity key. Those are mutable profile or authorization claims.

A typical application projection is:

```text
local_user
    id
    auth_issuer
    auth_subject
    display_name
    email

UNIQUE(auth_issuer, auth_subject)
```

Do not silently link a pre-existing local account because its email matches an
OIDC email claim. Migration requires either an explicit administrator mapping or
an account-linking ceremony authenticated on both sides.

## Identity is not tenancy

An authd login proves the external human identity and the authentication context
used at authd. It does not prove application-local membership such as:

```text
tenant / organization
customer / PBX / extension
project / room / conversation
case / boundary / workspace
resource ownership / ACL membership
```

Keep those facts in the application that owns them. In particular, never infer
an application tenant from a requested URL parameter or from a generic role name
in an authd token.

## Integration modes

### Identity-only

Request normal identity scopes and keep all authorization in the RP.

```text
openid profile email
```

This is appropriate when the application's local authority model is already
rich and resource-specific.

### Hybrid

Use authd for identity, MFA and a small number of application-wide entitlements,
while the RP owns tenant/resource membership.

Examples include Temary Core/Relay, Liminal, Liminallm and Astmgr. Astmgr keeps
its platform/customer/PBX/extension role bindings, PBX-local identities, SIP
credentials, voicemail PINs, API tokens and support grants locally.

### Authd-authorized

The RP has little separate authorization and can consume authd permissions as
OAuth scopes plus optional role claims. BDC Maps is the first integration and is
closest to this mode.

## Authentication context and step-up

Authd advertises `urn:authd:acr:pwd` and `urn:authd:acr:mfa`. The latter is
password plus TOTP/recovery, not phishing-resistant authentication.

`acr_values` is a voluntary preference. Do not treat a successful response to
`acr_values=urn:authd:acr:mfa` as proof that MFA occurred. This corrects the v0.8
integration guidance. Use a client-wide `require_mfa=true` policy or the standard
essential claim request for a mandatory per-operation requirement:

```json
{"id_token":{"acr":{"essential":true,"value":"urn:authd:acr:mfa"}}}
```

Send this JSON URL-encoded as `claims`, along with `max_age=300` for a five-minute
freshness requirement. Retain the original state, nonce, PKCE verifier, desired
identity and requested operation in the RP's server-side flow. Validate signature,
issuer, audience, nonce, expiry, returned `acr`, and `auth_time` before completing
that operation. Reject an unexpected subject or weaker context. A successful
refresh preserves the original authentication time; it cannot serve as step-up.

Essential context that cannot be achieved returns
`unmet_authentication_requirements`. With `prompt=none`, interaction-required
cases return `login_required`; do not convert an IdP outage into permanent
credential rejection or an automatic loop of login redirects.

## Protocol and claim transport

Use Authorization Code with S256 PKCE for confidential and public clients. The
provider accepts GET or form-encoded POST authorization, and query responses.
Do not send Request Objects, `request_uri`, or unsupported `form_post` response
mode. Configure exact callback/logout URIs; wildcard callbacks are not supported.
Basic or body client authentication is supported, never both in one request.

ID tokens use `typ=JWT` and are for the RP login; access tokens use `typ=at+jwt`
and must not substitute for an ID token. UserInfo requires an access token with
`openid`. `at_hash` is included in ID tokens. An RP accessing its own API must
validate the API token's audience/purpose rather than accept any signed JWT.

The normal `profile`/`email` scopes request their supported bundles. A supported
`claims` selector can request an individual field for ID-token or UserInfo output
without requesting the whole bundle. Missing profile fields, including unavailable
essential profile fields, are omitted; do not assume every account has email.
Neither `groups` nor `roles` is a standardized organizational membership model;
here both are gated views of effective local role **names**, including roles
granted through authd groups; neither claim lists authd group names. Application permissions remain
requested OAuth scopes, never a claim supplied by the browser.

## Offline access and refresh serialization

For a manually configured client, request `openid offline_access` **and
`prompt=consent`**, and configure that client
to permit refresh tokens. The user must approve the browser-bound consent page.
Without explicit consent, authd drops `offline_access` and issues no refresh
credential. Dynamically registered authd clients do not currently receive
refresh tokens. Inspect the actual response scopes and refresh-token presence.

Keep refresh tokens server-side or in an appropriately protected client store.
Serialize refresh per local RP session, including concurrent tabs/requests; adopt
the replacement token atomically. Do not retry a known consumed token. A lost
response or ambiguous COMMIT failure may require reauthorization: the provider
cannot make database commit and HTTP response delivery atomic, and deliberately
has no replay-acceptance grace window. True dependency failures return 503, not
`invalid_grant`; genuine reuse revokes the family.

## Session correlation

ID Tokens contain `sid`, the UUID of the authd provider session that performed
the authentication. An RP that creates a local application session should keep:

```text
oidc_issuer
oidc_subject
oidc_sid
```

`sid` remains the same for tokens refreshed from that provider session. A new
provider login gets a new `sid`. Ordinary reauthentication retires the old browser
session without erasing previously consented offline grants. Natural session
expiry also permits those grants to survive; explicit provider-session logout or
revocation stops their future refresh. Back-channel logout is not implemented,
but retaining `sid` now makes later targeted logout possible without changing
RP session schemas.

## Other identity providers

Authd is an organizational IdP, not a mandatory identity root for every
application or customer. An RP may trust a customer's IdP directly.

Evident is the important example. Its common gateway can serve many product
surfaces and divergent customer populations:

```text
our operators      -> authd -----------\
customer A users   -> customer OIDC ----> Evident gateway -> local authority
customer B users   -> customer SAML ----/
```

Evident should keep tenant, boundary, actor, purpose, case, workspace and
permission authority in its own gateway/session model. Provider routing and
customer federation belong there unless upstream federation later becomes an
explicit authd product requirement.

Authd therefore does not add upstream OIDC federation, SAML brokering,
organizations, tenants, realms or generic scoped grants merely to make every RP
see one issuer.

## RP-local session lifetime is a separate decision

An authd access-token TTL is not a kill switch for an application's longer-lived
cookie. Until an independently qualified logout/revalidation mechanism exists,
choose and document a local maximum lifetime, freshness checks for sensitive
operations, and how disable/revocation takes effect. Store `(issuer, sub, sid)`
for correlation, but never accept `sid` itself as a bearer credential. Preserve
local domain authorization checks on HTTP, WebSocket, background and export paths.

## Standards

See OpenID Connect Core 1.0 errata 2 §§3.1, 5.5, 11 and 12; RFC 7636;
RFC 9700; and RP-Initiated Logout 1.0. The executable audit and residual
qualification list are in `OIDC_AUDIT.md` and `../VALIDATION.md`.
