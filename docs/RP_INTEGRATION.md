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

Supported ACR values:

```text
urn:authd:acr:pwd
urn:authd:acr:mfa
```

An RP can require fresh MFA for a sensitive operation without requiring MFA for
every ordinary application visit:

```text
/authorize?...&
  acr_values=urn:authd:acr:mfa&
  max_age=300
```

The ID Token reports what authd actually satisfied:

```json
{
  "auth_time": 1780000000,
  "acr": "urn:authd:acr:mfa",
  "amr": ["pwd", "otp"]
}
```

If authd cannot meet the authentication requirement, it returns
`unmet_authentication_requirements`; it does not downgrade the token silently.

## Session correlation

ID Tokens contain `sid`, the UUID of the authd provider session that performed
the authentication. An RP that creates a local application session should keep:

```text
oidc_issuer
oidc_subject
oidc_sid
```

`sid` remains the same for tokens refreshed from that provider session. A new
provider login gets a new `sid`. Back-channel logout is not implemented in v1,
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
