# Protocol adapters

OIDC is the first protocol, but it must not become the identity model.

The core owns:

```text
users
credentials
roles
permissions
MFA state
account enable/disable state
audit identity
```

A protocol frontend converts a protocol-specific request into operations against
that core and converts the result back into protocol-specific attributes.

```text
                         ┌── OIDC / OAuth
identity + authorization ├── RADIUS (future)
core                     └── TACACS+ (future)
```

Do not build a generic plugin runtime. Add a frontend when there is an actual
protocol to support.

## OIDC

OIDC is implemented in-process and is the authoritative web SSO interface.
Application permissions are OAuth scopes. `groups` and `roles` are views of the
same role assignments.

## Protocol peer registrations

OIDC/OAuth clients, RADIUS peers, and TACACS+ clients are distinct protocol
objects. They share users and authorization facts; they do not share a generic
"client" configuration row.

```text
OIDC client     -> client ID, redirect/logout URIs, scopes, client auth
RADIUS peer     -> source/TLS identity, transport, auth methods, attributes
TACACS+ client  -> source/TLS identity, transport, service/command mappings
```

When those adapters are implemented, add explicit `radius_clients` /
`tacacs_clients`-style records. Do not add a protocol discriminator to the OIDC
client table.

## Credential capability rule

The canonical password credential is an Argon2id verifier. It is deliberately
not recoverable. Authentication methods must declare what credential material
they require.

```text
method                       canonical Argon2id
local web password           yes
RADIUS PAP                   yes
classic CHAP                 no
MS-CHAP / MS-CHAPv2          no
EAP-TTLS + inner PAP         possible future method
EAP-TLS                      separate certificate credential
```

PAP compatibility does **not** mean the NAS supports Argon2id. The RADIUS
frontend recovers the candidate password from the PAP request and calls the
normal Argon2id verifier.

Classic CHAP requires the original password to calculate the expected response.
MS-CHAP-family methods require NT-hash/password-equivalent material. Neither can
be derived from Argon2id.

If a real deployment requires weaker or recoverable credential material, it is
a separate explicitly enrolled credential with its own storage representation,
admin visibility, audit events, revocation, and warning. Prefer a separate
network credential rather than weakening the primary SSO password.

## RADIUS

A useful first RADIUS target is authentication/authorization for network access
that can be expressed without weakening authd's credential store.

Preferred initial shape:

```text
RADIUS Access-Request
        │
        ├── identify configured RADIUS peer
        ├── identify user
        ├── verify explicitly supported credential method
        ├── evaluate roles/permissions
        └── return explicit RADIUS attributes
```

Initial method policy:

- PAP can use the canonical Argon2id verifier.
- classic CHAP is disabled with the canonical credential.
- MS-CHAP/MS-CHAPv2 are disabled unless a deployment deliberately adds the
  required separate credential representation.
- EAP methods are not implied by "RADIUS support"; each EAP method is an
  explicit implementation decision.
- protected transport is preferred. Evaluate RADIUS/TLS and RADIUS/1.1 when
  client support permits it rather than defaulting blindly to classic UDP.

RADIUS authorization attributes are explicit mappings from roles or
permissions, not free-form policy code hidden in the protocol server.

## TACACS+

TACACS+ is a natural fit for administrator login and command authorization on
routers and switches because authd can answer from the same identity and role
model.

A future adapter can map permissions such as:

```text
network.login
network.command.show
network.command.configure
network.command.commit
```

to TACACS+ authentication, service authorization, and command authorization.

Do not add a general policy DSL preemptively. Start with declarative mappings
that are visible in the admin UI. Promote to a richer policy model only if real
network-device authorization rules cannot be represented cleanly.

Where client support permits it, TACACS+ over TLS 1.3 is preferred over the
legacy TACACS+ obfuscation mechanism.

## Process boundary

Start with protocol frontends in the same repository. A protocol may become a
separate executable only when privilege separation, UDP/raw socket ownership,
network placement, or independent failure behavior makes that boundary useful.

The shared identity store remains PostgreSQL either way.
