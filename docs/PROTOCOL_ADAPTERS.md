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

## RADIUS

A useful first RADIUS target is authentication/authorization for network access
that can be expressed without weakening authd's credential store.

Preferred initial shape:

```text
RADIUS Access-Request
        │
        ├── identify user
        ├── verify supported credential method
        ├── evaluate roles/permissions
        └── return explicit RADIUS attributes
```

Important credential boundary:

- RADIUS PAP can be verified against authd's Argon2id password hash because the
  server receives the recovered password and can perform normal verification.
- CHAP/MS-CHAP/MS-CHAPv2 and similar mechanisms may require password-equivalent
  material that cannot be derived from an Argon2id verifier.
- authd MUST NOT store weaker password material by default merely to claim those
  mechanisms are supported.
- If a real deployment later requires such a method, it gets an explicit
  credential type, threat analysis, storage rule, and UI warning.
- Prefer protected transport such as RadSec where the equipment and deployment
  support it.

RADIUS authorization attributes should be explicit mappings from roles or
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

## Process boundary

Start with protocol frontends in the same repository. A protocol may become a
separate executable only when privilege separation, UDP/raw socket ownership,
network placement, or independent failure behavior makes that boundary useful.

The shared identity store remains PostgreSQL either way.
