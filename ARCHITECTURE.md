# authd architecture

## Goal

Own identity once and expose it through a small number of protocol frontends.

```text
                         PostgreSQL
                            │
                 ┌──────────┴──────────┐
                 │ identity + access  │
                 │ users / roles /    │
                 │ permissions / MFA  │
                 └──────────┬──────────┘
                            │
              ┌─────────────┼─────────────┐
              │             │             │
           OIDC/OAuth    RADIUS*       TACACS+*
              │             │             │
          web apps       network       network
                        access/devices  administration

* future adapters, not v1 deliverables
```

The identity core owns users, credential verification, MFA state, role membership, and permission resolution. Protocol packages may ask the core to authenticate a subject and resolve authorization facts. They may not duplicate identity records.

## Process shape

One `authd` process contains:

- HTTP server;
- OIDC/OAuth endpoints;
- login/account/admin web UI;
- PostgreSQL repository;
- audit writer;
- signing and secret-encryption services.

There is no internal RPC, message bus, Redis requirement, service mesh, or plugin runtime.

A later RADIUS or TACACS+ listener may live in the same binary if the implementation remains clean. If protocol privilege separation or UDP/listener deployment eventually justifies a second process, both processes still share the same PostgreSQL identity model and internal packages. That split is a deployment/security decision, not a reason to build microservices now.

## Package ownership

`internal/identity` owns protocol-neutral identity facts.

`internal/oidc` owns HTTP/OIDC semantics: discovery, authorization requests, authorization codes, token exchange, claims, logout, JWKS.

`internal/protocol` defines the deliberately small adapter boundary for non-OIDC frontends. It is not a generic plugin framework.

`internal/db` owns PostgreSQL connectivity and migration sequencing.

`internal/web` owns provider-operated HTML surfaces. It must not contain authorization decisions that are absent from server-side handlers.

`internal/cryptoutil` owns password hashing and opaque random secrets. Signing-key handling will get its own package when implemented rather than bloating the general utility package.

## Identity model

```text
users
  ├── password_credentials (canonical Argon2id verifier)
  └── user_roles
        └── roles
              └── role_permissions
                    └── permissions
```

Authorization is additive only:

```text
effective permissions = union(all permissions in all assigned roles)
```

No nested roles, user-direct permissions, deny rules, precedence, policy language, or expression engine.

Roles are human administration bundles. Permissions are the stable application authorization API.

## OIDC mapping

Standard identity scopes remain OIDC concepts:

```text
openid profile email offline_access groups roles
```

Application permissions are also OAuth scopes:

```text
bdcmaps.review.read
bdcmaps.plan.write
bdcmaps.admin
```

`groups` and `roles` are aliases over the same role names. `groups` exists because many clients—including the existing `bdcmaps` client—already expect it.

A client has its own allow-list of application permissions. A permission can appear in a token only when all three are true:

```text
requested by the client
AND allowed for that client
AND possessed by the user
```

## Future network protocols

RADIUS and TACACS+ should be adapters, not new identity systems.

A protocol adapter receives credentials/context, authenticates against the same local user, resolves the same role/permission set, and maps that result to protocol-native output.

Examples of future mappings:

```text
role=network-admin
  -> TACACS+ authorization permits configured command class

permission=network.vpn.connect
  -> RADIUS Access-Accept + configured VLAN/filter attributes
```

Protocol-specific attributes belong in adapter configuration records keyed by role/permission/protocol peer/service. They do not belong as columns on the user table. OIDC clients, RADIUS peers, and TACACS+ clients remain separate registration types rather than sharing a polymorphic client table.

The canonical password credential is a one-way Argon2id verifier stored separately from the user row. RADIUS PAP can use it because the RADIUS frontend obtains the submitted password and performs normal verification. Classic CHAP cannot: it requires the original password to calculate the expected challenge response. MS-CHAP-family methods require NT-hash/password-equivalent material. `authd` must not weaken the primary password store or silently retain those representations just to support legacy methods. A real requirement gets a separately enrolled protocol credential with explicit storage and threat-model rules.

Protected network-AAA transports should be preferred when client support permits them, including current RADIUS/TLS/RADIUS/1.1 profiles and TACACS+ over TLS 1.3.

## Dependency rule

A new dependency needs a specific reason. Preference order:

1. Go standard library.
2. Small, mature, actively maintained package with narrow scope.
3. Larger framework only when implementing the feature correctly would otherwise create more custom security-critical code than the framework removes.

The starter uses only pgx and x/crypto.
