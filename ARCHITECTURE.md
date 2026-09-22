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

`internal/identity` owns protocol-neutral identity facts, credential orchestration, bounded hash work, and validation. Its Store interface consists of use-case transactions, not generic CRUD.

`internal/oidc` owns HTTP/OIDC semantics: discovery, authorization requests, authorization codes, token exchange, claims, logout, JWKS.

`internal/protocol` defines the deliberately small adapter boundary for non-OIDC frontends. It is not a generic plugin framework.

`internal/db` owns PostgreSQL SQL/transactions via database/sql and migration sequencing. The executable registers pgx/stdlib; no additional database driver is introduced.

`internal/web` owns provider-operated HTML surfaces. It must not contain authorization decisions that are absent from server-side handlers.

`internal/password` owns the Argon2id implementation and bounded verifier parser. `internal/cryptoutil` owns opaque random secrets, CSRF MACs, and authenticated encryption. Signing-key handling will get its own package when implemented rather than bloating the general utility package.

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


## v0.9.0 transaction and concurrency boundaries

Identity/client/signing-key mutations use an exclusive PostgreSQL transaction
advisory gate. Authorization issuance and token redemption take its shared form,
then lock their own request/code/family rows. Unrelated grants can proceed in
parallel, while privilege changes cannot commit between validation and issuance.

`OIDCStore.RedeemCode` and `RedeemRefresh` own complete grant transactions.
The injected `TokenIssuer` callback receives the current grant and active key;
it only constructs/signs the response. It performs no database I/O, external I/O
or KDF. Signing failure, audit failure and database failure before commit roll
back credential consumption. Only a successful commit releases the response.
Replay outcomes deliberately commit family revocation while returning an error.

Read-only administration uses a repeatable read transaction rather than the
writer gate. Session checks reload authority but throttle last-seen writes.
Bounded parsed-key caches save cryptographic decoding, never stale permissions.
Maintenance is budgeted and releases the writer gate between small batches.

The callback/store interfaces are internal implementation boundaries, not public
SDKs or support for interchangeable production databases. The only backend is
PostgreSQL; existing local identity, domain and adapter ownership stays intact.

## Relying-party boundary

Authd owns organizational human identity, local credentials, MFA, provider sessions and optional application-wide entitlements. Relying applications retain domain authority such as tenants, organizations, customers, PBXs, extensions, projects, rooms, cases and resource ownership. Durable RP identity is `(issuer, subject)` and provider-session correlation is `sid`; see `docs/RP_INTEGRATION.md`. Applications with customer-controlled IdPs may trust those providers directly rather than federating them through authd.

## Native HTTP transport (v0.9.2)

`internal/listener` owns TCP/Unix selection and HTTP shutdown. Unix publication
uses a daemon-owned, non-shared-writable parent, a persistent-inode kernel lock,
and a private staging socket with final permissions before rename. It rejects
live/foreign/non-socket paths and only removes an owned, proven-stale socket.
Closing a listener never removes another inode that replaced its public path.
This is a local service transport, not another identity adapter or an RPC layer.

`internal/web` resolves client IP once from the actual accepted transport plus
explicit proxy trust. Unix peer names are never IPs. `internal/requestid`
preserves the distinction between unknown IP and absent resolution so the OIDC
layer cannot fall back to a socket filename for auditing. The public issuer,
cookies and authorization remain unchanged. Native service setup owns directory
provisioning and supplementary groups, not the Go process.
