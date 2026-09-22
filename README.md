# authd

`authd` is a small Go identity and access service: local users, roles, permissions, OIDC/OAuth, and a local administration UI backed by PostgreSQL.

The reason it exists is simple: new internal web applications should consume one identity system instead of each application growing another user table, password flow, role editor, and permission model.

The first integration target is `yellowman/bdcmaps`, whose existing OIDC client already uses Authorization Code + PKCE, discovery, JWKS validation, `login_hint`, and the `groups` claim. `authd` therefore treats `groups` and `roles` as two claim names over the same local role set and supports both `client_secret_basic` and `client_secret_post` for confidential clients.

This repository is intentionally not an Authelia/Keycloak clone. It starts with the protocol and identity core that are actually needed, and it keeps future network-access protocols (RADIUS/TACACS+) as thin adapters over the same users, credentials, roles, and permissions.

## Status

This is the initial repository scaffold. It contains:

- the binding product/protocol specification in `SPEC.md`;
- the adapted Liminal UI language in `DESIGN_LANGUAGE.md`;
- the architecture and protocol-adapter boundaries in `ARCHITECTURE.md`;
- the first-client contract in `docs/BDCMAPS_INTEGRATION.md`;
- PostgreSQL schema/migration infrastructure;
- minimal identity models and additive role-permission evaluation;
- Argon2id password primitives;
- TOTP primitives;
- OIDC discovery metadata and route skeletons;
- a server-rendered login/admin shell with the adapted Liminal visual language;
- tests for the implemented pure components.

Authorization-code issuance, token exchange, persistent sessions, the bootstrap workflow, and admin CRUD are deliberately marked as the next implementation tranche rather than being represented as complete.

## Dependency policy

Production Go dependencies are intentionally limited to:

```text
github.com/jackc/pgx/v5   PostgreSQL driver/pool
golang.org/x/crypto       Argon2id password hashing
```

Everything else uses the Go standard library unless a future requirement justifies another dependency.

No frontend package manager is required. HTML templates, CSS, and the small JavaScript file are embedded into the Go binary.

## Build

The repository targets Go 1.25 or newer.

```sh
make verify
```

For a local PostgreSQL container:

```sh
make dev-db
export DATABASE_URL='postgres://authd:authd-dev-only@127.0.0.1:55432/authd?sslmode=disable'
export AUTHD_ISSUER='http://127.0.0.1:8080'
export AUTHD_DEVELOPMENT=true
./scripts/generate-master-key.sh > /tmp/authd-master.key
chmod 600 /tmp/authd-master.key
export AUTHD_MASTER_KEY_FILE=/tmp/authd-master.key
make run
```

Then visit:

```text
http://127.0.0.1:8080/login
http://127.0.0.1:8080/admin/
http://127.0.0.1:8080/.well-known/openid-configuration
```

## Repository map

```text
cmd/authd/                  process entry point
internal/config/            deployment configuration
internal/db/                pgx pool + embedded SQL migrations
internal/identity/          users / roles / permissions model
internal/cryptoutil/        password + random-token primitives
internal/totp/              TOTP verification primitives
internal/oidc/              OIDC metadata and protocol surface
internal/protocol/          shared boundary for future protocol adapters
internal/web/               server-rendered UI + static assets
docs/                       integration and implementation notes
SPEC.md                     binding product/protocol contract
DESIGN_LANGUAGE.md          adapted Liminal UI contract
ARCHITECTURE.md             ownership and dependency boundaries
```

## Immediate implementation order

1. Persistent signing-key manager and JWKS.
2. Bootstrap first administrator.
3. Provider sessions + CSRF.
4. `/authorize` transaction validation and login continuation.
5. Single-use authorization codes and `/token` exchange with PKCE.
6. ID/access token issuance and refresh-token rotation.
7. Admin CRUD for users, roles, permissions, and clients.
8. End-to-end compatibility test using the `bdcmaps` OIDC client contract.
9. TOTP enrollment/recovery UI.
10. Only after the OIDC path is solid, add RADIUS/TACACS+ adapters if they are actually needed.

## Design rule

The central identity model is not protocol-specific:

```text
user -> roles -> permissions
```

OIDC emits role names as `groups`/`roles` claims and application permissions as OAuth scopes. Future RADIUS/TACACS+ frontends must translate the same identity result into protocol attributes; they do not get a second user/role database.
