# Implementation sequence

The repository intentionally stops short of pretending that an OIDC provider is
finished because discovery JSON exists.

## Phase 1 — identity and bootstrap

- repository methods for users, roles, permissions, and effective grants;
- first-run bootstrap token and first `system-admin` creation;
- login sessions and CSRF;
- password change/reset and forced change;
- admin middleware enforcing `system.admin`;
- TOTP enrollment, replay prevention, and recovery codes;
- audit writer.

## Phase 2 — OIDC authorization

- client repository and exact redirect URI validation;
- `/authorize` request parser and validation order;
- login transaction storage;
- `prompt=none`, `prompt=login`, `max_age`, `login_hint`;
- permission-scope evaluation;
- `groups`/`roles` claim projection;
- one-use authorization codes;
- issuer parameter in authorization responses.

## Phase 3 — tokens

- RSA signing-key generation and encrypted persistence;
- JWKS publication and rotation overlap;
- `/token` code exchange;
- `client_secret_basic`, `client_secret_post`, and public-client `none`;
- RS256 ID tokens and access tokens;
- `/userinfo`;
- rotating opaque refresh tokens and family replay detection;
- `/revoke`;
- RP-initiated logout.

## Phase 4 — bdcmaps

Run every item in `docs/BDCMAPS_INTEGRATION.md` against a disposable PostgreSQL
instance and an actual bdcmaps instance/test harness.

## Phase 5 — admin completeness

- user, role, permission, and client CRUD;
- sessions and revocation;
- signing-key rotation UI;
- audit browser;
- one-time client-secret display;
- self-service account UI.

## Later, only from concrete need

- WebAuthn/passkeys;
- RADIUS frontend;
- TACACS+ frontend;
- PostgreSQL HA/multiple active authd instances;
- separate resource-server registration if clients and APIs diverge.
