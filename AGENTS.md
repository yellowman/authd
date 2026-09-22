# Repository rules

`authd` is intentionally small. Preserve that property.

## Architecture

- One Go service for OIDC, local identity, and the web UI until a concrete
  deployment boundary proves otherwise.
- PostgreSQL is the only required state service.
- Users, roles, permissions, clients, and protocol mappings are database state,
  not configuration-file state.
- OIDC is a protocol frontend. It does not own the identity model.
- Future RADIUS/TACACS+ support consumes the same identity core.

## Dependencies

Prefer the Go standard library. Add an external module only when implementing it
locally would be materially less safe or less maintainable.

Current intended direct dependencies:

```text
github.com/jackc/pgx/v5
golang.org/x/crypto
```

Do not add a web framework, ORM, frontend framework, dependency-injection
framework, generic plugin framework, policy engine, Redis client, or message bus
without a demonstrated requirement.

## Security invariants

- Exact redirect URI matching.
- Authorization Code only; PKCE S256 on every flow.
- Opaque one-use authorization codes.
- Opaque rotating refresh tokens with family reuse detection.
- Passwords are Argon2id only.
- High-entropy bearer material is hashed before PostgreSQL storage.
- TOTP seeds and signing private keys are encrypted using the external master key.
- Never log query strings, passwords, authorization codes, bearer tokens,
  refresh tokens, client secrets, TOTP seeds, recovery codes, or bootstrap tokens.
- Admin authorization is checked server-side with `system.admin`.
- `groups` and `roles` are claim aliases over roles; do not introduce a second
  group hierarchy.

## UI

Follow `DESIGN_LANGUAGE.md`:

- thin lines and low-radius surfaces;
- dense rows before card grids;
- restrained semantic color;
- slim left icon rail for administration;
- one authoritative focus-visible treatment;
- server-rendered HTML first;
- JavaScript only where interaction requires it;
- no gradients, glass effects, giant pills, glow, or card soup.

## Tests

Every security invariant gets a failing regression witness before the code is
considered complete. The bdcmaps compatibility profile in
`docs/BDCMAPS_INTEGRATION.md` is the first real end-to-end integration target.
