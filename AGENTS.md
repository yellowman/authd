# Repository rules

`authd` is intentionally small. Preserve that property.

## Architecture

- One Go service for OIDC, local identity, and the web UI until a concrete
  deployment boundary proves otherwise.
- PostgreSQL is the only required state service.
- Users, groups, roles, permissions, clients, and protocol mappings are database state,
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

Do not implement cryptographic primitives. Use the standard library or x/crypto.
Small protocol encodings around those primitives may remain local when covered by
test vectors/interoperability tests.

The canonical password credential is Argon2id only. Do not add recoverable primary
passwords, NT hashes, or other password-equivalent material to satisfy a protocol.
A concrete legacy requirement gets a separate explicit credential type.

OIDC clients are OIDC clients. Future RADIUS/TACACS+ peers get separate protocol
registration records rather than a discriminator on the existing client table.

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
- `groups` and `roles` claims expose effective **role names**, including roles
  inherited from actual authd groups. Do not conflate claim values with group
  names or introduce nested groups.

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
considered complete. `docs/APPLICATION_INTEGRATION.md` is the reusable
application contract. The first externally verified real application login is
dated evidence in `VALIDATION.md`; do not extend that evidence to a later
authorization-method migration without a new application-level test.

## Operator interface and native forms

Start here renders docs/ADDING_AN_APP.md. Keep original Markdown and actual
field behavior in agreement; do not add a separate HTML guide. All product
Markdown belongs in the authenticated, directory-derived documentation index.
Built-in UI help is generic for every app; do not branch on a client ID or add a
named-app link. Any integration report is ordinary Markdown, not UI metadata. Explain scope allow-lists versus grants and preserve the distinction
between authd administration and application-local membership. Do not call an
application connected simply because a client row exists. Follow
docs/BROWSER_TESTS.md when changing form/security-header behavior: manually
supplied Origin headers and layout-only screenshots do not prove native browser
submission works. Never relax CSRF/origin validation to make a browser test pass.

Documentation parser source is isolated under internal/thirdparty/markdown with
its upstream license/version. Do not add another parser/framework or hand-roll
Markdown grammar. The allow-list HTML renderer owns link/HTML safety. Update
root manual_test.go coverage when changing documentation roots. Index entries,
grouping and titles come from files, directories and Markdown headings; do not
maintain filename descriptions/categories or per-platform README lists.
