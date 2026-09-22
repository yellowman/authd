# Source notes for the initial scaffold

These notes record the concrete repositories used to shape the starter rather
than leaving important compatibility choices as oral history.

## yellowman/bdcmaps

Inspected from the private `main` branch on 2026-09-21.

Relevant files included:

```text
internal/oidc/client.go
internal/oidc/client_test.go
internal/oidc/flow.go
internal/appserver/auth.go
internal/config/config.go
db/000_base_schema.sql
deploy/production/bootstrap-oidc.sql
```

The resulting binding compatibility decisions are in
`docs/BDCMAPS_INTEGRATION.md`.

Most notably:

- Authorization Code + PKCE S256 is already implemented by the client.
- It performs discovery and JWKS-based ID-token validation.
- The configurable group claim defaults to `groups`.
- Fresh database OIDC scopes default to `openid profile email`, so `groups`
  must be added when role mapping is desired.
- The token exchange currently sends `client_secret` in the form body, so
  `authd` supports `client_secret_post` for compatibility.
- The callback path is `/auth/callback`.

## yellowman/liminal

The requested top-level `DESIGN_LANGUAGE.md` was not present on the private
`main` branch when inspected on 2026-09-21. The current sources used for the
adaptation were:

```text
docs/LIMINAL_UX_SPEC.md
frontend/src/index.css
```

The initial authd UI does not copy Liminal's application layout literally. It
carries forward the useful family traits—orientation, continuity, thin visual
hierarchy, strong focus treatment, restrained semantic color—and adapts them to
a quieter identity/admin console. `DESIGN_LANGUAGE.md` is the binding authd
version.
