# Initial scaffold validation

Validation performed while creating this repository on 2026-09-21:

```text
gofmt                      PASS
shell script syntax         PASS
stdlib-only Go tests        PASS
whole-tree compile check    PASS (local signature stubs for unavailable modules)
whole-tree tests            PASS (same local signature stubs)
go vet                      PASS (same local signature stubs)
template parse/routes       PASS (same local signature stubs)
```

The authoring sandbox contains Go 1.23 and has no outbound network access. The
repository intentionally targets Go 1.25 because the selected current pgx
release requires it. The sandbox therefore could not download the Go 1.25
toolchain, `pgx`, or `x/crypto`, and could not perform a real `make verify`
against those downloaded modules.

The sandbox also has no PostgreSQL server or Docker runtime, so the embedded SQL
migration has not yet been executed against a real PostgreSQL instance.

On the first normal development machine, run:

```sh
go mod tidy
make dev-db
make verify
```

Then run the migration/startup path against the disposable development database
before building further protocol behavior.

## 2026-09-21 credential-model/spec delta

After separating canonical password credentials from `users` and tightening the
future RADIUS/TACACS+ contract:

- `git diff --check`: PASS.
- whole-tree `go test ./...` against local signature-compatible stubs for pgx
  and x/crypto: PASS.
- whole-tree `go vet ./...` against the same stubs: PASS.
- new schema invariant tests cover `password_credentials` separation and forbid
  turning the OIDC client schema into a polymorphic protocol registry.

The sandbox still has Go 1.23.2 and cannot download the repository's Go 1.25
toolchain or real modules, so a real dependency-backed `make verify` remains an
external validation gate.
