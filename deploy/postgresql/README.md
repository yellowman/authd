# PostgreSQL role split

`authd migrate` is the only normal executable path that performs DDL. Run it
with a migration/owner connection. The daemon and `authd bootstrap` call only
`CheckSchema` and can use a DML-only runtime role.

A simple deployment sequence is:

```sh
# DATABASE_URL here belongs to the migration/owner role.
authd migrate

# Still connected as that migration owner, grant a pre-created runtime role DML.
psql "$DATABASE_URL" \
  -v authd_schema=public \
  -v authd_runtime_role=authd_runtime \
  -f deploy/postgresql/runtime-grants.sql

# Switch DATABASE_URL to the runtime login for all ordinary commands/processes.
authd bootstrap
authd
```

The repository deliberately does not create LOGIN roles or store their
passwords. Prefer a dedicated database/schema for authd. The runtime role needs
`CONNECT` on the database plus the grants in `runtime-grants.sql`; it does not
need table ownership or schema `CREATE` privileges.

When a release adds migrations, run `authd migrate` with the migration role
before restarting the daemon. An older schema or altered migration history makes
normal startup fail closed with an instruction to run the migration command.
