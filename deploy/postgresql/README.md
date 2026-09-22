# PostgreSQL deployment assets

The complete installation procedure is in [`../../DEPLOYMENT.md`](../../DEPLOYMENT.md).

This directory contains two different privilege stages:

- `create-database.sql` runs as a PostgreSQL cluster administrator against the `postgres` maintenance database. It creates the dedicated authd database plus `authd_owner` and `authd_runtime` LOGIN roles, but deliberately sets no passwords. Use psql `\password` interactively afterwards.
- `runtime-grants.sql` runs as `authd_owner` **against the authd database after `authd migrate`**. It grants the pre-existing `authd_runtime` role DML/sequence/schema usage, revokes schema CREATE from PUBLIC/runtime, and establishes matching default privileges for future migration-created objects.

The resulting trust split is:

```text
cluster administrator -> create database/LOGIN roles + set passwords
authd_owner           -> authd migrate + runtime-grants.sql
authd_runtime         -> authd bootstrap + normal daemon
```

The migration-owner password/DSN must not be stored in the daemon environment. The OpenBSD deployment uses `PGPASSFILE=/etc/authd/pgpass` for the runtime credential by default.
