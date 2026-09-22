# authd deployment

This is the complete native deployment sequence for a new authd installation.
It covers PostgreSQL cluster initialization, database and LOGIN-role creation,
schema migration, runtime grants, the authd service account, persistent secret
material, bootstrap, OpenBSD `rc.d`, and the reverse-proxy boundary.

The examples use the default names:

```text
database:       authd
migration role: authd_owner
runtime role:   authd_runtime
OS daemon user: _authd
```

Change the names consistently if a site requires different ones.

## 1. Trust boundaries

There are three distinct administrative identities. Do not collapse them:

```text
PostgreSQL cluster administrator
    creates database + LOGIN roles and sets their passwords

PostgreSQL authd_owner
    owns authd database objects
    runs `authd migrate`
    runs runtime-grants.sql
    is NOT stored in the daemon environment

PostgreSQL authd_runtime
    CONNECT + DML only
    stored in /etc/authd/authd.env
    used by `authd bootstrap` and the daemon
```

The Unix `_authd` account is unrelated to authd application users and roles.
Likewise, PostgreSQL roles are unrelated to authd's `roles` table.

## 2. OpenBSD packages and PostgreSQL cluster

On OpenBSD, install PostgreSQL and Go using packages appropriate to the running
release. authd requires Go 1.26 or newer.

```sh
doas pkg_add postgresql-server postgresql-client go
```

For a brand-new PostgreSQL cluster, follow the package README installed at
`/usr/local/share/doc/pkg-readmes/postgresql-server`. A normal OpenBSD setup is:

```sh
doas su - _postgresql
mkdir -p /var/postgresql/data
initdb -D /var/postgresql/data -U postgres -A scram-sha-256 -E UTF8 -W
exit

doas rcctl enable postgresql
doas rcctl start postgresql
```

`initdb -W` prompts for the PostgreSQL cluster-administrator password. The authd
repository never stores that password.

For a same-host deployment, configure PostgreSQL to accept only the required
loopback/SCRAM connections (plus whatever local administrative access the site
requires). Example `pg_hba.conf` entries after the authd roles exist:

```text
host    authd    authd_owner      127.0.0.1/32    scram-sha-256
host    authd    authd_runtime    127.0.0.1/32    scram-sha-256
host    authd    authd_owner      ::1/128         scram-sha-256
host    authd    authd_runtime    ::1/128         scram-sha-256
```

Keep PostgreSQL bound to loopback when authd and PostgreSQL share a host. A
remote PostgreSQL deployment should use TLS with certificate verification rather
than copying the loopback example.

## 3. Create the PostgreSQL roles and authd database

Run the checked-in cluster bootstrap while connected to the `postgres`
maintenance database as the PostgreSQL cluster administrator:

```sh
cd /path/to/authd
doas -u _postgresql psql -W -U postgres -d postgres \
  -v authd_database=authd \
  -v authd_owner_role=authd_owner \
  -v authd_runtime_role=authd_runtime \
  -f deploy/postgresql/create-database.sql
```

The script:

- creates `authd_owner` as a LOGIN role without superuser/createdb/createrole;
- creates `authd_runtime` with the same cluster-level restrictions;
- creates database `authd`, owned by `authd_owner`;
- revokes database CONNECT and TEMPORARY from PUBLIC;
- grants CONNECT only to the owner and runtime roles.

It deliberately does **not** put passwords in SQL. Set both passwords using
`psql`'s hidden interactive password prompt:

```sh
doas -u _postgresql psql -W -U postgres -d postgres
```

Then, at the `psql` prompt:

```text
\password authd_owner
\password authd_runtime
\q
```

Use different random passwords. The owner credential is an administrative
migration credential; do not copy it into `/etc/authd/authd.env`.

## 4. Build authd

```sh
make deps
make verify-openbsd
make build
```

`make verify-openbsd` intentionally omits the Go race detector because Go does
not support `-race` on OpenBSD/amd64. Run `make race` separately on a supported
release platform before a production release.

## 5. Apply the authd schema as authd_owner

`authd migrate` requires only `DATABASE_URL`. It does not need the authd issuer
or master key and should be run with the migration-owner credential.

For pgx to obtain the owner password without putting it in the command line,
create a temporary owner pgpass file with an editor:

```sh
install -m 0600 /dev/null "$HOME/.pgpass-authd-owner"
vi "$HOME/.pgpass-authd-owner"
```

For the same-host example its one data line is:

```text
127.0.0.1:5432:authd:authd_owner:OWNER_PASSWORD
```

Then migrate without embedding the password in the DSN:

```sh
PGPASSFILE="$HOME/.pgpass-authd-owner" \
DATABASE_URL='postgres://authd_owner@127.0.0.1:5432/authd?sslmode=disable' \
  ./bin/authd migrate
```

For a remote PostgreSQL server, use an appropriate `sslmode=verify-full` DSN and
CA configuration.

Migrations are embedded in the binary. Do not manually concatenate or apply the
files under `internal/db/migrations/`; `authd migrate` owns migration ordering and
records the exact manifest in `schema_migrations`.

## 6. Grant the runtime role DML only

Still using the owner credential, load the runtime grant script **against the
specific `authd` database**, not the `postgres` maintenance database:

```sh
PGPASSFILE="$HOME/.pgpass-authd-owner" \
psql -h 127.0.0.1 -U authd_owner -d authd \
  -v authd_schema=public \
  -v authd_runtime_role=authd_runtime \
  -f deploy/postgresql/runtime-grants.sql
```

After migrations and grants succeed, remove the temporary owner pgpass file or
move that credential into the site's normal privileged database-administration
secret store. The owner credential is not needed by the running daemon.

The runtime grant script gives `authd_runtime`:

```text
USAGE on schema
SELECT / INSERT / UPDATE / DELETE on tables
USAGE / SELECT / UPDATE on sequences
matching ALTER DEFAULT PRIVILEGES for future migrations
```

It does not grant table ownership or schema CREATE.

After this point ordinary authd commands use `authd_runtime`. The daemon must
never receive the owner DSN.

## 7. Install the OpenBSD service

The Makefile includes a native OpenBSD install that follows the same env-file
pattern used by WaveControl:

```sh
doas make install-openbsd
```

It installs:

```text
/usr/local/bin/authd
/etc/rc.d/authd
/etc/authd/authd.env.example
/etc/authd/authd.env        created once, then preserved
/etc/authd/master.key       generated once, then preserved
/usr/local/share/doc/authd/...
/usr/local/share/authd/postgresql/...
```

It also creates the `_authd` user/group when absent. The daemon runs as `_authd`,
not root.

The installed/prescribed secret permissions are:

```text
/etc/authd/authd.env    root:_authd 0640
/etc/authd/master.key   _authd:_authd 0400
/etc/authd/pgpass       _authd:_authd 0400   (created by the operator)
```

The env file must be readable by `_authd` because the `rc.d` execution shell
sources it **after** `rc.subr` drops privileges. The master key is readable only
by the daemon account. Reinstall/upgrade preserves both files.

## 8. Configure `/etc/authd/authd.env`

Edit the active environment file:

```sh
doas vi /etc/authd/authd.env
```

Create the runtime password file first:

```sh
doas install -m 0400 -o _authd -g _authd /dev/null /etc/authd/pgpass
doas vi /etc/authd/pgpass
```

Its same-host data line is:

```text
127.0.0.1:5432:authd:authd_runtime:RUNTIME_PASSWORD
```

Minimum production settings for a same-host PostgreSQL deployment are then:

```sh
AUTHD_ISSUER='https://auth.example.com'
AUTHD_LISTEN='127.0.0.1:8080'
DATABASE_URL='postgres://authd_runtime@127.0.0.1:5432/authd?sslmode=disable'
PGPASSFILE='/etc/authd/pgpass'
AUTHD_MASTER_KEY_FILE='/etc/authd/master.key'
AUTHD_TRUSTED_PROXIES='127.0.0.1/32,::1/128'
```

Do not set `AUTHD_DEVELOPMENT=true` in production. Embedding the runtime password
in `DATABASE_URL` also works, but the separate `PGPASSFILE` keeps the credential
out of the service configuration and is the recommended OpenBSD layout.

The master key is persistent encryption key material for TOTP seeds and OIDC
signing private keys. Back it up separately and securely. Replacing it with a
new random value without a supported key-rotation procedure makes existing
ciphertext unreadable.

## 9. Bootstrap the first authd administrator

Load the same environment used by the daemon and issue the one-time setup token:

```sh
doas -u _authd /bin/ksh -c '
  set -a
  . /etc/authd/authd.env
  set +a
  exec /usr/local/bin/authd bootstrap
' 
```

The command prints a single-use token valid for 30 minutes. It does not start an
HTTP listener.

Then start authd and visit the setup URL through the HTTPS origin:

```sh
doas rcctl enable authd
doas rcctl start authd
```

If PostgreSQL is on the same host, keep service ordering explicit:

```sh
doas rcctl order postgresql authd
```

Open `https://auth.example.com/setup`, supply the bootstrap token, and create the
first `system-admin` user.

After bootstrap, normal account and OIDC-client administration happens through
the web UI. Re-running `authd bootstrap` does not bypass the first-admin safety
rules.

## 10. OpenBSD rc.d behavior and environment propagation

`deploy/openbsd/rc.d/authd` deliberately follows the WaveControl convention:

1. `/etc/rc.d/rc.subr` owns start/stop/check behavior.
2. `daemon_user=_authd` performs the privilege drop.
3. `/etc/authd/authd.env` is sourced with `set -a` so every assignment becomes an
   exported process environment variable.
4. `rc_exec` sources the file again in the daemon execution shell after the
   privilege transition.
5. secrets are therefore not encoded into `authd_flags` or `rc.conf.local`.

Normal service control is consequently just:

```sh
doas rcctl check authd
doas rcctl start authd
doas rcctl restart authd
doas rcctl stop authd
```

`rcctl set authd flags ...` remains available for ordinary command-line flags,
but authd currently has no daemon flags; configuration belongs in the env file.

## 11. HTTPS reverse proxy

Production authd requires an HTTPS issuer. The authd listener should remain on a
loopback address and sit behind nginx, relayd, or another HTTPS reverse proxy.

A minimal nginx location looks like:

```nginx
location / {
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto https;
    proxy_pass http://127.0.0.1:8080;
}
```

When the proxy connects from loopback, configure:

```sh
AUTHD_TRUSTED_PROXIES='127.0.0.1/32,::1/128'
```

Do not trust arbitrary forwarded headers. authd ignores them unless the direct
peer is within an explicitly configured trusted-proxy CIDR.

The issuer must be the exact externally visible origin, for example
`https://auth.example.com`; it must not contain a path, query, or fragment.

## 12. Register relying parties

Use the authd admin UI to create OIDC clients. Each client gets exact redirect
and post-logout URIs plus an explicit identity/application-scope allow-list.

For `bdcmaps`, see `docs/BDCMAPS_INTEGRATION.md`. For the general `(iss, sub)`,
local-authority, ACR, and `sid` integration contract, see
`docs/RP_INTEGRATION.md`.

## 13. Upgrades

For every authd upgrade:

```text
1. stop or drain authd;
2. back up PostgreSQL and /etc/authd/master.key;
3. install the new binary;
4. run the new binary's `authd migrate` with authd_owner;
5. re-run runtime-grants.sql with authd_owner (safe and recommended);
6. switch back to authd_runtime credentials;
7. start authd;
8. run health/OIDC smoke tests.
```

Normal daemon startup performs **no DDL**. It verifies that the database migration
history exactly matches the embedded binary and fails closed if migrations were
not applied first.

## 14. Backups

At minimum, back up:

```text
PostgreSQL authd database
/etc/authd/master.key
/etc/authd/authd.env or an equivalent secure record of the runtime DSN/config
```

The database without the master key is not sufficient to recover encrypted TOTP
seeds and OIDC signing private keys. The master key without the database is not
useful by itself, but it is still highly sensitive and must be protected.

A complete automated backup/restore workflow remains release work; until that is
implemented, deployment is not fully disaster-recovery qualified.
