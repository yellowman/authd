# authd deployment

This is the native deployment and upgrade procedure for authd. It covers the
initial PostgreSQL cluster/database/LOGIN-role bootstrap, schema migration,
DML-only runtime grants, the `_authd` service account, runtime secrets,
first-admin bootstrap, repeatable OpenBSD `rc.d` / Linux `systemd` installation,
and the HTTPS reverse-proxy boundary.

The examples use these names:

```text
database:       authd
migration role: authd_owner
runtime role:   authd_runtime
OS daemon user: _authd
```

Change them consistently if a site requires different names.

`make install-openbsd` and `make install-linux` are repeatable. On first install
they create missing runtime env/master-key state. On later installs they replace
the binary, examples, documentation, and service definition while preserving the
active env, pgpass, master key, and PostgreSQL data. Schema migration remains an
explicit owner-credential step rather than an install-time side effect.

## 1. Trust boundaries

There are three distinct PostgreSQL/OS identities. Do not collapse them:

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
    used by `authd bootstrap` and the daemon
```

The Unix `_authd` account is unrelated to authd application users and roles.
Likewise, PostgreSQL roles are unrelated to authd's `roles` table.

## 2. Install PostgreSQL and Go

authd requires Go 1.26 or newer and PostgreSQL.

### 2.1 OpenBSD

Install packages appropriate to the running release:

```sh
doas pkg_add postgresql-server postgresql-client go
```

For a new PostgreSQL cluster, follow the package README at
`/usr/local/share/doc/pkg-readmes/postgresql-server`. A normal initial setup is:

```sh
doas su - _postgresql
mkdir -p /var/postgresql/data
initdb -D /var/postgresql/data -U postgres -A scram-sha-256 -E UTF8 -W
exit

doas rcctl enable postgresql
doas rcctl start postgresql
```

`initdb -W` prompts for the PostgreSQL cluster-administrator password. authd
never stores it.

### 2.2 Linux/systemd

Install Go 1.26+ and PostgreSQL from the distribution/vendor packages you use.
For example, on a Debian-derived host:

```sh
sudo apt install postgresql postgresql-client
sudo systemctl enable --now postgresql
```

PostgreSQL cluster initialization is distribution-specific. Complete the normal
vendor initialization first, then continue with the common authd database steps
below. The checked-in authd systemd unit does not initialize or own PostgreSQL.

### 2.3 PostgreSQL network policy

For a same-host deployment, bind PostgreSQL to loopback and permit only the
required loopback/SCRAM connections plus local administration. Example
`pg_hba.conf` entries after the authd roles exist:

```text
host    authd    authd_owner      127.0.0.1/32    scram-sha-256
host    authd    authd_runtime    127.0.0.1/32    scram-sha-256
host    authd    authd_owner      ::1/128         scram-sha-256
host    authd    authd_runtime    ::1/128         scram-sha-256
```

A remote PostgreSQL deployment should use TLS with certificate verification
rather than copying the loopback example.

## 3. Create the PostgreSQL roles and authd database

Run the checked-in cluster bootstrap while connected to the `postgres`
maintenance database as the PostgreSQL cluster administrator.

OpenBSD example:

```sh
cd /path/to/authd
doas -u _postgresql psql -W -U postgres -d postgres \
  -v authd_database=authd \
  -v authd_owner_role=authd_owner \
  -v authd_runtime_role=authd_runtime \
  -f deploy/postgresql/create-database.sql
```

Typical Linux peer-auth example:

```sh
cd /path/to/authd
sudo -u postgres psql -d postgres \
  -v authd_database=authd \
  -v authd_owner_role=authd_owner \
  -v authd_runtime_role=authd_runtime \
  -f deploy/postgresql/create-database.sql
```

The script:

- creates `authd_owner` as a restricted LOGIN role;
- creates `authd_runtime` as a restricted LOGIN role;
- creates database `authd`, owned by `authd_owner`;
- revokes database `CONNECT` and `TEMPORARY` from PUBLIC;
- grants database `CONNECT` only to the owner and runtime roles.

It deliberately does **not** put passwords in SQL. Set both passwords using
`psql`'s hidden interactive prompt. For example, enter psql as the cluster
administrator and run:

```text
\password authd_owner
\password authd_runtime
\q
```

Use different random passwords. `authd_owner` is an administrative migration
credential and MUST NOT be copied into `/etc/authd/authd.env`.

## 4. Build and verify authd

```sh
make deps
make build
```

Release qualification uses a disposable real PostgreSQL database:

```sh
# OpenBSD/amd64: race detector is unavailable
make verify-openbsd

# Linux: includes the race detector and systemd unit validation
make verify-linux
```

Both verify targets require the integration-test environment documented by the
Makefile (`AUTHD_TEST_DISPOSABLE=1` and `AUTHD_TEST_DATABASE_URL`). A deployment
host does not need to be the release-builder host; a previously qualified
binary may simply be installed.

## 5. Apply the authd schema as authd_owner

`authd migrate` requires only `DATABASE_URL`. It does not require the issuer or
master key and should be run with the migration-owner credential.

Create a temporary owner pgpass file with an editor:

```sh
install -m 0600 /dev/null "$HOME/.pgpass-authd-owner"
vi "$HOME/.pgpass-authd-owner"
```

Same-host content:

```text
127.0.0.1:5432:authd:authd_owner:OWNER_PASSWORD
```

Then migrate without putting the password in the command line:

```sh
PGPASSFILE="$HOME/.pgpass-authd-owner" \
DATABASE_URL='postgres://authd_owner@127.0.0.1:5432/authd?sslmode=disable' \
  ./bin/authd migrate
```

Migrations are embedded in the binary. Do not manually concatenate or apply
`internal/db/migrations/*`; `authd migrate` owns ordering and the exact
`schema_migrations` manifest.

## 6. Grant the runtime role DML only

Still using the owner credential, load the grant script against the **authd
database**, not the `postgres` maintenance database:

```sh
PGPASSFILE="$HOME/.pgpass-authd-owner" \
psql -h 127.0.0.1 -U authd_owner -d authd \
  -v authd_schema=public \
  -v authd_runtime_role=authd_runtime \
  -f deploy/postgresql/runtime-grants.sql
```

The runtime role receives:

```text
database CONNECT
schema USAGE
table SELECT/INSERT/UPDATE/DELETE
sequence USAGE/SELECT/UPDATE
```

It does **not** receive table ownership or schema `CREATE`.

After this point ordinary authd commands use `authd_runtime`. The daemon must
never receive the owner DSN.

## 7. Install the native service

Both native paths install the same runtime layout:

```text
/usr/local/bin/authd
/etc/authd/authd.env.example
/etc/authd/authd.env
/etc/authd/master.key
/etc/authd/pgpass.example
/var/authd
/usr/local/share/authd/postgresql/...
/usr/local/share/doc/authd/...
```

The daemon runs as `_authd`, not root.

### 7.1 OpenBSD rc.d

```sh
doas make install-openbsd
```

This additionally installs:

```text
/etc/rc.d/authd
```

### 7.2 Linux systemd

```sh
sudo make install-linux
```

This additionally installs:

```text
/etc/systemd/system/authd.service
```

The unit follows the WaveControl service pattern: `User=_authd`,
`Group=_authd`, `EnvironmentFile=/etc/authd/authd.env`, foreground `ExecStart`,
restart-on-failure, and systemd sandboxing (`NoNewPrivileges`, private tmp/devices,
read-only system paths, kernel/control-group protection, and restricted address
families).

### 7.3 Repeatable installer behavior

On the first real-host install, the native installer creates a missing
`/etc/authd/authd.env` from the current example and generates a missing
`/etc/authd/master.key`. It never creates the active pgpass file because only the
operator knows the PostgreSQL runtime password.

On subsequent installs, existing `/etc/authd/authd.env`, `/etc/authd/master.key`,
and `/etc/authd/pgpass` contents are preserved. Their expected ownership/mode is
reasserted, while the binary, example files, documentation, PostgreSQL helper SQL,
and service definition are replaced with the new release.

The installer deliberately does **not** run `authd migrate` or use the
migration-owner credential. Keeping migration explicit preserves the
`authd_owner` / `authd_runtime` privilege split and makes schema changes visible
to the operator before restart.

A `DESTDIR` staged/package install creates only distributable assets and examples;
it does not create users, active config, pgpass, or a master key.

## 8. Configure the shared runtime files

The prescribed permissions are the same on OpenBSD and Linux:

```text
/etc/authd                  root:_authd    0750
/etc/authd/authd.env        root:_authd    0640
/etc/authd/master.key       _authd:_authd  0400
/etc/authd/pgpass           _authd:_authd  0400
/var/authd                  root:_authd    0750
```

Edit the active environment file:

```sh
# OpenBSD
doas vi /etc/authd/authd.env

# Linux
sudo vi /etc/authd/authd.env
```

Create the runtime pgpass file and populate it with the real runtime password:

```sh
# OpenBSD
doas install -m 0400 -o _authd -g _authd /dev/null /etc/authd/pgpass
doas vi /etc/authd/pgpass

# Linux
sudo install -m 0400 -o _authd -g _authd /dev/null /etc/authd/pgpass
sudoedit /etc/authd/pgpass
```

Same-host pgpass line:

```text
127.0.0.1:5432:authd:authd_runtime:RUNTIME_PASSWORD
```

Minimum production env:

```sh
AUTHD_ISSUER='https://auth.example.com'
AUTHD_LISTEN='127.0.0.1:8080'
DATABASE_URL='postgres://authd_runtime@127.0.0.1:5432/authd?sslmode=disable'
PGPASSFILE='/etc/authd/pgpass'
AUTHD_MASTER_KEY_FILE='/etc/authd/master.key'
AUTHD_TRUSTED_PROXIES='127.0.0.1/32,::1/128'
```

Do not set `AUTHD_DEVELOPMENT=true` in production. Embedding the runtime password
in `DATABASE_URL` works, but `PGPASSFILE` is preferred.

The master key encrypts TOTP seeds and OIDC signing private keys. Service start
MUST NOT generate or replace it.

## 9. Bootstrap the first authd administrator

Run bootstrap as `_authd` with the same environment the service will use.

OpenBSD:

```sh
doas -u _authd /bin/ksh -c '
  set -a
  . /etc/authd/authd.env
  set +a
  exec /usr/local/bin/authd bootstrap
'
```

Linux/systemd environment file syntax is compatible with the checked-in sample;
for a one-time bootstrap, invoke through a root shell that exports the file:

```sh
sudo -u _authd /bin/sh -c '
  set -a
  . /etc/authd/authd.env
  set +a
  exec /usr/local/bin/authd bootstrap
'
```

The command prints a single-use token valid for 30 minutes and does not start an
HTTP listener.

## 10. Enable and start the service

### 10.1 OpenBSD

```sh
doas rcctl enable authd
doas rcctl order postgresql authd
doas rcctl start authd

doas rcctl check authd
doas rcctl restart authd
doas rcctl stop authd
```

The rc.d wrapper follows the WaveControl convention: it sources
`/etc/authd/authd.env` with `set -a` while validating configuration and again
inside `rc_exec` after `daemon_user=_authd` is applied. Runtime environment
variables therefore survive the privilege transition without being placed in
`authd_flags` or `/etc/rc.conf.local`.

### 10.2 Linux systemd

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now authd

sudo systemctl status authd
sudo systemctl restart authd
sudo systemctl stop authd
sudo journalctl -u authd
```

The unit uses:

```text
EnvironmentFile=/etc/authd/authd.env
User=_authd
Group=_authd
WorkingDirectory=/var/authd
ExecStart=/usr/local/bin/authd
```

It is ordered after `network-online.target` and `postgresql.service` but does not
`Require=` PostgreSQL, so remote-database deployments are not coupled to a local
PostgreSQL unit. If the distribution uses a different PostgreSQL unit name and
local boot ordering matters, add a normal systemd drop-in for that host.

After the service is running, visit `https://auth.example.com/setup`, submit the
bootstrap token, and create the first `system-admin` user.

## 11. HTTPS reverse proxy

Production authd requires an HTTPS issuer. Keep the authd listener on loopback
and place nginx, relayd, or another HTTPS reverse proxy in front.

Minimal nginx location:

```nginx
location / {
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto https;
    proxy_pass http://127.0.0.1:8080;
}
```

When the proxy connects from loopback:

```sh
AUTHD_TRUSTED_PROXIES='127.0.0.1/32,::1/128'
```

Do not trust arbitrary forwarded headers. The issuer must be the exact externally
visible origin, for example `https://auth.example.com`; it must not contain a
path, query, or fragment.

## 12. Register relying parties

Use the authd admin UI to create OIDC clients. Each client gets exact redirect
and post-logout URIs plus explicit identity/application-scope allow-lists.

For `bdcmaps`, see `docs/BDCMAPS_INTEGRATION.md`. For the general `(iss, sub)`,
local-authority, ACR, and `sid` integration contract, see
`docs/RP_INTEGRATION.md`.

## 13. Updating an existing installation

Normal upgrades reuse the same install targets as the first installation. The
active database, env, pgpass, and master key are deployment state and are not
replaced by `make install-openbsd` or `make install-linux`.

Recommended upgrade sequence:

```text
1. build and validate the new release;
2. stop or drain authd;
3. back up PostgreSQL plus /etc/authd/master.key and runtime configuration;
4. run the NEW release binary's `authd migrate` using authd_owner;
5. re-run runtime-grants.sql using authd_owner (safe/idempotent grant repair);
6. run make install-openbsd or make install-linux;
7. restart authd with the unchanged runtime env/key/pgpass;
8. run health, discovery, JWKS, login, and relying-party smoke tests.
```

Running the new release binary from the build tree for step 4 means a failed
migration does not first overwrite the currently installed executable. Each
migration is transactional, but a release that has successfully advanced the
schema may not be compatible with an older binary; rollback therefore means a
reviewed database restore or a release-specific backward-compatible plan, not
blindly reinstalling an old executable.

An ordinary installer rerun may update service-manager definitions. On Linux,
run `systemctl daemon-reload` before restart (the Makefile `restart` target does
this). On OpenBSD, the newly installed rc.d script is used on the next service
operation.

## 14. Backups

At minimum, back up:

```text
PostgreSQL authd database
/etc/authd/master.key
/etc/authd/authd.env or an equivalent secure record of the runtime configuration
```

The database without the master key is not sufficient to recover encrypted TOTP
seeds and OIDC signing private keys. The master key without the database is not
useful by itself, but remains highly sensitive.

A complete automated backup/restore workflow remains release work; until that is
implemented, deployment is not fully disaster-recovery qualified.

## 15. v0.8.4 → v0.9.0 audit-release upgrade

This is a real code/transaction change, not just a documentation release. Do not
use the earlier external PostgreSQL pass as approval of migration 005. Run the
new integration suite against a disposable database first, then test a restored
copy of the installed database. Keep the database and its matching master key
backups together. Stop/drain all authd instances before applying this migration;
do not mix v0.8.4 and v0.9.0 processes on one schema.

Before migration, connect to the **authd** database with the owner profile and
check the existing permission catalog (substitute a configured schema if needed):

```sql
SELECT id, name FROM permissions
WHERE name IN ('openid','profile','email','groups','roles','offline_access');
```

Any matches must be deliberately renamed or removed with their role/client/RP
references reviewed. Migration 005 fails transactionally rather than silently
changing what those grants mean. It does not rewrite applied migrations 001–004.

Use the established stop/backup/new-binary `authd migrate`/runtime-grants/install/
restart sequence. Only the owner migrates; the daemon keeps DML-only credentials.
The migrated schema preserves users, primary credentials, MFA, signing keys,
existing sessions and established offline families. The migration invalidates
pending browser flows and unused codes lacking browser bindings; those callers
restart login. Older consumed codes cannot retroactively acquire a descendant
family link that was not recorded when they were issued.

RPs should expect these protocol corrections:

- `acr_values` is voluntary. Require MFA via client policy or essential `claims`.
- Offline refresh issuance requires completed `prompt=consent` with `openid` and
  `offline_access`; clients must handle the consent interaction.
- Access JWTs now use `typ=at+jwt`. Older access JWTs with `typ=JWT` are refused by
  UserInfo; refresh/reauthorize rather than allowing token-type confusion. ID
  tokens remain `typ=JWT`. Existing offline families can mint new typed tokens.
- Bare or cross-session logout shows confirmation; it does not automatically
  end the current browser session. Explicit logout revokes associated offline
  grants; ordinary reauthentication/natural session expiry does not.
- Concurrent refresh of one family is an error/replay condition. Serialize it in
  each RP, and restart authorization after an ambiguous lost refresh response.

Rollback after a schema change is a restore of the matched database/key/config
backup, not running an old binary on the newer schema. `CheckSchema` intentionally
refuses that mismatch. It checks migration names/versions, not physical DDL or
migration-file checksums. Installer reruns preserve active deployment files; they
do not provide automatic data rollback.
