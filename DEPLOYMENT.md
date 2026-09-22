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

## After installation: operating the application

Installation gets the service running; it does not connect BDC or assign users.
Open **Administration → Start here**, or read [OPERATOR_GUIDE.md](OPERATOR_GUIDE.md)
for roles, client registration, which values belong in BDC, MFA, and daily changes.
You do not need to repeat PostgreSQL bootstrap when adding a person/application.

## 1. Trust boundaries

There are three PostgreSQL identities, plus a separate Unix service account.
Do not collapse them:

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

Use the same explicit database-login workflow on OpenBSD and Linux:

```sh
cd /path/to/authd
psql -Upostgres -dpostgres -X -v ON_ERROR_STOP=1 \
  -v authd_database=authd \
  -v authd_owner_role=authd_owner \
  -v authd_runtime_role=authd_runtime \
  -f deploy/postgresql/create-database.sql
```

`-Upostgres` selects the PostgreSQL role, not the Unix account. These commands
assume the cluster's local authentication policy permits that login from your
administrative account. They do not require running psql as `_postgresql` and do
not bypass `pg_hba.conf`. When the local socket uses peer authentication for a
*different* Unix account, use the site's configured authenticated connection, for
example add `-h127.0.0.1` for an already-configured loopback SCRAM admin connection.
Do not change the cluster to `trust` just to make a command work. psql may still
request the cluster administrator's login password according to that policy; a
protected administrator pgpass file can supply it for batch use. See the
[psql options][1] and [peer-authentication rules][2].

The script:

- creates `authd_owner` as a restricted LOGIN role;
- creates `authd_runtime` as a restricted LOGIN role;
- creates database `authd`, owned by `authd_owner`;
- revokes database `CONNECT` and `TEMPORARY` from PUBLIC;
- grants database `CONNECT` only to the owner and runtime roles.

It does not set or rotate role passwords. Initial credential assignment is the
explicit SQL step below; it is not repeated during ordinary upgrades.

### 3.1 Assign the two PostgreSQL role passwords with SQL

Use distinct random values for the owner and runtime roles. Keep the real values
out of the repository and command arguments. Prepare a private temporary SQL file
outside the checkout:

```sh
password_sql=$(mktemp "$HOME/.authd-db-passwords.XXXXXXXX")
chmod 0600 "$password_sql"
vi "$password_sql"
```

Put the following in that file, replacing **both** placeholder strings before
execution. Use the same role names chosen above. Double any single quote inside
an SQL password literal; for example a literal apostrophe is written as `''`.

```sql
BEGIN;
SET LOCAL standard_conforming_strings = on;
SET LOCAL password_encryption = 'scram-sha-256';
ALTER ROLE authd_owner WITH PASSWORD 'REPLACE_WITH_OWNER_PASSWORD';
ALTER ROLE authd_runtime WITH PASSWORD 'REPLACE_WITH_RUNTIME_PASSWORD';
COMMIT;
```

Load that file through the explicit cluster-administrator connection:

```sh
psql -Upostgres -dpostgres -X -v ON_ERROR_STOP=1 -f "$password_sql"
```

Stop on any error. Store the successful values securely for the owner pgpass in
step 5 and runtime pgpass in step 8, then remove the temporary file and any editor
backup/swap copies:

```sh
rm -f "$password_sql"
unset password_sql
```

Using a file keeps the literal passwords out of shell command history, psql's
interactive history and process arguments. It does **not** prevent PostgreSQL
statement/audit logging, error reports or session capture from recording the SQL.
Treat the file and any such output as secrets; use a local administrative socket
or certificate-verified TLS and review the site's logging policy. SCRAM controls
stored verifiers, not whether submitted SQL contains a password. See
[psql file input][1] and the [ALTER ROLE security notes][3].

The `authd_owner` credential is for migrations/grants only and MUST NOT be copied
into `/etc/authd/authd.env` or `/etc/authd/pgpass`. The daemon gets only
`authd_runtime`. An existing installation does not need new passwords just because
this documentation changed.

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
psql -Uauthd_owner -dauthd -h127.0.0.1 -X -v ON_ERROR_STOP=1 \
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
/usr/local/libexec/authd-run
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

### 8.1 Optional Unix-socket HTTP transport (v0.9.2+)

The earlier `127.0.0.1:8080` configuration remains valid. For a local Linux proxy,
authd now also accepts the socket below; OpenBSD normally uses
`unix:/var/run/authd/authd.sock`. Both native installers preserve your current
transport setting instead of switching a live upstream implicitly.

```sh
AUTHD_LISTEN='unix:/run/authd/authd.sock'
AUTHD_UNIX_MODE='0660'
AUTHD_UNIX_GROUP='authd_proxy'
AUTHD_TRUST_UNIX_PROXY='true'
```

Keep `AUTHD_ISSUER` as the public HTTPS origin. Complete the distinct proxy-group,
runtime-directory, service and nginx namespace steps in
[`docs/UNIX_SOCKET.md`](docs/UNIX_SOCKET.md) **before** using this example. Never
add the proxy worker to the private `_authd` group to make the socket reachable.
Without an explicit mode the socket is daemon-only `0600`; without explicit Unix
proxy trust forwarded IPs are ignored. No TCP fallback occurs after a bind failure.

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
for a one-time bootstrap, invoke a shell as `_authd` that exports the file:

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

The rc.d wrapper retains the WaveControl environment convention but uses
rc.subr's standard `rc_bg=YES` start/background/wait path for this foreground
Go server. `rc_pre` checks configuration and the supported Unix runtime directory.
The installed `/usr/local/libexec/authd-run` launcher sources the environment with
`set -a` after `daemon_user=_authd` is applied, then execs the binary. Variables
survive the privilege transition without secrets in `authd_flags` or
`/etc/rc.conf.local`. The process expression excludes administrative CLI commands.

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

Production authd requires an HTTPS issuer. Use either loopback TCP or a
filesystem-restricted Unix listener behind the same HTTPS reverse proxy. Changing
the internal transport MUST NOT change the issuer, registered callbacks, secure
cookies or public TLS configuration.

For Unix transport use [`docs/UNIX_SOCKET.md`](docs/UNIX_SOCKET.md) and
`deploy/nginx/authd.conf.example` (installed under `/usr/local/share/authd/nginx/`).
That guide distinguishes an OpenBSD chroot path from the host's socket path.
Verify the new listener before changing the live upstream.

For the existing TCP transport, a minimal nginx location is:

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


## 16. v0.9.0 → v0.9.1 documentation-only update

v0.9.1 records the externally reported v0.9.0 OpenBSD/PostgreSQL/live-OIDC pass and
corrects the psql procedure above. Go runtime source, dependency locks, migrations
001–005, SQL privilege statements, Makefile and native service definitions are
unchanged. There is no new migration or credential-rotation step for this update.
An already-running v0.9.0 daemon does not need a restart for these documentation
changes; a fresh install follows the complete procedure above.

The reported test pass covers the v0.9.0 PostgreSQL integration suite, greenfield
role/database setup with owner migration/runtime bootstrap, and a live provider
flow. It does not qualify a restored production database, the actual bdcmaps
callback, HTTPS/proxying, native service installation, live MFA, or Linux race/
systemd execution. Details and the verbatim report are in `VALIDATION.md`.

## 17. v0.9.1 → v0.9.2 Unix-listener update

Install the new binary and service assets to gain Unix support. Migration files
001–005 and dependency locks are unchanged; there is no v0.9.2 database migration,
rebootstrap, session reset or credential/key rotation. A restart is necessary
because this changes runtime code, unlike the v0.9.1 documentation update.

Use the existing build/test/stop/backup/install/start discipline. If switching
transport, follow the socket guide's cutover: configure the dedicated group and
runtime directory, start authd, test direct socket health as the proxy user, then
validate/reload the proxy and exercise HTTPS discovery/login and the real RP
callback. Keep the old TCP upstream available as configuration for rollback; do
not select it silently when Unix startup fails. Custom service-file copies must
also include the new OpenBSD launcher or Linux runtime-directory settings.

## PostgreSQL command references

[1]: https://www.postgresql.org/docs/current/app-psql.html
[2]: https://www.postgresql.org/docs/current/auth-peer.html
[3]: https://www.postgresql.org/docs/current/sql-alterrole.html


## v0.9.2 → v0.9.3 browser-form and operator-help update

No schema migration, new key, client-secret rotation, dependency change, or socket
reconfiguration is required. Build and validate the new binary, install with the
normal native target, and restart the daemon. Active env/key/pgpass files remain
unchanged. Reload open browser pages so their document policy comes from the new
response; old pages may retain the old `no-referrer` policy until navigation.

Authd's HTML form responses now use `Referrer-Policy: origin`. The former
`no-referrer` policy can produce `Origin: null` on native browser form posts and
conflicts with the provider UI's origin validation. Do not override the new header
with `no-referrer` at nginx/relayd. Do not fix rejection by allowing null origins or
removing CSRF. A missing/invalid CSRF token or foreign/opaque Origin remains an
error. The actual policy, not just the input cookies, must be tested through the
public HTTPS reverse proxy. See [browser tests](docs/BROWSER_TESTS.md).

`make install-*` now installs `OPERATOR_GUIDE.md` alongside this guide. The default
admin view is **Start here**; all prior `?view=users`/roles/clients links and form
endpoints remain valid.
