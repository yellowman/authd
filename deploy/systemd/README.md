# Linux systemd deployment assets

The complete procedure is in [`../../DEPLOYMENT.md`](../../DEPLOYMENT.md).

Files in this directory:

```text
authd.service       native systemd unit
authd.env.example   copy of the canonical runtime environment template
```

Linux uses the same runtime files as OpenBSD:

```text
/etc/authd/authd.env       root:_authd    0640
/etc/authd/master.key      _authd:_authd  0400
/etc/authd/pgpass          _authd:_authd  0400
/usr/local/bin/authd       root:root      0755
/var/authd                 root:_authd    0750
```

The service uses systemd `EnvironmentFile=/etc/authd/authd.env`; no database
password, issuer, or master key is encoded in the unit. `PGPASSFILE` in the env
file points pgx at the daemon-readable PostgreSQL password file.

`make install-linux` is safe to run for both first installation and normal
binary/service upgrades. It creates a missing active env file and master key on
first install, then preserves the existing env, master key, and pgpass contents
on later installs while replacing program/service/documentation assets. Database
migration remains an explicit `authd migrate` step with the migration-owner
credential.
