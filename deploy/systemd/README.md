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

`make install-linux` is deliberately a **greenfield-only** installer. It creates
the service account and first active env/master-key files and refuses to replace
an existing active installation. Upgrade/merge semantics will be added when the
project has an installed base that actually requires them.
