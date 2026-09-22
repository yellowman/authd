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

## Unix listener

v0.9.2 supports `AUTHD_LISTEN='unix:/run/authd/authd.sock'` as an alternative to
loopback TCP. The unit provisions `/run/authd` with `RuntimeDirectory=authd`, mode
`0711`, daemon ownership and retention across service stops. Only this directory
is writable under `ProtectSystem=strict`; private config/key/pgpass paths remain
read-only. The retained mode-0600 socket lock file is normal after shutdown.

Use a separate proxy-sharing group for a mode-0660 socket, not `_authd`. Set up
supplementary groups for both the daemon and actual proxy worker, then restart
affected processes. Source-IP forwarding over Unix requires explicit
`AUTHD_TRUST_UNIX_PROXY=true`; it is not implied by TCP trusted-proxy CIDRs.

The full configuration/cutover and a proxy example are in
[`../../docs/UNIX_SOCKET.md`](../../docs/UNIX_SOCKET.md). Existing TCP settings
remain valid. Install and verify the new listener before repointing an upstream.
For a custom runtime directory, provision it and add a site-specific
`ReadWritePaths` drop-in. No systemd socket activation is implemented.
