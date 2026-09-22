# OpenBSD deployment assets

The complete procedure is in [`../../DEPLOYMENT.md`](../../DEPLOYMENT.md).

Files in this directory:

```text
rc.d/authd       native OpenBSD service wrapper
pgpass.example   PostgreSQL runtime-password file format
```

The service deliberately follows the WaveControl rc.d environment pattern:
`/etc/authd/authd.env` is sourced with `set -a` both while validating the
service configuration and again inside `rc_exec`, after `rc.subr` applies
`daemon_user=_authd`. This means ordinary process-environment configuration is
available to authd without putting secrets in `authd_flags` or
`/etc/rc.conf.local`.

Expected installed permissions:

```text
/etc/authd                  root:_authd   0750
/etc/authd/authd.env        root:_authd   0640
/etc/authd/master.key       _authd:_authd 0400
/etc/authd/pgpass           _authd:_authd 0400
/etc/rc.d/authd             root:wheel    0555
/usr/local/bin/authd        root:bin      0755
```

`make install-openbsd` is a greenfield-only installer. It creates the service
account, binary/service, active env file, and first master key. If an active env
or master-key file already exists it refuses to continue; upgrade/merge policy is
not implemented yet. It does **not** create `/etc/authd/pgpass`; the operator
must populate that file with the real `authd_runtime` password.
