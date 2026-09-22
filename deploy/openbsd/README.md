# OpenBSD deployment assets

The complete procedure is in [`../../DEPLOYMENT.md`](../../DEPLOYMENT.md).
Unix-socket mode, the separate proxy group and chroot path mapping are in
[`../../docs/UNIX_SOCKET.md`](../../docs/UNIX_SOCKET.md).

```text
rc.d/authd       native OpenBSD service wrapper
authd-run        post-su environment loader; execs the foreground Go server
pgpass.example  PostgreSQL runtime-password file format
```

`rc.subr` performs its normal start/background/check handling with `rc_bg=YES`.
`rc_pre` validates the env and, for supported Unix paths, creates a dedicated
runtime directory under an existing controlled parent. The installed
`/usr/local/libexec/authd-run` sources `/etc/authd/authd.env` with `set -a` after
`daemon_user=_authd` is applied, then execs the binary. Environment survives the
privilege transition without secrets in `authd_flags` or `/etc/rc.conf.local`.
The final process expression is set after rc.subr and does not match concurrent
bootstrap or migration commands.

The standard Unix path is `/var/run/authd/authd.sock`. `/run/authd` and
`/var/www/run/authd` are also supported when their root-controlled parents already
exist; custom paths require explicit provisioning. The directory is daemon-owned,
normally `0711`, and is never group/world writable. Go owns the socket and its
lifetime lock; rc.d never removes either as a startup shortcut.

Expected private runtime permissions stay unchanged:

```text
/etc/authd                      root:_authd   0750
/etc/authd/authd.env             root:_authd   0640
/etc/authd/master.key            _authd:_authd 0400
/etc/authd/pgpass                _authd:_authd 0400
/etc/rc.d/authd                 root          0555
/usr/local/libexec/authd-run    root          0555
/usr/local/bin/authd            root          0755
```

Socket-sharing uses a separate `authd_proxy` group; the proxy must not become a
member of the private `_authd` group. See the socket guide for exact commands.

`make install-openbsd` is repeatable. It preserves active env, master key and
pgpass while replacing binary, docs, examples, launcher and rc.d assets.
It creates no runtime pgpass password and does not migrate the database.
`authd migrate` remains a separate owner-credential step. v0.9.2 adds no migration.
Native rcctl start/check/restart/stop still require actual OpenBSD qualification;
shell syntax checks and cross-compilation are not proof of native service use.
