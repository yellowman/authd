# OpenBSD deployment assets

The complete procedure is in [`../../DEPLOYMENT.md`](../../DEPLOYMENT.md).
Unix-socket mode, proxy group policy and chroot path mapping are in
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

Socket-sharing must use a group the running proxy worker actually has. OpenBSD
nginx may keep only its primary group, so verify with `ps -o supgrp` before
choosing `AUTHD_UNIX_GROUP`; never add the proxy to private `_authd`. See the
socket guide for exact commands.

`make install-openbsd` is repeatable. It preserves active env, master key and
pgpass while replacing binary, docs, examples, launcher and rc.d assets.
If upgrading an older installation, check the preserved env file: the supported
socket keys are `AUTHD_UNIX_MODE` and `AUTHD_UNIX_GROUP`. The older
`AUTHD_UNIX_SOCKET_MODE` and `AUTHD_UNIX_SOCKET_GROUP` names are ignored; a
restarted daemon would otherwise create a private `0600` socket and the proxy
would return 502.
It creates no runtime pgpass password and does not migrate the database.
`authd migrate` remains a separate owner-credential step. The groups and dynamic
registration upgrade adds migration 006; apply it and the runtime grants before
restarting the upgraded service.
Native rcctl start/check/restart/stop still require actual OpenBSD qualification;
shell syntax checks and cross-compilation are not proof of native service use.
