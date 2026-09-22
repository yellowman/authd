# HTTP over a Unix socket

**Implemented in v0.9.2. v0.9.0/v0.9.1 are TCP-only.** Install the new binary,
start it successfully, and verify the socket before changing an existing proxy
upstream. This change does not touch the PostgreSQL schema or OIDC credentials.

## Configuration and public identity

Exactly one HTTP listener is selected. Existing `AUTHD_LISTEN=127.0.0.1:8080`
configurations continue to work. For a same-host Linux reverse proxy:

```sh
AUTHD_ISSUER='https://auth.example.com'
AUTHD_LISTEN='unix:/run/authd/authd.sock'
AUTHD_UNIX_MODE='0660'
AUTHD_UNIX_GROUP='authd_proxy'
AUTHD_TRUST_UNIX_PROXY='true'
```

Put these settings in `/etc/authd/authd.env`. Keep `DATABASE_URL`, `PGPASSFILE`,
and `AUTHD_MASTER_KEY_FILE` unchanged. A bare absolute path such as
`AUTHD_LISTEN='/run/authd/authd.sock'` is also accepted. Use `unix:/path`, not a
`unix://` URL. Relative paths, abstract sockets, unclean paths and permissive
socket modes are rejected. The whole path is limited to 103 bytes and its parent
to 83 bytes, including the resolved parent path, to fit OpenBSD's Unix socket
address and a private staging name.

The public issuer, discovery URLs, redirects, Origin checks and secure-cookie
policy are independent of the listener. They remain HTTPS. Never use a socket
path as the issuer and never enable development mode to connect a production
proxy. The listener is ordinary HTTP over AF_UNIX, not FastCGI or direct TLS.
Binding errors stop startup; there is no silent fallback to TCP.

`AUTHD_UNIX_MODE` defaults to `0600` (daemon-only). The only other supported mode
is `0660`. `AUTHD_UNIX_GROUP` is optional and accepts a local group name or numeric
GID. The daemon must already be permitted to set that group, normally by being a
supplementary member. Startup refuses an unknown or unauthorized group rather
than widening permissions. `AUTHD_TRUST_UNIX_PROXY` defaults to `false`.

When reverting to TCP, unset the Unix group/mode settings and remove or set false
`AUTHD_TRUST_UNIX_PROXY`. Incompatible Unix options on a TCP listener are errors.
Neither `authd migrate` nor `authd bootstrap` creates or binds the HTTP socket.

## Keep proxy access separate from secret access

Use a dedicated socket-sharing group, for example `authd_proxy`. Do **not** add
nginx or another proxy to `_authd`: `/etc/authd/authd.env` uses that private group,
and proxy access must not confer access to authd's runtime configuration.
Do not change the private master-key/pgpass ownership or permissions.

The final layout is:

```text
socket parent      _authd:_authd       0711
socket             _authd:authd_proxy  0660
socket.lock        _authd:_authd       0600
```

The group of `socket.lock` is the daemon's primary group in the prescribed
layout; its mode is always owner-only. Parent mode `0711` permits traversal, not
listing or mutation by other users. The socket's permissions gate connections.
The parent must be owned by the daemon and must not be group/world writable.
Ancestors must be root-controlled or daemon-controlled; use a local runtime
filesystem, not a shared writable directory or a network filesystem.

Create `authd_proxy` only if it does not already exist. Substitute the **actual
nginx worker account**, not the master process's root account, in these commands.
The `www` and `www-data` names below are examples, not autodetection.

OpenBSD:

```sh
doas groupadd authd_proxy                 # first creation only
doas usermod -G authd_proxy _authd
proxy_user=www                            # verify in this site's nginx config
doas usermod -G authd_proxy "$proxy_user"
```

OpenBSD `usermod -G` appends supplementary groups. On Linux use `-aG` instead:

```sh
sudo groupadd --system authd_proxy        # first creation only
sudo usermod -aG authd_proxy _authd
proxy_user=www-data                       # or nginx / the actual worker account
sudo usermod -aG authd_proxy "$proxy_user"
```

Restart affected services so running processes acquire the new supplementary
groups. A fresh shell's `id` output alone does not prove a running worker has
them. Confirm the actual worker can connect. Never solve an access error with
`chmod 0666` or a shared writable socket directory.

## Linux / systemd

The supplied service creates `/run/authd` as `_authd` with mode `0711` using
`RuntimeDirectory=authd`. `ReadWritePaths=/run/authd` makes only that directory
writable under `ProtectSystem=strict`; `/etc/authd` and the application tree
remain read-only. The directory is retained across service stops so its lifetime
lock inode is not casually replaced. `/run` is still ephemeral across reboot.

After installing and setting group membership and the environment:

```sh
sudo systemctl daemon-reload
sudo systemctl restart authd
sudo systemctl status authd
sudo journalctl -u authd --since '5 minutes ago'
```

For a custom path outside `/run/authd`, provision its parent explicitly and add
a site systemd drop-in granting `ReadWritePaths` for precisely that directory.
Review its traversal and ownership as above. No `authd.socket` unit or socket
activation is implemented; authd creates and owns its listening socket itself.

## OpenBSD / rc.d

Use `AUTHD_LISTEN='unix:/var/run/authd/authd.sock'` for an ordinary OpenBSD layout.
The rc.d `rc_pre` step creates a missing `/var/run/authd` as `_authd`, mode `0711`.
It also supports `/run/authd` when the operator has provisioned a root-controlled
`/run`, and `/var/www/run/authd` for the chroot example below. Other socket
parents must be provisioned explicitly before service start. Existing parent
ownership and writability are checked, not silently repaired.

The service runs the standard `rc.subr` start/background/wait path with
`rc_bg=YES`. `/usr/local/libexec/authd-run` sources the protected environment
**after** the transition to `_authd`, then `exec`s `/usr/local/bin/authd`. The
process expression matches the server, not a concurrent `bootstrap` or `migrate`
command. No credentials are passed through `authd_flags` or process arguments.

```sh
doas rcctl restart authd
doas rcctl check authd
```

The launcher is a required installed file; copying just the new rc.d script onto
an old installation is insufficient. Use `make install-openbsd` from the new
release. This preserves existing env, pgpass and master-key contents.

### A proxy inside a filesystem chroot

Determine whether the actual proxy worker is chrooted. A path inside its chroot
and the host's path are different names for the **same socket inode**. For a
proxy whose root is `/var/www`, one possible layout is:

```text
authd (host) path:     /var/www/run/authd/authd.sock
nginx (chroot) path:   /run/authd/authd.sock
```

Create `/var/www/run` as root-owned, not group/world writable, and traversable by
`_authd`, if that directory is not already correctly provisioned. Then configure:

```sh
AUTHD_LISTEN='unix:/var/www/run/authd/authd.sock'
```

The rc.d step creates the final `authd` directory beneath the existing controlled
parent. Set nginx's upstream to its **chroot-relative** `/run/authd/authd.sock`.
Do not create a symlink to a host path outside the chroot; it cannot escape the
worker's filesystem root. Keep the separate proxy group and socket mode policy.
A non-chrooted proxy instead uses the ordinary host path. The release does not
assume every OpenBSD nginx deployment is chrooted.

## Reverse proxy and forwarded addresses

The repository includes `deploy/nginx/authd.conf.example`, installed at
`/usr/local/share/authd/nginx/authd.conf.example`. Adapt the server name,
certificates, socket namespace and logging policy; do not replace an unrelated
live server block blindly. The core location is:

```nginx
upstream authd_backend {
    server unix:/run/authd/authd.sock;
    keepalive 16;
}
server {
    # Existing site's listen/TLS/server_name configuration belongs here.
    location / {
        proxy_pass http://authd_backend;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header Forwarded "";
        proxy_buffering off;
        proxy_cache off;
        proxy_next_upstream off;
    }
}
```

Use the matching OpenBSD host/chroot path where appropriate. `proxy_pass` without
an appended URI preserves the request path and query. The single trusted edge
**overwrites** `X-Forwarded-For`, so a browser cannot prepend a fictional address.
Do not expose auth codes or tokens through request/access/error logs; the complete
example disables access logging and still requires site error-log review.

Unix peers have no client IP. Their socket names are not IP addresses. With
`AUTHD_TRUST_UNIX_PROXY=false`, authd ignores forwarded addresses on actual Unix
connections and records an unknown/empty IP. With it set to true, authd accepts a
bounded, valid `X-Forwarded-For` chain from that Unix hop. Optional
`AUTHD_TRUSTED_PROXIES` CIDRs may identify additional upstream TCP proxy hops; they
do not cause Unix connections to be trusted automatically. Duplicate, missing,
malformed or oversized chains remain unknown rather than acquiring invented
addresses. Unknown peers share the unknown-IP rate-limit bucket.

Transport identification comes from the accepted connection, never a header or
a peer-selected socket filename. Enabling the flag delegates source-address
assertion to **every process permitted to connect to the socket**. It does not
bypass passwords, CSRF, OIDC validation or administration authorization. There is
no peer-UID login shortcut or promise of OS credential authentication.

## Startup, shutdown, and stale paths

The Go listener holds an exclusive kernel lock on `authd.sock.lock` for its
listening lifetime. That regular file is mode `0600`, must be owned by the daemon,
and is deliberately never unlinked by authd. Do not delete it to force a second
start. The kernel releases the lock after a crash; the leftover inode is normal.

A preexisting path must be an owned socket. A successful connection means it is
live and startup fails. Only `ECONNREFUSED` proves it stale enough to remove;
permission errors, timeouts and other failures are not proof of staleness.
Files, directories, symlinks and foreign-owned sockets are never removed.

A new socket is bound inside a private `0700` staging directory, given its final
group/mode, then renamed into the public path. There is no world-accessible
bind-to-chmod interval and no process-wide umask change. A crash before publication
can leave a private `.authd-*` staging directory; it is not an active public socket.

On graceful shutdown authd stops accepting, removes only its own published socket
inode, and drains requests for up to ten seconds before forcing connections
closed. It leaves a path replaced by another actor untouched. `SIGKILL` cannot
clean up files, so the next start performs the stale-path procedure. The service
scripts never `rm` a socket or its lifetime lock as a startup workaround.

## Cutover and tests

1. Build and qualify v0.9.2. Stop authd, preserve the existing config/key/pgpass, and
   install the new binary and service assets. No new database migration is needed
   from v0.9.0/v0.9.1; do not rebootstrap or rotate credentials for this change.
2. Configure the Unix listener, its distinct proxy group and source-address trust.
   Restart authd with the updated service definition. Confirm it is listening.
3. Test the socket as the daemon and the actual proxy user, then validate and reload
   the proxy. Keep the public issuer unchanged. Test public discovery, browser
   login/secure cookies and the real relying-party callback before accepting the
   cutover. A successful `/healthz` alone is not an OIDC integration test.

For example (on Linux, substitute `doas` and the socket path on OpenBSD):

```sh
sudo -u _authd curl --fail --unix-socket /run/authd/authd.sock http://localhost/healthz
sudo -u "$proxy_user" curl --fail --unix-socket /run/authd/authd.sock http://localhost/healthz
sudo nginx -t
sudo systemctl reload nginx
curl --fail https://auth.example.com/.well-known/openid-configuration
```

The plain-HTTP local health requests only test transport/connect permissions;
they do not relax or test production browser-cookie enforcement. A chrooted
worker's reachability must also be checked in its actual filesystem namespace.

For a transport rollback, restore the old TCP listener value, unset Unix-only
options, restart authd and restore the matching proxy upstream. No database or
key rollback is involved. The previous v0.9.0 external OpenBSD/PostgreSQL report
does not qualify this new listener or service wrapper. See `../VALIDATION.md` for
the tests actually run and the remaining native-host qualification.

## Primary references

- [Go net / UnixListener lifecycle](https://pkg.go.dev/net#UnixListener).
- [OpenBSD Unix-domain sockets](https://man.openbsd.org/unix.4).
- [OpenBSD flock](https://man.openbsd.org/flock.2).
- [OpenBSD rc.subr](https://man.openbsd.org/rc.subr.8).
- [OpenBSD usermod](https://man.openbsd.org/usermod.8).
- [systemd execution / RuntimeDirectory](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html).
- [nginx proxy module](https://nginx.org/en/docs/http/ngx_http_proxy_module.html).
