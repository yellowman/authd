# External authd v0.9.0 qualification report

Received from the user in this conversation on 2026-09-22. This is the supplied
summary, not a raw terminal transcript or an independently repeated test run.
The report names v0.9.0; it does not supply the tested Git SHA, PostgreSQL version,
compiler version or native-service execution logs. The delivered v0.9.0 source
archive corresponds to commit `b8d336d`.

## Supplied report (verbatim)

```text
_ authd v0.9.0 passes the main local qualification:

  - make verify-openbsd: passed formatting, tests, vet, build, PostgreSQL integration, and deployment
    syntax.

  - Greenfield PostgreSQL setup: database/roles creation, owner migration, runtime grants, and runtime
    bootstrap passed.

  - Live OIDC flow: discovery, bootstrap, consent, PKCE, client_secret_post, ID-token claims, UserInfo,
    refresh rotation, and code-replay protection passed.

  Not exercised: the actual bdcmaps callback at maps.ykwc.com, HTTPS/proxy behavior, native service
  installation, MFA, and Linux race/systemd qualification.

  One documentation issue remains: v0.9 still recommends interactive \password and uses doas -u
  _postgresql psql in its OpenBSD example. That does not match your preferred psql -Upostgres workflow.
```

## Interpretation boundary

The reported PostgreSQL suite is evidence of v0.9.0 execution, not just the older
v0.8 test copy. It does not establish production conformance or capacity. Positive
owner/runtime setup does not, by itself, prove every denied privilege: no explicit
runtime DDL/owner-assumption refusal transcript was supplied. A greenfield pass is
not a restored-existing-database migration or backup/restore/failover test. Unknown
coverage stays unknown rather than being inferred from a successful login.
