# Changelog

## v0.4 — local identity and administration

Implemented explicit one-time bootstrap, PostgreSQL identity repository, local
password/MFA login, sessions/CSRF, password lifecycle, TOTP enrollment/recovery,
user/role/permission management, session inventory/revocation, and audit browsing.
Added transactional authority/snapshot rechecks, final-admin protection, bounded
KDF input/concurrency, strict configuration, and responsive real forms.

Added additive migration 002; no rewrite of migration 001. Added unit/race/HTTP
regressions and an explicit real-PostgreSQL integration suite. Dependency-free
checks now execute actual production components without substitute modules.
Added a full database-backed CI gate definition. Corrected the PostgreSQL 18
container volume mount to /var/lib/postgresql (upstream image PGDATA contract).

Not an OIDC completion or production signoff. See VALIDATION.md for exact evidence
and TODO.md for unfinished handlers and operational work.

## v0.3 — baseline

Separated password credentials from identities and refined the protocol-neutral
AAA credential/peer model. This release is the parent of v0.4.
