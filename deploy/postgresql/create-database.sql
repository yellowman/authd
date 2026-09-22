\set ON_ERROR_STOP on

-- Greenfield PostgreSQL cluster bootstrap for authd.
--
-- Run this while connected to a maintenance database (normally `postgres`) as
-- a PostgreSQL cluster administrator. The script creates dedicated LOGIN roles
-- and the authd database but deliberately does not set passwords. Set passwords
-- interactively afterwards with psql's \password command so credentials do not
-- appear in this file, shell history, or the process list.
--
-- Override defaults with psql -v when needed:
--   -v authd_database=authd
--   -v authd_owner_role=authd_owner
--   -v authd_runtime_role=authd_runtime

\if :{?authd_database}
\else
\set authd_database authd
\endif
\if :{?authd_owner_role}
\else
\set authd_owner_role authd_owner
\endif
\if :{?authd_runtime_role}
\else
\set authd_runtime_role authd_runtime
\endif

SELECT format(
    'CREATE ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT',
    :'authd_owner_role')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'authd_owner_role')
\gexec

SELECT format(
    'CREATE ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT',
    :'authd_runtime_role')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'authd_runtime_role')
\gexec

SELECT format(
    'CREATE DATABASE %I OWNER %I TEMPLATE template0 ENCODING ''UTF8''',
    :'authd_database', :'authd_owner_role')
WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = :'authd_database')
\gexec

-- Do not leave CONNECT open to every cluster role. authd uses only the
-- migration owner and the DML-only runtime role.
SELECT format('REVOKE CONNECT, TEMPORARY ON DATABASE %I FROM PUBLIC', :'authd_database')
\gexec
SELECT format('GRANT CONNECT ON DATABASE %I TO %I', :'authd_database', :'authd_owner_role')
\gexec
SELECT format('GRANT CONNECT ON DATABASE %I TO %I', :'authd_database', :'authd_runtime_role')
\gexec

\echo 'authd database objects exist. Set LOGIN passwords interactively in psql for roles:' :authd_owner_role 'and' :authd_runtime_role
\echo 'Then run authd migrate with the owner role and runtime-grants.sql against the authd database.'
