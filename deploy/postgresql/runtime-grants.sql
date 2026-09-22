\set ON_ERROR_STOP on

-- Run this as the same PostgreSQL role that owns/applies authd migrations.
-- The runtime LOGIN role must already exist. deploy/postgresql/create-database.sql
-- creates the default dedicated role; passwords are set interactively by the operator.
--
-- Override at invocation time when needed:
--   psql -v authd_schema=authd -v authd_runtime_role=authd_runtime -f runtime-grants.sql
\if :{?authd_schema}
\else
\set authd_schema public
\endif
\if :{?authd_runtime_role}
\else
\set authd_runtime_role authd_runtime
\endif

SELECT format('GRANT CONNECT ON DATABASE %I TO %I', current_database(), :'authd_runtime_role')
\gexec

REVOKE CREATE ON SCHEMA :"authd_schema" FROM PUBLIC;
REVOKE CREATE ON SCHEMA :"authd_schema" FROM :"authd_runtime_role";
GRANT USAGE ON SCHEMA :"authd_schema" TO :"authd_runtime_role";
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA :"authd_schema" TO :"authd_runtime_role";
GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA :"authd_schema" TO :"authd_runtime_role";

-- Future objects created by this migration owner inherit the same runtime DML
-- access. DDL ownership/CREATE is deliberately not granted to the runtime role.
ALTER DEFAULT PRIVILEGES IN SCHEMA :"authd_schema"
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO :"authd_runtime_role";
ALTER DEFAULT PRIVILEGES IN SCHEMA :"authd_schema"
    GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO :"authd_runtime_role";
