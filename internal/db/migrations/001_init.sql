CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE users (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    username text NOT NULL,
    display_name text NOT NULL DEFAULT '',
    email text,
    email_verified boolean NOT NULL DEFAULT false,
    enabled boolean NOT NULL DEFAULT true,
    force_password_change boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    last_login_at timestamptz,
    deleted_at timestamptz,
    CONSTRAINT users_username_nonempty CHECK (btrim(username) <> ''),
    CONSTRAINT users_email_nonempty CHECK (email IS NULL OR btrim(email) <> '')
);
CREATE UNIQUE INDEX users_username_unique ON users ((lower(username))) WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX users_email_unique ON users ((lower(email))) WHERE email IS NOT NULL AND deleted_at IS NULL;

-- Credentials are deliberately separate from identity rows. The canonical
-- primary password is an Argon2id verifier. Future protocol-specific
-- credentials (if a real deployment requires them) receive their own explicit
-- tables/migrations rather than adding recoverable secret material here.
CREATE TABLE password_credentials (
    user_id uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    password_hash text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    changed_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT password_credentials_hash_nonempty CHECK (btrim(password_hash) <> '')
);

CREATE TABLE permissions (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name text NOT NULL UNIQUE,
    description text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT permissions_name_format CHECK (name ~ '^[a-z0-9][a-z0-9._:-]*$')
);

CREATE TABLE roles (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name text NOT NULL UNIQUE,
    description text NOT NULL DEFAULT '',
    built_in boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT roles_name_format CHECK (name ~ '^[a-z0-9][a-z0-9._:-]*$')
);

CREATE TABLE user_roles (
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id uuid NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, role_id)
);

CREATE TABLE role_permissions (
    role_id uuid NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id uuid NOT NULL REFERENCES permissions(id) ON DELETE RESTRICT,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (role_id, permission_id)
);

CREATE TABLE clients (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id text NOT NULL UNIQUE,
    name text NOT NULL,
    client_type text NOT NULL,
    client_secret_hash bytea,
    enabled boolean NOT NULL DEFAULT true,
    require_mfa boolean NOT NULL DEFAULT false,
    refresh_tokens_enabled boolean NOT NULL DEFAULT false,
    access_token_ttl_seconds integer NOT NULL DEFAULT 300,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT clients_type CHECK (client_type IN ('public','confidential')),
    CONSTRAINT clients_public_secret CHECK (
        (client_type='public' AND client_secret_hash IS NULL) OR
        (client_type='confidential' AND client_secret_hash IS NOT NULL)
    ),
    CONSTRAINT clients_ttl CHECK (access_token_ttl_seconds BETWEEN 30 AND 3600)
);

CREATE TABLE client_redirect_uris (
    client_id uuid NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    uri text NOT NULL,
    PRIMARY KEY (client_id, uri)
);

CREATE TABLE client_logout_uris (
    client_id uuid NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    uri text NOT NULL,
    PRIMARY KEY (client_id, uri)
);

CREATE TABLE client_identity_scopes (
    client_id uuid NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    scope text NOT NULL,
    PRIMARY KEY (client_id, scope),
    CONSTRAINT client_identity_scope_known CHECK (scope IN ('openid','profile','email','groups','roles','offline_access'))
);

CREATE TABLE client_permissions (
    client_id uuid NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    permission_id uuid NOT NULL REFERENCES permissions(id) ON DELETE RESTRICT,
    PRIMARY KEY (client_id, permission_id)
);

CREATE TABLE authorization_codes (
    code_hash bytea PRIMARY KEY,
    client_id uuid NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    redirect_uri text NOT NULL,
    scopes text[] NOT NULL,
    nonce text,
    code_challenge text NOT NULL,
    auth_time timestamptz NOT NULL,
    auth_methods text[] NOT NULL,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX authorization_codes_expiry_idx ON authorization_codes(expires_at);

CREATE TABLE refresh_token_families (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id uuid NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    scopes text[] NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    absolute_expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    revoke_reason text
);

CREATE TABLE refresh_tokens (
    token_hash bytea PRIMARY KEY,
    family_id uuid NOT NULL REFERENCES refresh_token_families(id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now(),
    idle_expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    replacement_hash bytea
);
CREATE INDEX refresh_tokens_family_idx ON refresh_tokens(family_id);
CREATE INDEX refresh_tokens_idle_expiry_idx ON refresh_tokens(idle_expires_at);

CREATE TABLE sessions (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    token_hash bytea NOT NULL UNIQUE,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    csrf_hash bytea NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    auth_time timestamptz NOT NULL,
    auth_methods text[] NOT NULL,
    idle_expires_at timestamptz NOT NULL,
    absolute_expires_at timestamptz NOT NULL,
    ip_address inet,
    user_agent text NOT NULL DEFAULT ''
);
CREATE INDEX sessions_user_idx ON sessions(user_id);
CREATE INDEX sessions_expiry_idx ON sessions(absolute_expires_at);

CREATE TABLE totp_credentials (
    user_id uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    secret_ciphertext bytea NOT NULL,
    last_counter bigint,
    created_at timestamptz NOT NULL DEFAULT now(),
    confirmed_at timestamptz NOT NULL
);

CREATE TABLE recovery_codes (
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash bytea NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    consumed_at timestamptz,
    PRIMARY KEY (user_id, code_hash)
);

CREATE TABLE signing_keys (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    kid text NOT NULL UNIQUE,
    algorithm text NOT NULL DEFAULT 'RS256',
    private_key_ciphertext bytea NOT NULL,
    public_jwk jsonb NOT NULL,
    active boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now(),
    retired_at timestamptz,
    CONSTRAINT signing_keys_algorithm CHECK (algorithm='RS256')
);
CREATE UNIQUE INDEX signing_keys_one_active ON signing_keys((active)) WHERE active;

CREATE TABLE bootstrap_tokens (
    token_hash bytea PRIMARY KEY,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE audit_events (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    occurred_at timestamptz NOT NULL DEFAULT now(),
    event_type text NOT NULL,
    actor_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
    target_type text,
    target_id text,
    source_ip inet,
    request_id text,
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX audit_events_time_idx ON audit_events(occurred_at DESC);
CREATE INDEX audit_events_actor_idx ON audit_events(actor_user_id, occurred_at DESC);
CREATE INDEX audit_events_type_idx ON audit_events(event_type, occurred_at DESC);

INSERT INTO permissions(name, description)
VALUES ('system.admin', 'Access authd administration')
ON CONFLICT (name) DO NOTHING;

INSERT INTO roles(name, description, built_in)
VALUES ('system-admin', 'authd administrators', true)
ON CONFLICT (name) DO NOTHING;

INSERT INTO role_permissions(role_id, permission_id)
SELECT r.id, p.id
FROM roles r, permissions p
WHERE r.name='system-admin' AND p.name='system.admin'
ON CONFLICT DO NOTHING;
