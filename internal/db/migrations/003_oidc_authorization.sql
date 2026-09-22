-- Durable authorization request continuations. The browser carries only the
-- opaque high-entropy continuation handle; PostgreSQL stores its SHA-256 hash
-- and all OAuth/OIDC request state stays server-side.
CREATE TABLE authorization_requests (
    request_hash bytea PRIMARY KEY,
    client_id uuid NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    redirect_uri text NOT NULL,
    scopes text[] NOT NULL,
    state text,
    nonce text,
    code_challenge text NOT NULL,
    login_hint text,
    prompt text NOT NULL DEFAULT '',
    min_auth_time timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    CONSTRAINT authorization_requests_prompt CHECK (prompt IN ('','none','login'))
);
CREATE INDEX authorization_requests_expiry_idx ON authorization_requests(expires_at);

-- Token families need the authentication context that originally authorized
-- offline access. This prevents a client newly switched to require_mfa from
-- continuing a password-only family. Existing databases have no families yet
-- in v0.4, but the default keeps the migration safe if one does.
ALTER TABLE refresh_token_families
    ADD COLUMN auth_time timestamptz NOT NULL DEFAULT now(),
    ADD COLUMN auth_methods text[] NOT NULL DEFAULT ARRAY[]::text[];

ALTER TABLE refresh_tokens
    ADD COLUMN scopes text[] NOT NULL DEFAULT ARRAY[]::text[];
