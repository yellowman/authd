-- Group membership and protected, one-time dynamic client registration.
CREATE TABLE groups (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name text NOT NULL UNIQUE CHECK (name ~ '^[a-z0-9][a-z0-9._:-]*$'),
    description text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE group_roles (
    group_id uuid NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    role_id uuid NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, role_id)
);

CREATE TABLE user_groups (
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    group_id uuid NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, group_id)
);

CREATE TABLE initial_registration_tokens (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    token_hash bytea NOT NULL UNIQUE,
    scope_prefix text NOT NULL CHECK (scope_prefix ~ '^[a-z0-9][a-z0-9._:-]*\.$'),
    expires_at timestamptz NOT NULL,
    used_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX initial_registration_tokens_expiry_idx ON initial_registration_tokens(expires_at);

ALTER TABLE clients ADD COLUMN dynamic_registration boolean NOT NULL DEFAULT false;
