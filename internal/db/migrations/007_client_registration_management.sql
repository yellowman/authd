-- A client-bound management credential permits explicit updates to a dynamic
-- registration without recreating its client ID or changing its login secret.
CREATE TABLE client_registration_credentials (
    client_id uuid PRIMARY KEY REFERENCES clients(id) ON DELETE CASCADE,
    scope_prefix text NOT NULL CHECK (scope_prefix ~ '^[a-z0-9][a-z0-9._:-]*\.$'),
    token_hash bytea NOT NULL UNIQUE,
    issued_at timestamptz NOT NULL DEFAULT now()
);

-- Templates create roles and groups, but never assign a user to either.
CREATE TABLE client_role_templates (
    client_id uuid NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    role_id uuid NOT NULL UNIQUE REFERENCES roles(id) ON DELETE CASCADE,
    PRIMARY KEY (client_id, role_id)
);
CREATE TABLE client_group_templates (
    client_id uuid NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    group_id uuid NOT NULL UNIQUE REFERENCES groups(id) ON DELETE CASCADE,
    PRIMARY KEY (client_id, group_id)
);
