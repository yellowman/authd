-- Presentation history, not an authorization grant or a consent bypass.
-- Start empty: old sessions, roles and audit entries cannot prove what a person
-- reviewed. Record only a completed, explicitly approved authorization request.
CREATE TABLE client_consent_approvals (
 user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 client_id uuid NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
 scopes text[] NOT NULL,
 id_token_claims text[] NOT NULL DEFAULT ARRAY[]::text[],
 userinfo_claims text[] NOT NULL DEFAULT ARRAY[]::text[],
 approved_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY (user_id,client_id)
);
CREATE INDEX client_consent_approvals_client_idx ON client_consent_approvals(client_id);
