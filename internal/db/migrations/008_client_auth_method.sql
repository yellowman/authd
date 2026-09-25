-- Existing clients remain NULL to preserve their previously accepted client
-- authentication methods. New dynamic registrations record their choice.
ALTER TABLE clients ADD COLUMN token_endpoint_auth_method text;
ALTER TABLE clients ADD CONSTRAINT clients_token_endpoint_auth_method_check CHECK (
    token_endpoint_auth_method IS NULL OR
    (client_type = 'confidential' AND token_endpoint_auth_method IN ('client_secret_basic', 'client_secret_post'))
);
