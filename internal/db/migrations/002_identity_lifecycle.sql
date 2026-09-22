-- Additive migration: do not rewrite 001 on an existing installation.
CREATE TABLE installation_state (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    bootstrap_completed boolean NOT NULL DEFAULT false,
    initialized_at timestamptz
);
INSERT INTO installation_state(singleton, bootstrap_completed, initialized_at)
SELECT true, EXISTS(SELECT 1 FROM users) OR EXISTS(SELECT 1 FROM bootstrap_tokens WHERE consumed_at IS NOT NULL),
       CASE WHEN EXISTS(SELECT 1 FROM users) OR EXISTS(SELECT 1 FROM bootstrap_tokens WHERE consumed_at IS NOT NULL) THEN now() END;

CREATE TABLE pending_totp_enrollments (
    user_id uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    session_id uuid NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    secret_ciphertext bytea NOT NULL,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX pending_totp_expiry_idx ON pending_totp_enrollments(expires_at);

-- Keep verification state honest even for operator SQL updates.
UPDATE users SET email_verified=false WHERE email IS NULL;
CREATE FUNCTION authd_clear_email_verification() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF lower(btrim(NEW.email)) IS DISTINCT FROM lower(btrim(OLD.email)) OR NEW.email IS NULL THEN
        NEW.email_verified := false;
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER users_clear_email_verification BEFORE UPDATE OF email, email_verified ON users
FOR EACH ROW EXECUTE FUNCTION authd_clear_email_verification();
ALTER TABLE users ADD CONSTRAINT users_verified_email_present CHECK (NOT email_verified OR email IS NOT NULL);
