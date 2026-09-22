-- Fail atomically if an old application permission collides with an OIDC
-- control scope. Operators must explicitly rename/remove those grants first.
ALTER TABLE permissions ADD CONSTRAINT permissions_no_oidc_control_scope
 CHECK (name NOT IN ('openid','profile','email','groups','roles','offline_access'));

-- Outstanding browser flows lack the new browser binding and cannot be migrated
-- into authenticated authority. Only restart those short-lived flows; identities,
-- secrets, sessions and established offline grants are preserved.
DELETE FROM authorization_requests;
DELETE FROM authorization_codes WHERE consumed_at IS NULL;
ALTER TABLE authorization_requests
 ADD COLUMN claims jsonb NOT NULL DEFAULT '{}'::jsonb,
 ADD COLUMN browser_hash bytea NOT NULL CHECK (octet_length(browser_hash)=32),
 ADD COLUMN consent_session_id uuid,
 ADD COLUMN preferred_acr text NOT NULL DEFAULT '',
 ADD COLUMN expected_subjects text[] NOT NULL DEFAULT ARRAY[]::text[],
 ADD COLUMN max_age_seconds bigint CHECK (max_age_seconds >= 0),
 DROP CONSTRAINT authorization_requests_prompt, DROP COLUMN min_auth_time;
ALTER TABLE authorization_codes
 ADD COLUMN claims jsonb NOT NULL DEFAULT '{}'::jsonb,
 ADD COLUMN refresh_family_id uuid REFERENCES refresh_token_families(id) ON DELETE SET NULL,
 ADD COLUMN acr text NOT NULL DEFAULT '';
ALTER TABLE refresh_token_families ADD COLUMN acr text NOT NULL DEFAULT '', ADD COLUMN claims jsonb NOT NULL DEFAULT '{}'::jsonb;
UPDATE refresh_token_families SET acr=CASE
 WHEN 'pwd'=ANY(auth_methods) AND ('otp'=ANY(auth_methods) OR 'recovery'=ANY(auth_methods)) THEN 'urn:authd:acr:mfa'
 WHEN 'pwd'=ANY(auth_methods) THEN 'urn:authd:acr:pwd'
 ELSE '' END;
-- Reverse-FK lookups must be indexed for revocation, cleanup and parent deletion.
CREATE INDEX user_roles_role_idx ON user_roles(role_id);
CREATE INDEX role_permissions_permission_idx ON role_permissions(permission_id);
CREATE INDEX client_permissions_permission_idx ON client_permissions(permission_id);
CREATE INDEX authorization_requests_client_idx ON authorization_requests(client_id);
CREATE INDEX authorization_codes_client_idx ON authorization_codes(client_id);
CREATE INDEX authorization_codes_user_idx ON authorization_codes(user_id);
CREATE INDEX authorization_codes_session_idx ON authorization_codes(session_id);
CREATE INDEX authorization_codes_family_idx ON authorization_codes(refresh_family_id);
CREATE INDEX refresh_families_client_idx ON refresh_token_families(client_id);
CREATE INDEX refresh_families_user_idx ON refresh_token_families(user_id);
CREATE INDEX refresh_families_session_idx ON refresh_token_families(session_id);
CREATE INDEX refresh_families_expiry_idx ON refresh_token_families(absolute_expires_at);
CREATE INDEX sessions_idle_expiry_idx ON sessions(idle_expires_at);
CREATE INDEX pending_totp_session_idx ON pending_totp_enrollments(session_id);

CREATE INDEX client_redirect_origin_idx ON client_redirect_uris (lower(substring(uri from '^(https?://[^/?#]+)')));
