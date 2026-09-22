-- OIDC RP integration contract additions.
--
-- required_acr stores the single authd assurance level selected from the RP's
-- ordered acr_values preference list. The raw preference list is not authority;
-- authd persists only the requirement it committed to enforce.
ALTER TABLE authorization_requests
    ADD COLUMN required_acr text NOT NULL DEFAULT '',
    ADD CONSTRAINT authorization_requests_required_acr CHECK (
        required_acr IN ('','urn:authd:acr:pwd','urn:authd:acr:mfa')
    );

-- sid names the provider login session that authenticated the user. It is kept
-- as a UUID value without an FK on purpose: authorization codes and refresh
-- families may outlive deletion/revocation of the live provider session, but
-- RPs still need the original stable sid for local-session correlation and
-- future back-channel logout.
ALTER TABLE authorization_codes
    ADD COLUMN session_id uuid;

ALTER TABLE refresh_token_families
    ADD COLUMN session_id uuid;
