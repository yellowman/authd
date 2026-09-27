package db

import (
	"context"
	"database/sql"
	"errors"

	"github.com/yellowman/authd/internal/identity"
	"github.com/yellowman/authd/internal/oidc"
)

// The caller supplies a live session, never a user ID from browser input.
func (s *OIDCStore) ConsentApproval(ctx context.Context, sessionHash []byte, clientID string) (out oidc.ConsentApproval, err error) {
	err = s.grantWrite(ctx, func(tx *sql.Tx) error {
		session, e := requireSession(ctx, tx, sessionHash, false, false, false)
		if errors.Is(e, identity.ErrSession) || errors.Is(e, identity.ErrForbidden) {
			return oidc.ErrLoginRequired
		}
		if e != nil {
			return e
		}
		client, e := clientByDBID(ctx, tx, clientID)
		if e != nil {
			return e
		}
		if !client.Enabled {
			return oidc.ErrInvalidClient
		}
		var scopes, idClaims, infoClaims string
		e = tx.QueryRowContext(ctx, `SELECT array_to_json(scopes)::text,array_to_json(id_token_claims)::text,array_to_json(userinfo_claims)::text,approved_at
 FROM client_consent_approvals WHERE user_id=$1::uuid AND client_id=$2::uuid`, session.User.ID, client.ID).Scan(&scopes, &idClaims, &infoClaims, &out.ApprovedAt)
		if errors.Is(e, sql.ErrNoRows) {
			return nil
		}
		if e != nil {
			return e
		}
		if out.Scopes, e = decodeList(scopes); e != nil {
			return e
		}
		if out.IDTokenClaims, e = decodeList(idClaims); e != nil {
			return e
		}
		out.UserInfoClaims, e = decodeList(infoClaims)
		return e
	})
	return
}

func saveConsentApprovalTx(ctx context.Context, tx *sql.Tx, userID, clientID string, request oidc.AuthorizationRequest) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO client_consent_approvals(user_id,client_id,scopes,id_token_claims,userinfo_claims)
 VALUES($1::uuid,$2::uuid,ARRAY(SELECT jsonb_array_elements_text($3::jsonb)),ARRAY(SELECT jsonb_array_elements_text($4::jsonb)),ARRAY(SELECT jsonb_array_elements_text($5::jsonb)))
 ON CONFLICT (user_id,client_id) DO UPDATE SET scopes=EXCLUDED.scopes,id_token_claims=EXCLUDED.id_token_claims,userinfo_claims=EXCLUDED.userinfo_claims,approved_at=clock_timestamp()`, userID, clientID, listJSON(request.Scopes), listJSON(request.Claims.IDToken), listJSON(request.Claims.UserInfo))
	return err
}
