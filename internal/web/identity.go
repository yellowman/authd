package web

import (
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	qrcode "github.com/skip2/go-qrcode"
	"github.com/yellowman/authd/internal/identity"
	"github.com/yellowman/authd/internal/oidc"
)

func (s *Server) setup(w http.ResponseWriter, r *http.Request) {
	open, err := s.auth.Store.BootstrapOpen(r.Context())
	if err != nil {
		s.failure(w, r, err)
		return
	}
	if !open {
		http.NotFound(w, r)
		return
	}
	d := s.data("Initial administrator")
	d.CSRF, err = s.browserCSRF(w, r)
	if err != nil {
		s.failure(w, r, err)
		return
	}
	s.render(w, 200, "setup.html", d)
}
func (s *Server) setupPost(w http.ResponseWriter, r *http.Request) {
	if err := s.anonForm(w, r); err != nil {
		s.failure(w, r, err)
		return
	}
	err := s.auth.Bootstrap(r.Context(), r.PostForm.Get("bootstrap_token"), profile(r), r.PostForm.Get("password"), auditInfo(w, r))
	if err != nil {
		s.failure(w, r, err)
		return
	}
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}
func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	d := s.data("Sign in")
	if err := s.loadBranding(r, &d); err != nil {
		s.failure(w, r, err)
		return
	}
	var err error
	d.CSRF, err = s.browserCSRF(w, r)
	if err != nil {
		s.failure(w, r, err)
		return
	}
	d.ReturnTo = safeReturn(r.URL.Query().Get("return_to"))
	if raw := r.URL.Query().Get("oidc"); raw != "" {
		if client, hint, requiresMFA, ok := s.oidc.PendingLogin(r.Context(), raw, s.cookie(r, "oidc_browser")); ok {
			d.ClientRequiresMFA = requiresMFA
			d.ClientName, d.LoginHint, d.OIDCRequest = client, hint, raw
			d.ReturnTo = "/authorize"
		}
	}
	s.render(w, 200, "login.html", d)
}
func (s *Server) loginPost(w http.ResponseWriter, r *http.Request) {
	if err := s.anonForm(w, r); err != nil {
		s.failure(w, r, err)
		return
	}
	if flow := r.PostForm.Get("oidc_request"); flow != "" {
		if _, _, ok := s.oidc.Pending(r.Context(), flow, s.cookie(r, "oidc_browser")); !ok {
			s.failure(w, r, identity.ErrForbidden)
			return
		}
	}
	raw, err := s.auth.AuthenticateReplacing(r.Context(), r.PostForm.Get("username"), r.PostForm.Get("password"), r.PostForm.Get("factor"), r.UserAgent(), s.cookie(r, "session"), auditInfo(w, r))
	if err != nil {
		if errors.Is(err, identity.ErrCredentials) {
			d := s.data("Sign in")
			if err := s.loadBranding(r, &d); err != nil {
				s.failure(w, r, err)
				return
			}
			d.CSRF = s.auth.CSRF(s.cookie(r, "browser"), "browser")
			d.ReturnTo = safeReturn(r.PostForm.Get("return_to"))
			if raw := r.PostForm.Get("oidc_request"); raw != "" {
				if client, hint, requiresMFA, ok := s.oidc.PendingLogin(r.Context(), raw, s.cookie(r, "oidc_browser")); ok {
					d.ClientRequiresMFA = requiresMFA
					d.ClientName, d.LoginHint, d.OIDCRequest = client, hint, raw
					d.ReturnTo = "/authorize"
				}
			}
			d.Error = "Invalid credentials. Check your password and authenticator or recovery code."
			s.render(w, 401, "login.html", d)
		} else {
			s.failure(w, r, err)
		}
		return
	}
	// The new session and retirement of the previous browser credential are
	// already committed together. Reauthentication is not offline-grant revocation.
	s.setCookie(w, "session", raw, s.cfg.SessionAbsoluteTTL)
	s.setCookie(w, "browser", "", 0)
	if session, e := s.auth.Session(r.Context(), raw); e != nil {
		s.failure(w, r, e)
		return
	} else if session.User.ForcePasswordChange {
		http.Redirect(w, r, "/account", http.StatusSeeOther)
		return
	}
	if raw := r.PostForm.Get("oidc_request"); raw != "" {
		if _, _, ok := s.oidc.Pending(r.Context(), raw, s.cookie(r, "oidc_browser")); ok {
			oidc.RedirectFromForm(w, r, "/authorize/resume?flow="+url.QueryEscape(raw))
			return
		}
	}
	http.Redirect(w, r, safeReturn(r.PostForm.Get("return_to")), http.StatusSeeOther)
}
func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	sess, raw, ok := s.user(w, r, false, true)
	if !ok {
		return
	}
	if err := s.auth.Store.RevokeSession(r.Context(), identity.Hash(raw), sess.ID, false, auditInfo(w, r)); err != nil {
		s.failure(w, r, err)
		return
	}
	s.setCookie(w, "session", "", 0)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}
func (s *Server) account(w http.ResponseWriter, r *http.Request) {
	sess, raw, ok := s.user(w, r, false, true)
	if !ok {
		return
	}
	sessions, err := s.auth.Store.Sessions(r.Context(), identity.Hash(raw))
	if err != nil {
		s.failure(w, r, err)
		return
	}
	d := s.data("Your account")
	d.View = "account"
	d.Session = sess
	d.Sessions = sessions
	d.CSRF = s.auth.CSRF(raw, "session")
	s.render(w, 200, "account.html", d)
}
func (s *Server) changePassword(w http.ResponseWriter, r *http.Request) {
	_, raw, ok := s.user(w, r, false, true)
	if !ok {
		return
	}
	if err := s.auth.ChangePassword(r.Context(), raw, r.PostForm.Get("current_password"), r.PostForm.Get("new_password"), auditInfo(w, r)); err != nil {
		s.failure(w, r, err)
		return
	}
	s.setCookie(w, "session", "", 0)
	d := s.data("Password changed")
	d.Notice = "Password changed. All provider sessions and refresh-token families were revoked. Sign in with your new password."
	s.render(w, 200, "message.html", d)
}
func (s *Server) editOwnProfile(w http.ResponseWriter, r *http.Request) {
	_, raw, ok := s.user(w, r, false, false)
	if !ok {
		return
	}
	if err := s.auth.EditOwnProfile(r.Context(), raw, r.PostForm.Get("display_name"), r.PostForm.Get("email"), auditInfo(w, r)); err != nil {
		s.failure(w, r, err)
		return
	}
	http.Redirect(w, r, "/account", http.StatusSeeOther)
}
func (s *Server) revokeSession(w http.ResponseWriter, r *http.Request) {
	admin := r.URL.Path == "/admin/sessions/revoke"
	sess, raw, ok := s.user(w, r, admin, !admin)
	if !ok {
		return
	}
	target := r.PostForm.Get("session_id")
	others := r.PostForm.Get("others") == "true"
	if err := s.auth.Store.RevokeSession(r.Context(), identity.Hash(raw), target, others, auditInfo(w, r)); err != nil {
		s.failure(w, r, err)
		return
	}
	if !others && target == sess.ID {
		s.setCookie(w, "session", "", 0)
		http.Redirect(w, r, "/login", 303)
		return
	}
	destination := "/account"
	if admin {
		destination = "/admin/?view=sessions"
	}
	http.Redirect(w, r, destination, 303)
}
func (s *Server) beginTOTP(w http.ResponseWriter, r *http.Request) {
	sess, raw, ok := s.user(w, r, false, false)
	if !ok {
		return
	}
	secret, uri, err := s.auth.BeginTOTP(r.Context(), raw, r.PostForm.Get("current_password"), auditInfo(w, r))
	if err != nil {
		s.failure(w, r, err)
		return
	}
	d := s.data("Enroll authenticator")
	d.Session = sess
	d.CSRF = s.auth.CSRF(raw, "session")
	d.Secret = secret
	d.URI = uri
	if png, err := qrcode.Encode(uri, qrcode.Medium, 256); err == nil {
		d.QRBase64 = base64.StdEncoding.EncodeToString(png)
	}
	s.render(w, 200, "mfa.html", d)
}
func (s *Server) confirmTOTP(w http.ResponseWriter, r *http.Request) {
	_, raw, ok := s.user(w, r, false, false)
	if !ok {
		return
	}
	codes, err := s.auth.ConfirmTOTP(r.Context(), raw, r.PostForm.Get("code"), auditInfo(w, r))
	if err != nil {
		s.failure(w, r, err)
		return
	}
	s.setCookie(w, "session", "", 0)
	d := s.data("Save your recovery codes")
	d.RecoveryCodes = codes
	s.render(w, 200, "mfa.html", d)
}
func (s *Server) removeTOTP(w http.ResponseWriter, r *http.Request) {
	_, raw, ok := s.user(w, r, false, false)
	if !ok {
		return
	}
	if err := s.auth.RemoveTOTP(r.Context(), raw, r.PostForm.Get("current_password"), auditInfo(w, r)); err != nil {
		s.failure(w, r, err)
		return
	}
	s.setCookie(w, "session", "", 0)
	d := s.data("Authenticator removed")
	d.Notice = "The authenticator and recovery codes were removed. All provider sessions and refresh-token families were revoked."
	s.render(w, 200, "message.html", d)
}
func (s *Server) regenerateRecoveryCodes(w http.ResponseWriter, r *http.Request) {
	sess, raw, ok := s.user(w, r, false, false)
	if !ok {
		return
	}
	codes, err := s.auth.RegenerateRecoveryCodes(r.Context(), raw, auditInfo(w, r))
	if err != nil {
		s.failure(w, r, err)
		return
	}
	d := s.data("Save your new recovery codes")
	d.Session = sess
	d.CSRF = s.auth.CSRF(raw, "session")
	d.RecoveryCodes = codes
	d.Notice = "Previous unused recovery codes no longer work. Save these new codes now; they are shown only once."
	s.render(w, 200, "mfa.html", d)
}
func (s *Server) admin(w http.ResponseWriter, r *http.Request) {
	sess, raw, ok := s.user(w, r, true, false)
	if !ok {
		return
	}
	d := s.data("Administration")
	d.Session = sess
	d.CSRF = s.auth.CSRF(raw, "session")
	d.View = r.URL.Query().Get("view")
	switch d.View {
	case "guide", "users", "roles", "groups", "permissions", "clients", "sessions", "keys", "audit":
	default:
		d.View = "guide"
	}
	// The static guide needs a live admin identity, not a full catalog scan.
	var data identity.AdminData
	selected := r.URL.Query().Get("user") != "" || r.URL.Query().Get("role") != "" || r.URL.Query().Get("group") != "" || r.URL.Query().Get("permission") != "" || r.URL.Query().Get("client") != ""
	if d.View != "guide" || selected {
		var err error
		data, err = s.auth.Store.AdminData(r.Context(), identity.Hash(raw))
		if err != nil {
			s.failure(w, r, err)
			return
		}
		d.Admin = data
	}
	if d.View == "clients" || r.URL.Query().Get("client") != "" {
		clients, e := s.oidc.AdminClients(r.Context(), raw)
		if e != nil {
			s.failure(w, r, e)
			return
		}
		d.OIDCClients = clients
		if id := r.URL.Query().Get("client"); id != "" {
			for i := range clients {
				if clients[i].ID == id {
					d.SelectedClient = &clients[i]
				}
			}
			if d.SelectedClient == nil {
				http.NotFound(w, r)
				return
			}
			d.View = "clients"
		}
	}
	if d.View == "keys" {
		keys, e := s.oidc.AdminSigningKeys(r.Context(), raw)
		if e != nil {
			s.failure(w, r, e)
			return
		}
		d.SigningKeys = keys
	}
	if id := r.URL.Query().Get("user"); id != "" {
		for i := range data.Users {
			if data.Users[i].ID == id {
				d.SelectedUser = &data.Users[i]
			}
		}
		if d.SelectedUser == nil {
			http.NotFound(w, r)
			return
		}
		d.View = "users"
	}
	if id := r.URL.Query().Get("role"); id != "" {
		for i := range data.Roles {
			if data.Roles[i].ID == id {
				d.SelectedRole = &data.Roles[i]
			}
		}
		if d.SelectedRole == nil {
			http.NotFound(w, r)
			return
		}
		d.View = "roles"
	}
	if id := r.URL.Query().Get("group"); id != "" {
		for i := range data.Groups {
			if data.Groups[i].ID == id {
				d.SelectedGroup = &data.Groups[i]
			}
		}
		if d.SelectedGroup == nil {
			http.NotFound(w, r)
			return
		}
		d.View = "groups"
	}
	if id := r.URL.Query().Get("permission"); id != "" {
		for i := range data.Permissions {
			if data.Permissions[i].ID == id {
				d.SelectedPermission = &data.Permissions[i]
			}
		}
		if d.SelectedPermission == nil {
			http.NotFound(w, r)
			return
		}
		d.View = "permissions"
	}
	if d.View == "permissions" || d.View == "roles" || d.View == "clients" {
		permissions := data.Permissions
		var selectedID string
		var checkedIDs []string
		if d.SelectedPermission != nil {
			selectedID = d.SelectedPermission.ID
		}
		if d.SelectedRole != nil {
			checkedIDs = d.SelectedRole.PermissionIDs
		}
		if d.SelectedClient != nil {
			checkedIDs = d.SelectedClient.PermissionIDs
		}
		if d.View == "clients" {
			permissions = make([]identity.Permission, 0, len(data.Permissions))
			for _, permission := range data.Permissions {
				if permission.Name != "system.admin" {
					permissions = append(permissions, permission)
				}
			}
		}
		d.PermissionTree = permissionTree(permissions, selectedID, checkedIDs)
	}
	if d.View == "guide" {
		s.startDocument(&d)
	}
	if time.Since(sess.AuthTime) > 10*time.Minute {
		d.Notice = "You can read administration. Sign in again before making changes; privileged writes require fresh authentication."
	}
	s.render(w, 200, "admin.html", d)
}
func profile(r *http.Request) identity.Profile {
	return identity.Profile{Username: r.PostForm.Get("username"), DisplayName: r.PostForm.Get("display_name"), Email: r.PostForm.Get("email")}
}
func editVersion(r *http.Request) (time.Time, error) {
	raw := strings.TrimSpace(r.PostForm.Get("expected_updated_at"))
	if raw == "" {
		return time.Time{}, identity.Invalid("missing record version; reload the page before saving")
	}
	v, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return time.Time{}, identity.Invalid("invalid record version; reload the page before saving")
	}
	return v.UTC(), nil
}
func (s *Server) createUser(w http.ResponseWriter, r *http.Request) {
	_, raw, ok := s.user(w, r, true, false)
	if !ok {
		return
	}
	err := s.auth.CreateUser(r.Context(), raw, profile(r), r.PostForm.Get("password"), r.PostForm["roles"], r.PostForm.Get("force_password_change") == "on", auditInfo(w, r))
	if err != nil {
		s.failure(w, r, err)
		return
	}
	http.Redirect(w, r, "/admin/?view=users", 303)
}
func (s *Server) editUser(w http.ResponseWriter, r *http.Request) {
	_, raw, ok := s.user(w, r, true, false)
	if !ok {
		return
	}
	version, err := editVersion(r)
	if err != nil {
		s.failure(w, r, err)
		return
	}
	edit := identity.UserEdit{ID: r.PostForm.Get("id"), Profile: profile(r), Enabled: r.PostForm.Get("enabled") == "on", ForcePasswordChange: r.PostForm.Get("force_password_change") == "on", VerifyEmail: r.PostForm.Get("email_verified") == "on", RoleIDs: r.PostForm["roles"], ExpectedUpdatedAt: version}
	if err := s.auth.EditUser(r.Context(), raw, edit, auditInfo(w, r)); err != nil {
		s.failure(w, r, err)
		return
	}
	http.Redirect(w, r, "/admin/?view=users", 303)
}
func (s *Server) resetPassword(w http.ResponseWriter, r *http.Request) {
	_, raw, ok := s.user(w, r, true, false)
	if !ok {
		return
	}
	err := s.auth.ResetPassword(r.Context(), raw, r.PostForm.Get("id"), r.PostForm.Get("password"), r.PostForm.Get("force_password_change") == "on", auditInfo(w, r))
	if err != nil {
		s.failure(w, r, err)
		return
	}
	http.Redirect(w, r, "/admin/?view=users", 303)
}
func (s *Server) resetUserMFA(w http.ResponseWriter, r *http.Request) {
	sess, raw, ok := s.user(w, r, true, false)
	if !ok {
		return
	}
	id := r.PostForm.Get("id")
	if err := s.auth.ResetMFA(r.Context(), raw, id, auditInfo(w, r)); err != nil {
		s.failure(w, r, err)
		return
	}
	if id == sess.User.ID {
		s.setCookie(w, "session", "", 0)
		d := s.data("Authenticator reset")
		d.Notice = "Your authenticator and recovery codes were reset. Your provider sessions and refresh grants were revoked; sign in again."
		s.render(w, 200, "message.html", d)
		return
	}
	http.Redirect(w, r, "/admin/?user="+id, http.StatusSeeOther)
}
func (s *Server) deleteUser(w http.ResponseWriter, r *http.Request) {
	sess, raw, ok := s.user(w, r, true, false)
	if !ok {
		return
	}
	id := r.PostForm.Get("id")
	if r.PostForm.Get("confirm") != "delete" {
		s.failure(w, r, identity.Invalid("type delete to confirm user deletion"))
		return
	}
	if err := s.auth.DeleteUser(r.Context(), raw, id, auditInfo(w, r)); err != nil {
		s.failure(w, r, err)
		return
	}
	if id == sess.User.ID {
		s.setCookie(w, "session", "", 0)
		d := s.data("Account deleted")
		d.Notice = "Your local authd account was deleted and all credentials and provider sessions were revoked."
		s.render(w, 200, "message.html", d)
		return
	}
	http.Redirect(w, r, "/admin/?view=users", http.StatusSeeOther)
}
func (s *Server) saveRole(w http.ResponseWriter, r *http.Request) {
	_, raw, ok := s.user(w, r, true, false)
	if !ok {
		return
	}
	var version time.Time
	var err error
	if r.PostForm.Get("id") != "" {
		version, err = editVersion(r)
		if err != nil {
			s.failure(w, r, err)
			return
		}
	}
	err = s.auth.SaveRole(r.Context(), raw, identity.RoleEdit{ID: r.PostForm.Get("id"), Name: r.PostForm.Get("name"), Description: r.PostForm.Get("description"), PermissionIDs: r.PostForm["permissions"], ExpectedUpdatedAt: version}, auditInfo(w, r))
	if err != nil {
		s.failure(w, r, err)
		return
	}
	http.Redirect(w, r, "/admin/?view=roles", 303)
}
func (s *Server) deleteRole(w http.ResponseWriter, r *http.Request) {
	_, raw, ok := s.user(w, r, true, false)
	if !ok {
		return
	}
	if r.PostForm.Get("confirm") != "delete" {
		s.failure(w, r, identity.Invalid("type delete to confirm role deletion"))
		return
	}
	if err := s.auth.DeleteRole(r.Context(), raw, r.PostForm.Get("id"), auditInfo(w, r)); err != nil {
		s.failure(w, r, err)
		return
	}
	http.Redirect(w, r, "/admin/?view=roles", http.StatusSeeOther)
}
func (s *Server) saveGroup(w http.ResponseWriter, r *http.Request) {
	_, raw, ok := s.user(w, r, true, false)
	if !ok {
		return
	}
	var version time.Time
	var err error
	if r.PostForm.Get("id") != "" {
		version, err = editVersion(r)
		if err != nil {
			s.failure(w, r, err)
			return
		}
	}
	err = s.auth.SaveGroup(r.Context(), raw, identity.GroupEdit{ID: r.PostForm.Get("id"), Name: r.PostForm.Get("name"), Description: r.PostForm.Get("description"), RoleIDs: r.PostForm["roles"], UserIDs: r.PostForm["users"], ExpectedUpdatedAt: version}, auditInfo(w, r))
	if err != nil {
		s.failure(w, r, err)
		return
	}
	http.Redirect(w, r, "/admin/?view=groups", http.StatusSeeOther)
}
func (s *Server) deleteGroup(w http.ResponseWriter, r *http.Request) {
	_, raw, ok := s.user(w, r, true, false)
	if !ok {
		return
	}
	if r.PostForm.Get("confirm") != "delete" {
		s.failure(w, r, identity.Invalid("type delete to confirm group deletion"))
		return
	}
	if err := s.auth.DeleteGroup(r.Context(), raw, r.PostForm.Get("id"), auditInfo(w, r)); err != nil {
		s.failure(w, r, err)
		return
	}
	http.Redirect(w, r, "/admin/?view=groups", http.StatusSeeOther)
}
func splitLines(raw string) []string {
	var out []string
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}
func clientEdit(r *http.Request) (oidc.ClientEdit, error) {
	ttl, err := strconv.Atoi(strings.TrimSpace(r.PostForm.Get("access_token_ttl")))
	if err != nil {
		return oidc.ClientEdit{}, identity.Invalid("access token lifetime must be seconds")
	}
	var version time.Time
	if r.PostForm.Get("id") != "" {
		version, err = editVersion(r)
		if err != nil {
			return oidc.ClientEdit{}, err
		}
	}
	return oidc.ClientEdit{ID: r.PostForm.Get("id"), ClientID: r.PostForm.Get("client_id"), Name: r.PostForm.Get("name"), Type: r.PostForm.Get("client_type"), Enabled: r.PostForm.Get("enabled") == "on", RequireMFA: r.PostForm.Get("require_mfa") == "on", RefreshTokensEnabled: r.PostForm.Get("refresh_tokens_enabled") == "on", AccessTokenTTL: time.Duration(ttl) * time.Second, RedirectURIs: splitLines(r.PostForm.Get("redirect_uris")), LogoutURIs: splitLines(r.PostForm.Get("logout_uris")), IdentityScopes: r.PostForm["identity_scopes"], PermissionIDs: r.PostForm["permissions"], ExpectedUpdatedAt: version}, nil
}
func (s *Server) createClient(w http.ResponseWriter, r *http.Request) {
	_, raw, ok := s.user(w, r, true, false)
	if !ok {
		return
	}
	edit, err := clientEdit(r)
	if err != nil {
		s.failure(w, r, err)
		return
	}
	client, secret, err := s.oidc.CreateClient(r.Context(), raw, edit, auditInfo(w, r))
	if err != nil {
		s.failure(w, r, err)
		return
	}
	if secret != "" {
		d := s.data("Save the client secret")
		d.Secret = secret
		d.SelectedClient = &client
		d.Notice = "Client " + client.ClientID + " was created. This secret is shown only in this response."
		s.render(w, 200, "client_secret.html", d)
		return
	}
	http.Redirect(w, r, "/admin/?view=clients", 303)
}
func (s *Server) saveClient(w http.ResponseWriter, r *http.Request) {
	_, raw, ok := s.user(w, r, true, false)
	if !ok {
		return
	}
	edit, err := clientEdit(r)
	if err != nil {
		s.failure(w, r, err)
		return
	}
	if err = s.oidc.UpdateClient(r.Context(), raw, edit, auditInfo(w, r)); err != nil {
		s.failure(w, r, err)
		return
	}
	http.Redirect(w, r, "/admin/?view=clients", 303)
}
func (s *Server) rotateClientSecret(w http.ResponseWriter, r *http.Request) {
	_, raw, ok := s.user(w, r, true, false)
	if !ok {
		return
	}
	secret, err := s.oidc.RotateClientSecret(r.Context(), raw, r.PostForm.Get("id"), auditInfo(w, r))
	if err != nil {
		s.failure(w, r, err)
		return
	}
	d := s.data("Save the new client secret")
	d.Secret = secret
	d.Notice = "The old client secret no longer works. This new secret is shown only in this response."
	s.render(w, 200, "client_secret.html", d)
}

func (s *Server) deleteClient(w http.ResponseWriter, r *http.Request) {
	_, raw, ok := s.user(w, r, true, false)
	if !ok {
		return
	}
	if r.PostForm.Get("confirm") != "delete" {
		s.failure(w, r, identity.Invalid("type delete to confirm client deletion"))
		return
	}
	if err := s.oidc.DeleteClient(r.Context(), raw, r.PostForm.Get("id"), auditInfo(w, r)); err != nil {
		s.failure(w, r, err)
		return
	}
	http.Redirect(w, r, "/admin/?view=clients", http.StatusSeeOther)
}

func (s *Server) createPermission(w http.ResponseWriter, r *http.Request) {
	_, raw, ok := s.user(w, r, true, false)
	if !ok {
		return
	}
	if err := s.auth.CreatePermission(r.Context(), raw, r.PostForm.Get("name"), r.PostForm.Get("description"), auditInfo(w, r)); err != nil {
		s.failure(w, r, err)
		return
	}
	http.Redirect(w, r, "/admin/?view=permissions", 303)
}
func (s *Server) savePermission(w http.ResponseWriter, r *http.Request) {
	_, raw, ok := s.user(w, r, true, false)
	if !ok {
		return
	}
	version, err := editVersion(r)
	if err != nil {
		s.failure(w, r, err)
		return
	}
	edit := identity.PermissionEdit{ID: r.PostForm.Get("id"), Name: r.PostForm.Get("name"), Description: r.PostForm.Get("description"), ExpectedUpdatedAt: version}
	if err := s.auth.SavePermission(r.Context(), raw, edit, auditInfo(w, r)); err != nil {
		s.failure(w, r, err)
		return
	}
	http.Redirect(w, r, "/admin/?view=permissions", http.StatusSeeOther)
}
func (s *Server) deletePermission(w http.ResponseWriter, r *http.Request) {
	_, raw, ok := s.user(w, r, true, false)
	if !ok {
		return
	}
	if r.PostForm.Get("confirm") != "delete" {
		s.failure(w, r, identity.Invalid("type delete to confirm permission deletion"))
		return
	}
	if err := s.auth.DeletePermission(r.Context(), raw, r.PostForm.Get("id"), auditInfo(w, r)); err != nil {
		s.failure(w, r, err)
		return
	}
	http.Redirect(w, r, "/admin/?view=permissions", http.StatusSeeOther)
}
func (s *Server) rotateSigningKey(w http.ResponseWriter, r *http.Request) {
	_, raw, ok := s.user(w, r, true, false)
	if !ok {
		return
	}
	if _, err := s.oidc.RotateSigningKey(r.Context(), raw, auditInfo(w, r)); err != nil {
		s.failure(w, r, err)
		return
	}
	http.Redirect(w, r, "/admin/?view=keys", http.StatusSeeOther)
}
