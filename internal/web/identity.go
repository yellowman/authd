package web

import (
	"errors"
	"net/http"
	"time"

	"github.com/yellowman/authd/internal/identity"
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
	var err error
	d.CSRF, err = s.browserCSRF(w, r)
	if err != nil {
		s.failure(w, r, err)
		return
	}
	d.ReturnTo = safeReturn(r.URL.Query().Get("return_to"))
	s.render(w, 200, "login.html", d)
}
func (s *Server) loginPost(w http.ResponseWriter, r *http.Request) {
	if err := s.anonForm(w, r); err != nil {
		s.failure(w, r, err)
		return
	}
	raw, err := s.auth.Authenticate(r.Context(), r.PostForm.Get("username"), r.PostForm.Get("password"), r.PostForm.Get("factor"), r.UserAgent(), auditInfo(w, r))
	if err != nil {
		if errors.Is(err, identity.ErrCredentials) {
			d := s.data("Sign in")
			d.CSRF = s.auth.CSRF(s.cookie(r, "browser"), "browser")
			d.ReturnTo = safeReturn(r.PostForm.Get("return_to"))
			d.Error = "Invalid credentials. Check your password and authenticator or recovery code."
			s.render(w, 401, "login.html", d)
		} else {
			s.failure(w, r, err)
		}
		return
	}
	// Fresh session token, never an upgrade of the pre-auth browser cookie.
	// Retire this browser's old authenticated session after a successful new login.
	if old := s.cookie(r, "session"); old != "" {
		if previous, e := s.auth.Session(r.Context(), old); e == nil {
			_ = s.auth.Store.RevokeSession(r.Context(), identity.Hash(old), previous.ID, false, auditInfo(w, r))
		}
	}
	s.setCookie(w, "session", raw, s.cfg.SessionAbsoluteTTL)
	s.setCookie(w, "browser", "", 0)
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
func (s *Server) admin(w http.ResponseWriter, r *http.Request) {
	sess, raw, ok := s.user(w, r, true, false)
	if !ok {
		return
	}
	data, err := s.auth.Store.AdminData(r.Context(), identity.Hash(raw))
	if err != nil {
		s.failure(w, r, err)
		return
	}
	d := s.data("Administration")
	d.Session = sess
	d.Admin = data
	d.CSRF = s.auth.CSRF(raw, "session")
	d.View = r.URL.Query().Get("view")
	switch d.View {
	case "users", "roles", "permissions", "sessions", "audit":
	default:
		d.View = "users"
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
	if time.Since(sess.AuthTime) > 10*time.Minute {
		d.Notice = "You can read administration. Sign in again before making changes; privileged writes require fresh authentication."
	}
	s.render(w, 200, "admin.html", d)
}
func profile(r *http.Request) identity.Profile {
	return identity.Profile{Username: r.PostForm.Get("username"), DisplayName: r.PostForm.Get("display_name"), Email: r.PostForm.Get("email")}
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
	edit := identity.UserEdit{ID: r.PostForm.Get("id"), Profile: profile(r), Enabled: r.PostForm.Get("enabled") == "on", ForcePasswordChange: r.PostForm.Get("force_password_change") == "on", VerifyEmail: r.PostForm.Get("email_verified") == "on", RoleIDs: r.PostForm["roles"]}
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
func (s *Server) saveRole(w http.ResponseWriter, r *http.Request) {
	_, raw, ok := s.user(w, r, true, false)
	if !ok {
		return
	}
	err := s.auth.SaveRole(r.Context(), raw, identity.RoleEdit{ID: r.PostForm.Get("id"), Name: r.PostForm.Get("name"), Description: r.PostForm.Get("description"), PermissionIDs: r.PostForm["permissions"]}, auditInfo(w, r))
	if err != nil {
		s.failure(w, r, err)
		return
	}
	http.Redirect(w, r, "/admin/?view=roles", 303)
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
