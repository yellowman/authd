package web

import (
	"bytes"
	"image"
	_ "image/jpeg"
	"image/png"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/yellowman/authd/internal/identity"
)

func (s *Server) loadBranding(r *http.Request, d *pageData) error {
	d.Branding.Name = "authd"
	store, ok := s.auth.Store.(identity.BrandingStore)
	if !ok {
		return nil
	}
	b, err := store.Branding(r.Context())
	if err != nil {
		return err
	}
	d.Branding = b
	return nil
}

func (s *Server) loginLogo(w http.ResponseWriter, r *http.Request) {
	d := s.data("")
	if err := s.loadBranding(r, &d); err != nil {
		http.Error(w, "Logo unavailable", 503)
		return
	}
	if len(d.Branding.Logo) == 0 {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(d.Branding.Logo)
}

func (s *Server) branding(w http.ResponseWriter, r *http.Request) {
	sess, raw, ok := s.user(w, r, true, false)
	if !ok {
		return
	}
	d := s.data("Login appearance")
	d.View = "branding"
	d.Session = sess
	d.CSRF = s.auth.CSRF(raw, "session")
	if err := s.loadBranding(r, &d); err != nil {
		s.failure(w, r, err)
		return
	}
	if r.URL.Query().Get("saved") == "1" {
		d.Notice = "Login appearance saved."
	}
	s.render(w, 200, "admin.html", d)
}

// Decode/re-encode raster uploads to reject active content and strip metadata.
// No external image URLs or SVGs are served on the sign-in origin.
func normalizeLogo(raw []byte) ([]byte, error) {
	if len(raw) > 256<<10 {
		return nil, identity.Invalid("Logo must be at most 256 KiB.")
	}
	config, format, err := image.DecodeConfig(bytes.NewReader(raw))
	if err != nil || (format != "png" && format != "jpeg") || config.Width < 1 || config.Height < 1 || config.Width > 2048 || config.Height > 2048 {
		return nil, identity.Invalid("Use a PNG or JPEG logo no larger than 2048 × 2048 pixels.")
	}
	img, _, err := image.Decode(bytes.NewReader(raw))
	if err != nil {
		return nil, identity.Invalid("Invalid logo image.")
	}
	var out bytes.Buffer
	if err = png.Encode(&out, img); err != nil {
		return nil, err
	}
	if out.Len() > 256<<10 {
		return nil, identity.Invalid("Processed logo exceeds 256 KiB; use a smaller image.")
	}
	return out.Bytes(), nil
}

func (s *Server) saveBranding(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if r.MultipartForm != nil {
			_ = r.MultipartForm.RemoveAll()
		}
	}()
	_, raw, ok := s.user(w, r, true, false)
	if !ok {
		return
	}
	store, ok := s.auth.Store.(identity.BrandingStore)
	if !ok {
		s.failure(w, r, identity.ErrUnavailable)
		return
	}
	edit := identity.Branding{Name: strings.TrimSpace(r.PostForm.Get("name"))}
	var err error
	edit.UpdatedAt, err = time.Parse(time.RFC3339Nano, r.PostForm.Get("expected_updated_at"))
	if err != nil {
		s.failure(w, r, identity.Invalid("Reload the appearance form before saving."))
		return
	}
	if err = identity.ValidateBrandName(edit.Name); err != nil {
		s.failure(w, r, err)
		return
	}
	replace, remove := false, r.PostForm.Get("remove_logo") == "true"
	if r.MultipartForm != nil {
		for name, files := range r.MultipartForm.File {
			if name != "logo" || len(files) > 1 {
				s.failure(w, r, identity.Invalid("Upload one logo."))
				return
			}
		}
	}
	file, _, err := r.FormFile("logo")
	if err == nil {
		defer file.Close()
		replace = true
		contents, e := io.ReadAll(io.LimitReader(file, (256<<10)+1))
		if e == nil {
			edit.Logo, e = normalizeLogo(contents)
		}
		if e != nil {
			s.failure(w, r, e)
			return
		}
	} else if err != http.ErrMissingFile {
		s.failure(w, r, identity.Invalid("Invalid logo upload."))
		return
	}
	if replace && remove {
		s.failure(w, r, identity.Invalid("Choose a replacement logo or remove the current logo, not both."))
		return
	}
	if err = store.SaveBranding(r.Context(), identity.Hash(raw), edit, replace, remove, auditInfo(w, r)); err != nil {
		s.failure(w, r, err)
		return
	}
	http.Redirect(w, r, "/admin/branding?saved=1", http.StatusSeeOther)
}
