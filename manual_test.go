package manual

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yellowman/authd/internal/docsite"
)

func TestEveryProductMarkdownFileIsEmbeddedAndRenderable(t *testing.T) {
	library, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	err = filepath.WalkDir(".", func(name string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if name == ".git" || name == "internal" || name == "bin" {
				return filepath.SkipDir
			}
			return nil
		}
		name = filepath.ToSlash(name)
		if !strings.HasSuffix(name, ".md") {
			return nil
		}
		wanted := !strings.Contains(name, "/") || strings.HasPrefix(name, "docs/") || name == "deploy/openbsd/README.md" || name == "deploy/systemd/README.md" || name == "deploy/postgresql/README.md"
		if !wanted {
			return nil
		}
		count++
		b, err := os.ReadFile(name)
		if err != nil {
			return err
		}
		doc, ok := library.Document(name)
		if !ok || doc.Source != string(b) || doc.Body == "" {
			t.Errorf("not embedded/rendered from original source: %s", name)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if count != library.Count() {
		t.Errorf("disk docs=%d, rendered catalog=%d", count, library.Count())
	}
	start, ok := library.Document(docsite.StartDocument)
	if !ok || !strings.Contains(start.Source, "Adding an app to authd") {
		t.Fatal("missing generic starting guide")
	}
	if strings.Contains(strings.ToLower(start.Source), "bdc") {
		t.Fatal("generic landing workflow must not be an app-specific profile")
	}
	for _, name := range []string{".env.example", "go.mod", ".git/config", "internal/web/server.go", "master.key", "../DEPLOYMENT.md"} {
		if _, ok := library.Source(name); ok {
			t.Errorf("published non-documentation file %q", name)
		}
	}
}
