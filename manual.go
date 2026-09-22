// Package manual embeds the documentation shipped with this exact binary.
// Keeping this file at the module root lets Go embed the original Markdown;
// there is no generated or copied second version of the operator guide.
package manual

import (
	"embed"
	"sync"

	"github.com/yellowman/authd/internal/docsite"
)

// Include release documentation roots, never a runtime config directory or an
// administrator-selected path. docsite discovers Markdown recursively; deploy
// has no per-platform README registry. Non-document files are not published.
// docs also contains explicitly shipped, plain-text validation evidence.
//
//go:embed *.md docs deploy
var sources embed.FS

var loadOnce = sync.OnceValues(func() (*docsite.Library, error) {
	return docsite.New(sources)
})

// Load renders and indexes the finite release catalog once. It performs no disk,
// database or network IO. Authentication belongs to the HTTP layer on every read.
func Load() (*docsite.Library, error) { return loadOnce() }
