// Package manual embeds the documentation shipped with this exact binary.
// Keeping this file at the module root lets Go embed the original Markdown;
// there is no generated or copied second version of the operator guide.
package manual

import (
	"embed"
	"sync"

	"github.com/yellowman/authd/internal/docsite"
)

// Include release documentation only, never a checkout, config directory or
// administrator-selected path. docs contains Markdown and retained test evidence.
//
//go:embed *.md docs deploy/openbsd/README.md deploy/systemd/README.md deploy/postgresql/README.md
var sources embed.FS

var loadOnce = sync.OnceValues(func() (*docsite.Library, error) {
	return docsite.New(sources)
})

// Load renders and indexes the finite release catalog once. It performs no disk,
// database or network IO. Authentication belongs to the HTTP layer on every read.
func Load() (*docsite.Library, error) { return loadOnce() }
