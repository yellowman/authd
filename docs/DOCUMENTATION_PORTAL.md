# Documentation portal

**Start here** renders the generic [Adding an app to authd](ADDING_AN_APP.md)
workflow. **Documentation** lists the Markdown files shipped with this release,
not a registry of known applications or a hand-maintained menu.

## Directory listing

The index is discovered from the embedded documentation tree. Each group names an
actual directory (`./`, `docs/`, `deploy/openbsd/`, and any other directory that
contains Markdown). Each row shows the filename, the first Markdown heading when
present, and the full relative path. A file without a heading uses its filename.
Directories and filenames are sorted alphabetically; there are no pinned files,
per-application links, named categories or filename-to-description mappings.

Product Markdown comes from root `*.md` files and recursive `docs/` and `deploy/`
directories. New subdirectories are discovered too; no Go filename list needs
editing. Linked validation logs under `docs/` remain readable as plain text, but only Markdown
files become index rows. Empty directories and directories with only logs do not
get invented document entries.

The built-in interface and client connection help are application-neutral.
Application names and client settings displayed by forms come from their saved
records, not client-ID-specific branches. A named application report, when present
in the documentation tree, is an ordinary source document, not special UI. Historical
validation evidence is not rewritten or filtered according to an application's name.

## Reading and editing

Select a filename to read its Markdown, follow **On this page** heading links, or
select **Markdown source** for the original file. Search matches filenames, paths,
headings and source text. Relative document links remain inside the portal with
their heading fragments. Reading and searching need no JavaScript or remote docs
service.

Edit, add, rename or remove the original Markdown file, then rebuild, install and
restart authd. The next binary's index reflects that directory tree automatically.
There is no separate HTML guide, title catalog or metadata registration to update.
The existing Start here entry deliberately uses `docs/ADDING_AN_APP.md`; keep that
landing document at its stable path. The documentation index does not give it a
special ordering rule.

This is a build-time release snapshot, not a live directory watcher. Editing the
installed `/usr/local/share/doc/authd/` copy does not change the running binary.
The source checkout is not required on the installed server. No runtime document
path setting, upload endpoint, database table or migration is added.

## Rendering and security

Every directory index, rendered page and raw-source/evidence request requires a
live session with `system.admin`. Responses retain `no-store` and the existing
security headers. Documentation reads do not scan users, roles or clients.

The finite embedded tree is parsed once and rendered into an immutable catalog.
Requests select exact discovered names, never host filesystem paths or remote
URLs. Traversal and missing names return 404. Environment files, credentials,
source code, SQL, service files, deployment JSON/text and repository internals are
not served. Document
symlinks, invalid UTF-8 and oversized inputs are refused.

The parser is an isolated, unmodified `rsc.io/markdown` snapshot used by the Go
toolchain; see [Third-party code](../THIRD_PARTY.md). The renderer escapes raw HTML,
restricts links, and never fetches remote images. Fenced code, reference links,
lists, blockquotes, tables and heading navigation remain supported. File-derived
titles and paths receive the same HTML escaping as other template data.

## Navigation

The left rail uses local inline outline SVGs with accessible text names. Normal,
hover and selected links remain transparent and shadow-free. Selection uses a
narrow edge line and `aria-current`; keyboard focus remains visible. Short
viewports can scroll the rail. See [Design language](../DESIGN_LANGUAGE.md).
