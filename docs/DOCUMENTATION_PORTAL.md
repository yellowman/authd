# Documentation portal

Administration → Start here begins with **Adding an app to authd**, a generic
workflow rendered from `docs/ADDING_AN_APP.md`. **Documentation** opens the
searchable release-document catalog. Application-specific instructions are
separate profiles, not the landing-page workflow.

## Reading documentation

Select a document to read its rendered Markdown, use its **On this page** heading
links, or select **Markdown source** for the original file. Search matches document
names, descriptions and source text. Relative Markdown links stay inside the
portal and retain heading fragments. Linked, embedded test logs are available as
plain-text evidence. Everything works without JavaScript or a network connection
to a documentation host.

All product Markdown at the repository root, under `docs/`, and the three native
PostgreSQL/OpenBSD/systemd README files is compiled into the binary from the actual
source files. Tests require those files to appear in the catalog. This includes
the spec, design language, operator/deployment guides, release notes, validation,
application profiles and developer rules. Vendored parser implementation files,
`.git`, environment files, credentials and arbitrary installed files are not
served. The source checkout is not needed on the installed server.

## Editing documentation

Edit the original `.md` file, then build/install/restart authd. The binary is a
release snapshot, not a live wiki. No duplicated HTML help article or generated
copy has to be edited. New root/docs Markdown files are automatically embedded
and listed; a short description/category can be added in
`internal/docsite/library.go`. Native deployment README paths are explicit
in `manual.go`. Adding another documentation root requires a deliberate embed
rule and a catalog coverage test.

The original Markdown files are also shipped by the native installer. There is
no new database table, migration, document upload endpoint, remote fetcher or
runtime document-directory setting.

## Rendering and security

Every catalog, rendered document and raw-source/evidence request requires a live
session with `system.admin`, like the rest of administration. These are not public
operational pages. Responses remain `no-store` with the existing security headers.

The portal parses the finite embedded files once and caches immutable rendered
pages. Reading a page does not scan the user/role/client catalogs. It does not
read the host filesystem or fetch a requested URL. The request can select only
an exact embedded catalog name; traversal and noncatalog names return 404.

The parser is an isolated, unmodified `rsc.io/markdown` snapshot used by the Go
toolchain; see [Third-party code](../THIRD_PARTY.md). authd's renderer uses a fixed
HTML element set and escapes raw HTML. Script/data/file URLs and scheme-relative
links are refused. External links require an ordinary explicit click. Images are
rendered as descriptive links rather than fetched into the administrator's page.
Fenced code, reference links, nested lists, task lists, blockquotes and tables are
supported. This is not an unrestricted HTML or Markdown application.

## Navigation

The left rail uses local inline outline SVGs with accessible text names. Normal,
hover and selected links have no shaded backgrounds or button shadows. Selection
uses a narrow edge indicator and `aria-current`; keyboard focus retains its
visible outline. The rail can scroll on short viewports without losing the
account link. See [Design language](../DESIGN_LANGUAGE.md).
