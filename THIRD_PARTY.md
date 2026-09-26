# Third-party code

## Markdown parser

The documentation portal uses the `rsc.io/markdown` parser at
`v0.0.0-20240306144322-0bf8f97ee8ef`, the source snapshot distributed with Go
1.23.2 under `src/cmd/vendor/rsc.io/markdown`. Its unmodified Go source is retained
in `internal/thirdparty/markdown`, together with its BSD-3-Clause license. Source:
https://github.com/rsc/markdown/tree/0bf8f97ee8ef

This is one isolated parser using the existing `golang.org/x/text/cases`
dependency for Unicode reference-label folding, not a frontend framework or an
additional service. Vendoring the parser keeps the documentation available in
the same binary without a CDN, package download, or Markdown build step. Its large
entity/emoji lookup tables are upstream data, not additional authd features.
Vendoring the parser did not itself add a module dependency.

Only compiled, release-owned documentation is parsed. This is **not** a Markdown
upload or arbitrary-file rendering endpoint. `internal/docsite` renders the
parsed structure through its own small HTML allow-list: it never calls the
parser's raw HTML renderer. HTML is escaped, links are validated and local
Markdown links are resolved against the embedded catalog. Images are rendered as
text links, not automatically fetched. Every installed document is read-only.

The inventory in `internal/thirdparty/markdown/SHA256SUMS` records the source
snapshot. Update it deliberately when updating the parser; do not patch the
vendored grammar to add product behavior. Renderer safety and documentation
coverage are tested in `internal/docsite` and the root `manual` package.

## Authenticator QR encoder

The enrollment page uses `github.com/skip2/go-qrcode` at
`v0.0.0-20200617195104-da1b6568686e` (MIT license; copy in
`internal/thirdparty/licenses/go-qrcode-LICENSE`). The Go standard library has
no QR encoder; implementing its matrix placement and error correction locally
would be less reliable. This package replaces only QR symbol encoding, not
TOTP generation, verification, encryption, or authorization.

The latest published module snapshot is from 2020 and upstream maintenance is
infrequent. The input is the bounded, server-generated provisioning URI, not
arbitrary uploaded content. Encoding happens in-process; the PNG is embedded
in the existing no-store enrollment response, with no external QR service or
additional secret-bearing URL. Manual key entry remains available.
