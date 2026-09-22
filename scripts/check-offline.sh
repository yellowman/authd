#!/bin/sh
# This is a deliberately PARTIAL check, not an alternate production build.
# It changes no repository module files, uses no pgx/Argon2 substitutes, and tests
# the real component packages and bundled upstream Markdown parser. The parser
# uses x/text; its actual source/version is explicit below. Argon2 and pgx need
# the normal release gate.
set -eu
cd "$(dirname "$0")/.."
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM
printf 'module github.com/yellowman/authd\n\ngo 1.23.0\n' > "$work/offline.mod"
# The portal parser uses the already-pinned x/text module. A deliberately
# supplied LOCAL REAL source snapshot can be used for this partial developer
# check. Its version is not silently presented as the production dependency.
if [ -n "${AUTHD_OFFLINE_XTEXT_DIR:-}" ]; then
  case "$AUTHD_OFFLINE_XTEXT_DIR" in /*) ;; *) echo "AUTHD_OFFLINE_XTEXT_DIR must be absolute" >&2; exit 1;; esac
  test -f "$AUTHD_OFFLINE_XTEXT_DIR/go.mod" || { echo "real x/text source go.mod required" >&2; exit 1; }
  printf '\nrequire golang.org/x/text v0.42.0\nreplace golang.org/x/text => %s\n' "$AUTHD_OFFLINE_XTEXT_DIR" >> "$work/offline.mod"
  printf 'PARTIAL DEPENDENCY CHECK: x/text from explicitly supplied source %s; not production v0.42.0 qualification.\n' "$AUTHD_OFFLINE_XTEXT_DIR"
else
  printf '\nrequire golang.org/x/text v0.42.0\n' >> "$work/offline.mod"
fi
export GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOWORK=off
packages=". ./internal/docsite ./internal/config ./internal/cryptoutil ./internal/identity ./internal/listener ./internal/db ./internal/oidc ./internal/protocol ./internal/requestid ./internal/totp ./internal/web"
go test -race -count=1 -modfile="$work/offline.mod" $packages
go vet -modfile="$work/offline.mod" $packages
go test -race -count=1 -modfile="$work/offline.mod" internal/password/encoding.go internal/password/encoding_test.go
# Typecheck the real SQL integration test body, without the separate pgx driver
# registration test file. This does NOT run it or prove SQL behavior.
go test -run '^$' -modfile="$work/offline.mod" internal/db/integration_test.go internal/db/oidc_integration_test.go
printf '\nPARTIAL CHECK ONLY: pgx, Argon2, full executable, PostgreSQL transactions and external OIDC-client interoperability were not exercised. Run make deps and make verify in the supported environment.\n'
