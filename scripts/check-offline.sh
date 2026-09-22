#!/bin/sh
# This is a deliberately PARTIAL check, not an alternate production build.
# It changes no repository module files, uses no module replacements, and tests
# the real stdlib-only packages. Argon2 and pgx need the normal release gate.
set -eu
cd "$(dirname "$0")/.."
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM
printf 'module github.com/yellowman/authd\n\ngo 1.23.0\n' > "$work/offline.mod"
export GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOWORK=off
packages="./internal/config ./internal/cryptoutil ./internal/identity ./internal/db ./internal/oidc ./internal/protocol ./internal/requestid ./internal/totp ./internal/web"
go test -race -count=1 -modfile="$work/offline.mod" $packages
go vet -modfile="$work/offline.mod" $packages
go test -race -count=1 -modfile="$work/offline.mod" internal/password/encoding.go internal/password/encoding_test.go
# Typecheck the real SQL integration test body, without the separate pgx driver
# registration test file. This does NOT run it or prove SQL behavior.
go test -run '^$' -modfile="$work/offline.mod" internal/db/integration_test.go internal/db/oidc_integration_test.go
printf '\nPARTIAL CHECK ONLY: pgx, Argon2, full executable, PostgreSQL transactions and external OIDC-client interoperability were not exercised. Run make deps and make verify in the supported environment.\n'
