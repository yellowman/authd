.PHONY: deps fmt fmt-check test race vet build verify verify-openbsd integration integration-openbsd offline-check run migrate dev-db dev-db-down

deps:
	go mod tidy
	go mod verify

fmt:
	gofmt -w $$(find cmd internal -type f -name '*.go' -print)

fmt-check:
	@test -z "$$(gofmt -l $$(find cmd internal -type f -name '*.go' -print))" || { echo "Run make fmt" >&2; exit 1; }

test:
	go test ./...

race:
	go test -race ./...

vet:
	go vet ./...

build:
	mkdir -p bin
	go build -trimpath -o bin/authd ./cmd/authd

# Requires real dependencies and a marked disposable PostgreSQL database.
# Missing prerequisites are failures, not successful skipped checks.
verify: fmt-check test race vet build integration

# Go does not support -race on OpenBSD/amd64. This is the native OpenBSD gate;
# release qualification still requires `make race` on a race-supported platform.
verify-openbsd: fmt-check test vet build integration-openbsd

integration:
	@test "$$AUTHD_TEST_DISPOSABLE" = "1" || { echo "AUTHD_TEST_DISPOSABLE=1 required" >&2; exit 1; }
	@test -n "$$AUTHD_TEST_DATABASE_URL" || { echo "AUTHD_TEST_DATABASE_URL required" >&2; exit 1; }
	go test -race -count=1 -tags=integration ./internal/db

integration-openbsd:
	@test "$$AUTHD_TEST_DISPOSABLE" = "1" || { echo "AUTHD_TEST_DISPOSABLE=1 required" >&2; exit 1; }
	@test -n "$$AUTHD_TEST_DATABASE_URL" || { echo "AUTHD_TEST_DATABASE_URL required" >&2; exit 1; }
	go test -count=1 -tags=integration ./internal/db

offline-check:
	./scripts/check-offline.sh

run:
	go run ./cmd/authd

migrate:
	go run ./cmd/authd migrate

dev-db:
	docker compose -f compose.dev.yml up -d postgres

dev-db-down:
	docker compose -f compose.dev.yml down
