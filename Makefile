.PHONY: deps fmt fmt-check test race vet build verify integration offline-check run dev-db dev-db-down

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

integration:
	@test "$$AUTHD_TEST_DISPOSABLE" = "1" || { echo "AUTHD_TEST_DISPOSABLE=1 required" >&2; exit 1; }
	@test -n "$$AUTHD_TEST_DATABASE_URL" || { echo "AUTHD_TEST_DATABASE_URL required" >&2; exit 1; }
	go test -race -count=1 -tags=integration ./internal/db

offline-check:
	./scripts/check-offline.sh

run:
	go run ./cmd/authd

dev-db:
	docker compose -f compose.dev.yml up -d postgres

dev-db-down:
	docker compose -f compose.dev.yml down
