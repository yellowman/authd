.PHONY: fmt test vet build verify run dev-db dev-db-down

fmt:
	gofmt -w $$(find cmd internal -type f -name '*.go' -print)

test:
	go test ./...

vet:
	go vet ./...

build:
	mkdir -p bin
	go build -trimpath -o bin/authd ./cmd/authd

verify: fmt test vet build

run:
	go run ./cmd/authd

dev-db:
	docker compose -f compose.dev.yml up -d postgres

dev-db-down:
	docker compose -f compose.dev.yml down
