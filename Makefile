.PHONY: deps fmt fmt-check test race vet build verify verify-openbsd integration integration-openbsd openbsd-deploy-check offline-check run migrate dev-db dev-db-down install-openbsd install-openbsd-user install-openbsd-files install-openbsd-config install-openbsd-service enable start restart status stop

DESTDIR?=
PREFIX?=/usr/local
BINDIR?=${PREFIX}/bin
SHAREDIR?=${PREFIX}/share/authd
DOCDIR?=${PREFIX}/share/doc/authd
SYSCONFDIR?=/etc
CONFDIR?=${SYSCONFDIR}/authd
ENVFILE?=${CONFDIR}/authd.env
MASTERKEY?=${CONFDIR}/master.key
PGPASS_PATH?=${CONFDIR}/pgpass
RCDIR?=${SYSCONFDIR}/rc.d
RUN_USER?=_authd
RUN_GROUP?=_authd

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
verify-openbsd: fmt-check test vet build integration-openbsd openbsd-deploy-check

integration:
	@test "$$AUTHD_TEST_DISPOSABLE" = "1" || { echo "AUTHD_TEST_DISPOSABLE=1 required" >&2; exit 1; }
	@test -n "$$AUTHD_TEST_DATABASE_URL" || { echo "AUTHD_TEST_DATABASE_URL required" >&2; exit 1; }
	go test -race -count=1 -tags=integration ./internal/db

integration-openbsd:
	@test "$$AUTHD_TEST_DISPOSABLE" = "1" || { echo "AUTHD_TEST_DISPOSABLE=1 required" >&2; exit 1; }
	@test -n "$$AUTHD_TEST_DATABASE_URL" || { echo "AUTHD_TEST_DATABASE_URL required" >&2; exit 1; }
	go test -count=1 -tags=integration ./internal/db

openbsd-deploy-check:
	@ksh -n deploy/openbsd/rc.d/authd
	@ksh -n .env.example

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

install-openbsd: install-openbsd-user install-openbsd-files install-openbsd-config install-openbsd-service
	@echo ""
	@echo "authd installed for OpenBSD."
	@echo "Complete ${ENVFILE} and ${PGPASS_PATH}, then follow ${DOCDIR}/DEPLOYMENT.md."

install-openbsd-user:
	@if [ -n "${DESTDIR}" ]; then \
		echo "==> staged install: not creating ${RUN_USER}"; \
		exit 0; \
	fi; \
	if ! grep -q '^${RUN_GROUP}:' /etc/group; then groupadd "${RUN_GROUP}"; fi; \
	if ! id "${RUN_USER}" >/dev/null 2>&1; then \
		useradd -g "${RUN_GROUP}" -d /var/empty -s /sbin/nologin "${RUN_USER}"; \
	fi; \
	if [ `id -gn "${RUN_USER}"` != "${RUN_GROUP}" ]; then \
		echo "${RUN_USER} exists with an unexpected primary group" >&2; exit 1; \
	fi

install-openbsd-files:
	@test -x bin/authd || { echo "bin/authd is missing; run make build" >&2; exit 1; }
	@echo "==> installing authd binary and documentation"
	@install -d -m 0755 "${DESTDIR}${BINDIR}" "${DESTDIR}${SHAREDIR}/postgresql" "${DESTDIR}${DOCDIR}"
	@install -m 0755 bin/authd "${DESTDIR}${BINDIR}/authd"
	@install -m 0644 README.md DEPLOYMENT.md SECURITY.md SPEC.md DESIGN_LANGUAGE.md "${DESTDIR}${DOCDIR}/"
	@install -m 0644 deploy/openbsd/README.md "${DESTDIR}${DOCDIR}/OPENBSD.md"
	@install -m 0644 deploy/postgresql/create-database.sql deploy/postgresql/runtime-grants.sql deploy/postgresql/README.md "${DESTDIR}${SHAREDIR}/postgresql/"

install-openbsd-config:
	@echo "==> installing authd configuration templates"
	@install -d -m 0750 "${DESTDIR}${CONFDIR}"
	@install -m 0640 .env.example "${DESTDIR}${CONFDIR}/authd.env.example"
	@install -m 0640 deploy/openbsd/pgpass.example "${DESTDIR}${CONFDIR}/pgpass.example"
	@if [ -n "${DESTDIR}" ]; then \
		echo "staged install: active env, pgpass, and master key are not created"; \
		exit 0; \
	fi; \
	chown root:"${RUN_GROUP}" "${CONFDIR}" "${CONFDIR}/authd.env.example" "${CONFDIR}/pgpass.example"; \
	if [ -e "${ENVFILE}" ]; then \
		chmod 0640 "${ENVFILE}"; chown root:"${RUN_GROUP}" "${ENVFILE}"; \
		echo "preserving existing ${ENVFILE}"; \
	else \
		install -m 0640 -o root -g "${RUN_GROUP}" .env.example "${ENVFILE}"; \
		echo "created ${ENVFILE}; edit it before first start"; \
	fi; \
	if [ -e "${MASTERKEY}" ]; then \
		chmod 0400 "${MASTERKEY}"; chown "${RUN_USER}":"${RUN_GROUP}" "${MASTERKEY}"; \
		echo "preserving existing ${MASTERKEY}"; \
	else \
		tmp="${MASTERKEY}.new.$$$$"; umask 077; ./scripts/generate-master-key.sh > "$$tmp"; \
		install -m 0400 -o "${RUN_USER}" -g "${RUN_GROUP}" "$$tmp" "${MASTERKEY}"; rm -f "$$tmp"; \
		echo "generated persistent ${MASTERKEY}"; \
	fi

install-openbsd-service:
	@echo "==> installing OpenBSD rc.d service"
	@install -d -m 0755 "${DESTDIR}${RCDIR}"
	@install -m 0555 deploy/openbsd/rc.d/authd "${DESTDIR}${RCDIR}/authd"

enable:
	@rcctl enable authd

start:
	@rcctl start authd

restart:
	@rcctl restart authd

status:
	@rcctl check authd

stop:
	@rcctl stop authd
