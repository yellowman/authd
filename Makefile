# authd build, verification, and native installation workflow.
#
# Keep this file in the common GNU make / BSD make subset so the same targets
# work on Linux and OpenBSD.

GO?=go
GOFMT?=gofmt
GOFLAGS?=
GO_BUILD_FLAGS?=-trimpath
BUILD_DIR?=bin
BINARY?=${BUILD_DIR}/authd

DESTDIR?=
PREFIX?=/usr/local
BINDIR?=${PREFIX}/bin
LIBEXECDIR?=${PREFIX}/libexec
SHAREDIR?=${PREFIX}/share/authd
DOCDIR?=${PREFIX}/share/doc/authd
SYSCONFDIR?=/etc
CONFDIR?=${SYSCONFDIR}/authd
ENVFILE?=${CONFDIR}/authd.env
MASTERKEY?=${CONFDIR}/master.key
PGPASS_PATH?=${CONFDIR}/pgpass
RUNDIR?=/var/authd
SYSTEMD_UNITDIR?=${SYSCONFDIR}/systemd/system
RCDIR?=${SYSCONFDIR}/rc.d
RUN_USER?=_authd
RUN_GROUP?=_authd
INSTALL_OS?=

.NOTPARALLEL:
.PHONY: deps fmt fmt-check env-check test race vet build verify verify-openbsd \
	verify-linux integration integration-openbsd openbsd-deploy-check \
	linux-deploy-check offline-check browser-check run migrate dev-db dev-db-down \
	install install-openbsd install-linux install-user install-files \
	install-config install-service enable start restart status stop help

deps:
	${GO} mod download
	${GO} mod verify

fmt:
	${GOFMT} -w $$(find cmd internal -type f -name '*.go' -print)

fmt-check:
	@test -z "$$(${GOFMT} -l $$(find cmd internal -type f -name '*.go' -print))" || { echo "Run make fmt" >&2; exit 1; }

env-check:
	@cmp -s .env.example deploy/openbsd/authd.env.example || { \
		echo "deploy/openbsd/authd.env.example is out of sync with .env.example" >&2; exit 1; }
	@cmp -s .env.example deploy/systemd/authd.env.example || { \
		echo "deploy/systemd/authd.env.example is out of sync with .env.example" >&2; exit 1; }

test:
	${GO} test -mod=readonly -count=1 ./...

race:
	${GO} test -mod=readonly -race -count=1 ./...

vet:
	${GO} vet -mod=readonly ./...

build:
	mkdir -p "${BUILD_DIR}"
	${GO} build -mod=readonly ${GOFLAGS} ${GO_BUILD_FLAGS} -o "${BINARY}" ./cmd/authd

# Requires real dependencies and a marked disposable PostgreSQL database.
# Missing prerequisites are failures, not successful skipped checks.
verify: fmt-check env-check test race vet build integration

# Go does not support -race on OpenBSD/amd64. This is the native OpenBSD gate;
# release qualification still requires `make race` on a race-supported platform.
verify-openbsd: fmt-check env-check test vet build integration-openbsd openbsd-deploy-check

# Native Linux release gate: includes the race detector and systemd-unit check.
verify-linux: fmt-check env-check test race vet build integration linux-deploy-check

integration:
	@test "$$AUTHD_TEST_DISPOSABLE" = "1" || { echo "AUTHD_TEST_DISPOSABLE=1 required" >&2; exit 1; }
	@test -n "$$AUTHD_TEST_DATABASE_URL" || { echo "AUTHD_TEST_DATABASE_URL required" >&2; exit 1; }
	${GO} test -mod=readonly -race -count=1 -tags=integration ./internal/db

integration-openbsd:
	@test "$$AUTHD_TEST_DISPOSABLE" = "1" || { echo "AUTHD_TEST_DISPOSABLE=1 required" >&2; exit 1; }
	@test -n "$$AUTHD_TEST_DATABASE_URL" || { echo "AUTHD_TEST_DATABASE_URL required" >&2; exit 1; }
	${GO} test -mod=readonly -count=1 -tags=integration ./internal/db

openbsd-deploy-check:
	@ksh -n deploy/openbsd/rc.d/authd
	@ksh -n .env.example
	@sh -n deploy/openbsd/authd-run

linux-deploy-check:
	@command -v systemd-analyze >/dev/null 2>&1 || { echo "systemd-analyze required" >&2; exit 1; }
	@tmp=`mktemp /tmp/authd.XXXXXX.service`; \
	trap 'rm -f "$$tmp"' EXIT HUP INT TERM; \
	sed -e 's#^ExecStart=.*#ExecStart=/bin/true#' -e 's#^EnvironmentFile=.*#EnvironmentFile=-/dev/null#' deploy/systemd/authd.service > "$$tmp"; \
	systemd-analyze verify "$$tmp"

# Developer-only browser gate. Missing Playwright/browser is a failure here,
# not a skipped pass. Runtime Go dependencies are unchanged.
browser-check:
	@python3 -c 'import playwright.sync_api' || { echo "Python Playwright required; see docs/BROWSER_TESTS.md" >&2; exit 1; }
	${GO} test -mod=readonly -race -count=1 -tags=browser -run '^TestBrowser' ./internal/web ./internal/oidc

offline-check:
	./scripts/check-offline.sh

run:
	${GO} run ./cmd/authd

migrate:
	${GO} run ./cmd/authd migrate

dev-db:
	docker compose -f compose.dev.yml up -d postgres

dev-db-down:
	docker compose -f compose.dev.yml down

# Generic native install. The first install creates missing runtime state;
# later installs replace program/service/documentation assets while preserving
# deployment-owned configuration, PostgreSQL credentials, and master-key data.
install: env-check install-user install-files install-config install-service
	@echo ""
	@echo "authd program/service assets installed."
	@echo "First install: complete ${ENVFILE} and ${PGPASS_PATH}. Upgrade: run reviewed migrations before restart."
	@echo "See ${DOCDIR}/DEPLOYMENT.md."

install-openbsd:
	@${MAKE} INSTALL_OS=OpenBSD install

install-linux:
	@${MAKE} INSTALL_OS=Linux install

install-user:
	@if [ -n "${DESTDIR}" ]; then \
		echo "==> staged install: not creating ${RUN_USER}"; \
		exit 0; \
	fi; \
	os="${INSTALL_OS}"; [ -n "$$os" ] || os=`uname -s`; \
	if ! grep -q '^${RUN_GROUP}:' /etc/group; then \
		case "$$os" in \
		Linux) groupadd -r "${RUN_GROUP}" ;; \
		OpenBSD) groupadd "${RUN_GROUP}" ;; \
		*) echo "unsupported install host: $$os (supported: Linux, OpenBSD)" >&2; exit 1 ;; \
		esac; \
	fi; \
	if ! id "${RUN_USER}" >/dev/null 2>&1; then \
		case "$$os" in \
		Linux) \
			nologin=/usr/sbin/nologin; [ -x "$$nologin" ] || nologin=/sbin/nologin; \
			useradd -r -g "${RUN_GROUP}" -d "${RUNDIR}" -s "$$nologin" -M "${RUN_USER}" ;; \
		OpenBSD) \
			useradd -g "${RUN_GROUP}" -d "${RUNDIR}" -s /sbin/nologin "${RUN_USER}" ;; \
		*) echo "unsupported install host: $$os (supported: Linux, OpenBSD)" >&2; exit 1 ;; \
		esac; \
	fi; \
	if [ `id -gn "${RUN_USER}"` != "${RUN_GROUP}" ]; then \
		echo "${RUN_USER} exists with an unexpected primary group" >&2; exit 1; \
	fi; \
	home=`awk -F: -v user="${RUN_USER}" '$$1 == user { print $$6; exit }' /etc/passwd`; \
	if [ "$$home" != "${RUNDIR}" ]; then \
		echo "${RUN_USER} exists with home $$home; authd requires ${RUNDIR}" >&2; exit 1; \
	fi; \
	install -d -m 0750 -o root -g "${RUN_GROUP}" "${RUNDIR}"

install-files:
	@test -x "${BINARY}" || { echo "${BINARY} is missing; run make build" >&2; exit 1; }
	@echo "==> installing authd binary and documentation"
	@install -d -m 0755 "${DESTDIR}${BINDIR}" "${DESTDIR}${SHAREDIR}/postgresql" "${DESTDIR}${DOCDIR}"
	@install -m 0755 "${BINARY}" "${DESTDIR}${BINDIR}/authd"
	@install -m 0644 README.md OPERATOR_GUIDE.md DEPLOYMENT.md SECURITY.md SPEC.md DESIGN_LANGUAGE.md ARCHITECTURE.md VALIDATION.md TODO.md CHANGELOG.md "${DESTDIR}${DOCDIR}/"
	@install -d -m 0755 "${DESTDIR}${DOCDIR}/docs" "${DESTDIR}${SHAREDIR}/nginx"
	@cp -R docs/. "${DESTDIR}${DOCDIR}/docs/"
	@find "${DESTDIR}${DOCDIR}/docs" -type d -exec chmod 0755 {} \;
	@find "${DESTDIR}${DOCDIR}/docs" -type f -exec chmod 0644 {} \;
	@install -m 0644 deploy/nginx/authd.conf.example "${DESTDIR}${SHAREDIR}/nginx/"
	@sed 's|../../DEPLOYMENT.md|DEPLOYMENT.md|g; s|../../docs/|docs/|g' deploy/openbsd/README.md > "${DESTDIR}${DOCDIR}/OPENBSD.md"
	@sed 's|../../DEPLOYMENT.md|DEPLOYMENT.md|g; s|../../docs/|docs/|g' deploy/systemd/README.md > "${DESTDIR}${DOCDIR}/LINUX.md"
	@chmod 0644 "${DESTDIR}${DOCDIR}/OPENBSD.md" "${DESTDIR}${DOCDIR}/LINUX.md"
	@install -m 0644 deploy/postgresql/create-database.sql deploy/postgresql/runtime-grants.sql deploy/postgresql/README.md "${DESTDIR}${SHAREDIR}/postgresql/"

install-config:
	@echo "==> installing authd configuration"
	@install -d -m 0750 "${DESTDIR}${CONFDIR}"
	@install -m 0640 .env.example "${DESTDIR}${CONFDIR}/authd.env.example"
	@install -m 0640 deploy/openbsd/pgpass.example "${DESTDIR}${CONFDIR}/pgpass.example"
	@if [ -n "${DESTDIR}" ]; then \
		echo "staged install: active env, pgpass, and master key are not created"; \
		exit 0; \
	fi; \
	chown root:"${RUN_GROUP}" "${CONFDIR}" "${CONFDIR}/authd.env.example" "${CONFDIR}/pgpass.example"; \
	if [ -e "${ENVFILE}" ]; then \
		chown root:"${RUN_GROUP}" "${ENVFILE}"; chmod 0640 "${ENVFILE}"; \
		echo "preserving existing ${ENVFILE}"; \
	else \
		install -m 0640 -o root -g "${RUN_GROUP}" .env.example "${ENVFILE}"; \
		echo "created ${ENVFILE}; edit it before first start"; \
	fi; \
	if [ -e "${MASTERKEY}" ]; then \
		chown "${RUN_USER}":"${RUN_GROUP}" "${MASTERKEY}"; chmod 0400 "${MASTERKEY}"; \
		echo "preserving existing ${MASTERKEY}"; \
	else \
		tmp="${MASTERKEY}.new.$$$$"; umask 077; ./scripts/generate-master-key.sh > "$$tmp"; \
		install -m 0400 -o "${RUN_USER}" -g "${RUN_GROUP}" "$$tmp" "${MASTERKEY}"; rm -f "$$tmp"; \
		echo "created ${MASTERKEY}; back it up before production use"; \
	fi; \
	if [ -e "${PGPASS_PATH}" ]; then \
		chown "${RUN_USER}":"${RUN_GROUP}" "${PGPASS_PATH}"; chmod 0400 "${PGPASS_PATH}"; \
		echo "preserving existing ${PGPASS_PATH}"; \
	fi

install-service:
	@os="${INSTALL_OS}"; [ -n "$$os" ] || os=`uname -s`; \
	case "$$os" in \
	Linux) \
		echo "==> installing systemd service"; \
		install -d -m 0755 "${DESTDIR}${SYSTEMD_UNITDIR}"; \
		install -m 0644 deploy/systemd/authd.service "${DESTDIR}${SYSTEMD_UNITDIR}/authd.service" ;; \
	OpenBSD) \
		echo "==> installing OpenBSD rc.d service"; \
		install -d -m 0755 "${DESTDIR}${RCDIR}" "${DESTDIR}${LIBEXECDIR}"; \
		install -m 0555 deploy/openbsd/authd-run "${DESTDIR}${LIBEXECDIR}/authd-run"; \
		install -m 0555 deploy/openbsd/rc.d/authd "${DESTDIR}${RCDIR}/authd" ;; \
	*) echo "unsupported install host: $$os (supported: Linux, OpenBSD)" >&2; exit 1 ;; \
	esac

enable:
	@os="${INSTALL_OS}"; [ -n "$$os" ] || os=`uname -s`; \
	case "$$os" in \
	Linux) systemctl daemon-reload && systemctl enable authd ;; \
	OpenBSD) rcctl enable authd ;; \
	*) echo "unsupported service host: $$os" >&2; exit 1 ;; \
	esac

start:
	@os="${INSTALL_OS}"; [ -n "$$os" ] || os=`uname -s`; \
	case "$$os" in \
	Linux) systemctl start authd ;; \
	OpenBSD) rcctl start authd ;; \
	*) echo "unsupported service host: $$os" >&2; exit 1 ;; \
	esac

restart:
	@os="${INSTALL_OS}"; [ -n "$$os" ] || os=`uname -s`; \
	case "$$os" in \
	Linux) systemctl daemon-reload && systemctl restart authd ;; \
	OpenBSD) rcctl restart authd ;; \
	*) echo "unsupported service host: $$os" >&2; exit 1 ;; \
	esac

status:
	@os="${INSTALL_OS}"; [ -n "$$os" ] || os=`uname -s`; \
	case "$$os" in \
	Linux) systemctl status authd ;; \
	OpenBSD) rcctl check authd ;; \
	*) echo "unsupported service host: $$os" >&2; exit 1 ;; \
	esac

stop:
	@os="${INSTALL_OS}"; [ -n "$$os" ] || os=`uname -s`; \
	case "$$os" in \
	Linux) systemctl stop authd ;; \
	OpenBSD) rcctl stop authd ;; \
	*) echo "unsupported service host: $$os" >&2; exit 1 ;; \
	esac

help:
	@printf '%s\n' \
		'make build                    Build authd' \
		'make verify                   Run full test/race/vet/PostgreSQL gate' \
		'make verify-openbsd           Native OpenBSD gate (no race detector)' \
		'make verify-linux             Native Linux/systemd gate' \
		'make browser-check            Native Chromium forms; test-only Playwright required' \
		'make install-openbsd          Install/update OpenBSD assets; preserve runtime state' \
		'make install-linux            Install/update Linux assets; preserve runtime state' \
		'make enable|start|restart     Manage installed service for current OS'
