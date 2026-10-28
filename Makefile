PYTHON ?= python3.13
VENV = .venv/bin
DEV = docker compose -f docker-compose.yml -f infra/compose.dev.yml

.PHONY: setup up down bootstrap seed infra dev-api dev-worker dev-web migrate lint format test test-unit test-integration test-web e2e build audit logs clean-demo smoke
setup:
	$(PYTHON) -m venv .venv
	$(VENV)/python -m pip install --upgrade pip==26.2.2
	$(VENV)/pip install --require-hashes --no-deps -r requirements-dev.lock
	$(VENV)/pip install -e . --no-deps
	npm --prefix apps/web ci
	$(VENV)/python scripts/init_env.py
up:
	python3 scripts/init_env.py
	docker compose up -d --build
down:
	docker compose down
bootstrap:
	docker compose run --rm migrate python -m aegis.cli bootstrap
seed:
	docker compose run --rm migrate python -m aegis.cli seed
infra:
	$(VENV)/python scripts/init_env.py
	$(DEV) up -d --wait db redis
dev-api:
	$(VENV)/uvicorn aegis.main:app --host 127.0.0.1 --port 18781 --reload
dev-worker:
	$(VENV)/python -m aegis.worker
dev-web:
	npm --prefix apps/web run dev
migrate:
	$(VENV)/alembic upgrade head
lint:
	$(VENV)/ruff check apps/api scripts tests
	$(VENV)/ruff format --check apps/api scripts tests
	$(VENV)/mypy
	npm --prefix apps/web run lint
	npm --prefix apps/web run format:check
format:
	$(VENV)/ruff check --fix apps/api scripts tests
	$(VENV)/ruff format apps/api scripts tests
	npm --prefix apps/web run format
test-unit:
	$(VENV)/pytest tests/test_domain.py -q
test-integration:
	$(VENV)/pytest tests/test_flow.py tests/test_security.py tests/test_integrations.py tests/test_migrations.py tests/test_cleanup.py tests/test_transactions.py tests/test_scheduling.py tests/test_linux_campaigns.py tests/test_binding_review.py tests/test_wazuh_campaigns.py tests/test_rule_links.py tests/test_coverage_comparison.py tests/test_sigma_analysis.py tests/test_sigma_readiness.py -q
test-web:
	npm --prefix apps/web test
test:
	$(VENV)/pytest -q
	npm --prefix apps/web test
e2e: build
	$(VENV)/python scripts/e2e.py
build:
	npm --prefix apps/web run build
audit:
	$(VENV)/python scripts/audit_dependencies.py
	npm --prefix apps/web audit --audit-level=high
logs:
	docker compose logs --tail=100 api worker
clean-demo:
	$(VENV)/python scripts/clean_demo.py
smoke:
	$(VENV)/python scripts/smoke_compose.py

.PHONY: release-check
release-check:
	$(VENV)/python scripts/check_release.py

# Operator-only Demo recovery. Verify always creates its own offline clone.
.PHONY: backup-demo verify-backup backup-retention-plan test-recovery
backup-demo:
	$(VENV)/python scripts/demo_backup.py create
verify-backup:
	@test -n "$(BACKUP_ID)" || (echo 'Use make verify-backup BACKUP_ID=<id>'; exit 2)
	$(VENV)/python scripts/demo_backup.py verify "$(BACKUP_ID)"
backup-retention-plan:
	$(VENV)/python scripts/demo_backup.py retention-plan
test-recovery:
	$(VENV)/pytest tests/test_backup_inventory.py tests/test_backup_cli.py tests/test_backup_vault.py tests/test_recovery_guards.py tests/test_recovery_api.py tests/test_recovery_probe.py tests/test_recovery_reconciliation.py tests/test_recovered_demo_cycle.py tests/test_recovery_cycle_runtime.py -q

.PHONY: recovery-app-build verify-recovered-app
recovery-app-build:
	docker build --pull=false -t aegis-recovery-local:0.2 .
verify-recovered-app:
	@test -n "$(BACKUP_ID)" || (echo 'Use make verify-recovered-app BACKUP_ID=<id>'; exit 2)
	$(VENV)/python scripts/demo_backup.py verify-application "$(BACKUP_ID)"
.PHONY: reconcile-demo-backup
reconcile-demo-backup:
	@test -n "$(BACKUP_ID)" || (echo 'Use make reconcile-demo-backup BACKUP_ID=<id>'; exit 2)
	$(VENV)/python scripts/demo_backup.py reconcile-demo "$(BACKUP_ID)"
.PHONY: verify-recovered-cycle
verify-recovered-cycle:
	@test -n "$(BACKUP_ID)" || (echo 'Use make verify-recovered-cycle BACKUP_ID=<id>'; exit 2)
	$(VENV)/python scripts/demo_backup.py verify-recovered-cycle "$(BACKUP_ID)"

# Linux lab is opt-in; never started by make up or make test.
LAB = docker compose --env-file .local/linux-lab/ids.env -f labs/linux/compose.yml
.PHONY: lab-init lab-config lab-build lab-up lab-preflight lab-inspect lab-smoke lab-down
lab-init:
	$(VENV)/python scripts/init_linux_lab.py
lab-config:
	$(LAB) config --quiet
lab-build: lab-config
	$(LAB) build runner
lab-up: lab-config
	$(LAB) up -d runner
lab-preflight:
	$(LAB) run --rm --no-deps controller preflight
lab-inspect:
	$(VENV)/python scripts/inspect_linux_lab.py
lab-smoke: lab-inspect
	$(LAB) run --rm --no-deps controller marker --confirm-marker-test
lab-down:
	$(LAB) down
.PHONY: test-runner
test-runner:
	$(VENV)/pytest tests/test_runner_protocol.py tests/test_runner_engine.py tests/test_runner_transport.py tests/test_runner_parent_death.py tests/test_runner_isolation.py -q

# Separate database/API on 18785; never modifies the default Demo stack.
LINUX_PLATFORM = docker compose --env-file .env --env-file .local/linux-lab/ids.env -p aegis-linux-lab -f docker-compose.yml -f labs/linux/compose.yml -f labs/linux/platform.yml
.PHONY: linux-platform-config linux-platform-build linux-platform-up linux-platform-smoke linux-platform-down
linux-platform-config:
	$(LINUX_PLATFORM) config --quiet
linux-platform-build: linux-platform-config
	$(LINUX_PLATFORM) build migrate runner
linux-platform-up: linux-platform-config
	$(LINUX_PLATFORM) up -d db redis migrate runner api worker
linux-platform-smoke:
	$(VENV)/python scripts/inspect_linux_lab.py
	$(VENV)/python scripts/smoke_linux_platform.py --confirm-integrated-marker
linux-platform-down:
	$(LINUX_PLATFORM) down

# Local contract tests only: no Wazuh installation or real lab startup.
.PHONY: test-wazuh
test-wazuh:
	$(VENV)/pytest tests/test_wazuh_collection.py tests/test_wazuh_campaigns.py tests/test_marker_observer.py tests/test_wazuh_tls.py -q

# A separate real Wazuh assay is never started by default. See labs/wazuh/ASSAY.md.
.PHONY: wazuh-lab-prepare wazuh-lab-config wazuh-lab-preflight test-wazuh-preparation wazuh-lab-pull wazuh-lab-hash-users wazuh-lab-build wazuh-lab-up wazuh-lab-inspect wazuh-lab-check-rule wazuh-lab-assay wazuh-lab-status wazuh-lab-down
wazuh-lab-prepare:
	$(VENV)/python scripts/prepare_wazuh_lab.py
wazuh-lab-config:
	$(VENV)/python scripts/wazuh_lab.py config
wazuh-lab-preflight:
	$(VENV)/python scripts/wazuh_host_preflight.py
test-wazuh-preparation:
	$(VENV)/pytest tests/test_wazuh_host_preflight.py tests/test_wazuh_lab_preparation.py tests/test_wazuh_lab_lifecycle.py tests/test_wazuh_runtime_inspection.py tests/test_wazuh_assay_guard.py tests/test_marker_log.py tests/test_marker_observer.py -q
wazuh-lab-pull:
	$(VENV)/python scripts/wazuh_lab.py pull --confirm-local-wazuh
wazuh-lab-hash-users:
	$(VENV)/python scripts/wazuh_lab.py hash-users --confirm-local-wazuh
wazuh-lab-build:
	$(VENV)/python scripts/wazuh_lab.py build --confirm-local-wazuh
wazuh-lab-up:
	$(VENV)/python scripts/wazuh_lab.py up --confirm-local-wazuh
wazuh-lab-inspect:
	$(VENV)/python scripts/inspect_wazuh_lab.py
wazuh-lab-check-rule:
	$(VENV)/python scripts/wazuh_lab.py check-rule --confirm-local-wazuh
wazuh-lab-assay:
	$(VENV)/python scripts/smoke_wazuh_platform.py --confirm-integrated-marker
wazuh-lab-status:
	$(VENV)/python scripts/wazuh_lab.py status
wazuh-lab-down:
	$(VENV)/python scripts/wazuh_lab.py down --confirm-local-wazuh

# Encryption is host-only. Private identities are never accepted on the command line.
.PHONY: backup-tools backup-keygen seal-backup verify-sealed-backup backup-vault-plan
backup-tools:
	$(VENV)/pip install --require-hashes --no-deps --only-binary=:all: -r requirements-backup.lock
backup-keygen:
	$(VENV)/python scripts/demo_backup.py keygen
seal-backup:
	@test -n "$(BACKUP_ID)" -a -n "$(RECIPIENT)" || (echo 'Set BACKUP_ID and public RECIPIENT'; exit 2)
	$(VENV)/python scripts/demo_backup.py seal "$(BACKUP_ID)" --recipient "$(RECIPIENT)"
verify-sealed-backup:
	@test -n "$(SEALED_ID)" -a -n "$(CIPHERTEXT_SHA256)" -a -n "$(KEY_ID)" || (echo 'Set SEALED_ID, CIPHERTEXT_SHA256 and KEY_ID'; exit 2)
	$(VENV)/python scripts/demo_backup.py verify-sealed "$(SEALED_ID)" --expected-sha256 "$(CIPHERTEXT_SHA256)" --key-id "$(KEY_ID)"
backup-vault-plan:
	$(VENV)/python scripts/demo_backup.py vault-plan

# Host-only runner PKI candidates. These commands never activate or start a lab.
PKI_SOURCE ?= .local/linux-lab
PKI_OUTPUT ?= .local/pki-candidates
.PHONY: runner-pki-inspect runner-pki-prepare runner-pki-verify test-runner-pki
runner-pki-inspect:
	$(VENV)/python scripts/runner_pki.py inspect --source "$(PKI_SOURCE)"
runner-pki-prepare:
	@test -n "$(PKI_SHA256)" || (echo 'Set PKI_SHA256 from the reviewed public inventory'; exit 2)
	$(VENV)/python scripts/runner_pki.py prepare --source "$(PKI_SOURCE)" --expected-sha256 "$(PKI_SHA256)" --output-root "$(PKI_OUTPUT)"
runner-pki-verify:
	@test -n "$(PKI_CANDIDATE)" -a -n "$(PKI_SHA256)" || (echo 'Set PKI_CANDIDATE and reviewed manifest PKI_SHA256'; exit 2)
	$(VENV)/python scripts/runner_pki.py verify --source "$(PKI_SOURCE)" --candidate "$(PKI_CANDIDATE)" --expected-sha256 "$(PKI_SHA256)"
test-runner-pki:
	$(VENV)/pytest tests/test_runner_pki_generation.py tests/test_runner_pki.py tests/test_runner_pki_tls.py -q

.PHONY: test-binding-review
test-binding-review:
	$(VENV)/pytest tests/test_binding_review.py -q

# Read-only host metadata planning. No activation/lifecycle command is exposed.
.PHONY: runner-activation-plan runner-activation-recheck test-runner-activation
runner-activation-plan:
	$(VENV)/python scripts/runner_activation.py plan --source "$(PKI_SOURCE)" --candidate "$(PKI_CANDIDATE)" --manifest-sha256 "$(PKI_SHA256)" --application-image "$(APPLICATION_IMAGE_ID)" --runner-image "$(RUNNER_IMAGE_ID)" --postgres-image "$(POSTGRES_IMAGE_ID)" --redis-image "$(REDIS_IMAGE_ID)"
runner-activation-recheck:
	$(VENV)/python scripts/runner_activation.py recheck --plan "$(ACTIVATION_PLAN)" --expected-sha256 "$(ACTIVATION_SHA256)"
test-runner-activation:
	$(VENV)/pytest tests/test_runner_activation_metadata.py tests/test_runner_activation_plan.py tests/test_runner_activation_intents.py tests/test_runner_activation_ownership.py tests/test_runner_activation_probe_runtime.py tests/test_runner_activation_cleanup.py tests/test_runner_activation_probe_result.py tests/test_runner_activation_transport.py tests/test_runner_activation_probe_lifecycle.py tests/test_runner_activation_active_metadata.py tests/test_runner_activation_active_plan.py tests/test_runner_activation_database_runtime.py tests/test_runner_activation_database_result.py tests/test_runner_activation_database_lifecycle.py tests/test_runner_activation_database_policy.py tests/test_runner_activation_database_server.py tests/test_runner_activation_database_inspection.py tests/test_runner_activation_database_server_lifecycle.py -q

# Temporary PostgreSQL schema + SQLite only. Never mount/start a Linux lab.
.PHONY: test-runner-continuity
test-runner-continuity:
	$(VENV)/pytest tests/test_runner_journal_continuity.py tests/test_runner_persisted_review.py tests/test_runner_journal_probe.py tests/test_runner_persisted_probe.py -q

# Committed private source only; never builds, pulls or starts a runner.
.PHONY: runner-image-source-prepare runner-image-source-verify test-runner-image-source
runner-image-source-prepare:
	$(VENV)/python scripts/runner_activation_image_source.py prepare
runner-image-source-verify:
	$(VENV)/python scripts/runner_activation_image_source.py verify --source-id "$(RUNNER_SOURCE_ID)" --expected-sha256 "$(RUNNER_SOURCE_SHA256)"
test-runner-image-source:
	$(VENV)/pytest tests/test_runner_activation_image_source.py -q

.PHONY: test-runner-image-build
test-runner-image-build:
	$(VENV)/pytest tests/test_runner_image_assert.py tests/test_runner_image_registry.py tests/test_runner_image_wheels.py tests/test_runner_image_base.py -q

# Download verified wheels only; does not install, pull images or start a lab.
.PHONY: runner-image-wheels-prepare runner-image-wheels-verify
runner-image-wheels-prepare:
	$(VENV)/python scripts/runner_image_wheels.py prepare --source-id "$(RUNNER_SOURCE_ID)" --expected-sha256 "$(RUNNER_SOURCE_SHA256)"
runner-image-wheels-verify:
	$(VENV)/python scripts/runner_image_wheels.py verify --cache-id "$(RUNNER_WHEEL_CACHE_ID)" --expected-sha256 "$(RUNNER_WHEEL_CACHE_SHA256)"
