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
	$(VENV)/pytest tests/test_flow.py tests/test_security.py tests/test_integrations.py tests/test_migrations.py tests/test_cleanup.py tests/test_transactions.py tests/test_scheduling.py tests/test_linux_campaigns.py tests/test_wazuh_campaigns.py -q
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
