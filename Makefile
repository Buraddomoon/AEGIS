PYTHON ?= python3.13
VENV = .venv/bin
DEV = docker compose -f docker-compose.yml -f infra/compose.dev.yml

.PHONY: setup up down bootstrap seed infra dev-api dev-worker dev-web migrate lint format test test-unit test-integration test-web e2e build audit logs clean-demo
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
	$(VENV)/pytest tests/test_flow.py tests/test_security.py tests/test_integrations.py tests/test_migrations.py -q
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
