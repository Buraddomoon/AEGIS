import uuid

import aegis.db as database
import pytest
from aegis.config import settings
from aegis.models import User
from aegis.security import hasher, redis_client
from aegis.seed import seed
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text


@pytest.fixture(scope="session")
def pg_engine():
    """Real PostgreSQL, temporary schema; never truncate application tables."""
    schema = "aegis_test_" + uuid.uuid4().hex
    original = database.engine()
    with original.begin() as conn:
        conn.execute(text(f'CREATE SCHEMA "{schema}"'))
    test_engine = create_engine(
        settings().database_url, connect_args={"options": f"-csearch_path={schema}"}, pool_size=8
    )
    previous = database.engine
    database.engine = lambda: test_engine
    redis_before = settings().redis_url
    settings().redis_url = redis_before.rsplit("/", 1)[0] + "/15"
    settings().demo_step_seconds = 0
    try:
        command.upgrade(Config("alembic.ini"), "head")
        yield test_engine
    finally:
        database.engine = previous
        settings().redis_url = redis_before
        test_engine.dispose()
        with original.begin() as conn:
            conn.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))


@pytest.fixture
def db_ready(pg_engine):
    with pg_engine.begin() as connection:
        tables = [f'"{t}"' for t in database.Base.metadata.tables]
        connection.execute(text("TRUNCATE " + ",".join(tables) + " CASCADE"))
    client = redis_client()
    keys = list(client.scan_iter("aegis:limit:*"))
    if keys:
        client.delete(*keys)
    with database.session_factory()() as db:
        seed(db)
        for role in ["administrator", "operator", "viewer"]:
            db.add(
                User(
                    username=role,
                    role=role,
                    password_hash=hasher.hash("Test-only-randomized-scope-23!"),
                )
            )
        db.commit()


@pytest.fixture
def client(db_ready):
    from aegis.main import app

    with TestClient(app) as client:
        yield client


@pytest.fixture
def admin(client):
    result = client.post(
        "/api/v1/auth/login",
        headers={"x-aegis-request": "browser"},
        json={"username": "administrator", "password": "Test-only-randomized-scope-23!"},
    )
    assert result.status_code == 200, result.text
    client.headers["x-csrf-token"] = result.json()["csrf_token"]
    return client


def create_queued(client, tests=None):
    lab = client.get("/api/v1/labs").json()["items"][0]
    campaign = client.post(
        "/api/v1/campaigns",
        json={
            "name": "Teste de integração",
            "objective": "Validar o fluxo completo e a coleta sintética.",
            "laboratory_id": lab["id"],
            "test_ids": tests
            or ["demo-shell", "demo-powershell", "demo-process-discovery", "demo-file-marker"],
        },
    )
    assert campaign.status_code == 201, campaign.text
    run = client.post(
        f"/api/v1/campaigns/{campaign.json()['id']}/runs",
        json={"idempotency_key": uuid.uuid4().hex},
    )
    assert run.status_code == 201, run.text
    result = run.json()
    approved = client.post(
        f"/api/v1/executions/{result['id']}/approve",
        json={"confirm_scope_hash": result["scope_hash"], "max_duration_seconds": 60},
    )
    assert approved.status_code == 200, approved.text
    started = client.post(f"/api/v1/executions/{result['id']}/start", json={"confirm": True})
    assert started.status_code == 200, started.text
    return result
