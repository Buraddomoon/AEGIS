"""Disposable PostgreSQL and offline smoke failures; never start the Lab."""

import importlib.util
from pathlib import Path
from uuid import uuid4

import pytest
from aegis.operations.linux_campaign_readiness import check
from aegis.operations.runtime_grants import RUNTIME_PERMISSIONS
from sqlalchemy import text


@pytest.fixture
def readiness_role(db_ready, pg_engine):
    role = "aegis_campaign_test_" + uuid4().hex
    with pg_engine.begin() as connection:
        namespace = connection.scalar(text("SELECT current_schema()"))
        assert namespace.startswith("aegis_test_") and namespace.isidentifier()
        connection.exec_driver_sql(f'CREATE ROLE "{role}" NOLOGIN')
    try:
        with pg_engine.begin() as connection:
            for statement in RUNTIME_PERMISSIONS:
                connection.exec_driver_sql(
                    statement.replace("SCHEMA public", f'SCHEMA "{namespace}"').replace(
                        "aegis_app", f'"{role}"'
                    )
                )
        yield role
    finally:
        with pg_engine.begin() as connection:
            connection.exec_driver_sql(f'DROP OWNED BY "{role}"')
            connection.exec_driver_sql(f'DROP ROLE "{role}"')


def test_readiness_is_a_read_only_snapshot(readiness_role, pg_engine):
    with pg_engine.connect() as connection:
        check(connection, role=readiness_role)
        assert connection.scalar(text("SHOW transaction_read_only")) == "on"
        assert connection.scalar(text("SHOW transaction_isolation")) == "repeatable read"
        with pytest.raises(Exception, match="read-only transaction"):
            connection.execute(text("DELETE FROM audit_events"))


def test_readiness_refuses_legacy_revision_without_migrating(readiness_role, pg_engine):
    with pg_engine.begin() as connection:
        connection.execute(text("UPDATE alembic_version SET version_num='d4465b7aca2a'"))
    try:
        with pg_engine.connect() as connection:
            with pytest.raises(RuntimeError, match="schema upgrade"):
                check(connection, role=readiness_role)
        with pg_engine.connect() as connection:
            assert (
                connection.scalar(text("SELECT version_num FROM alembic_version")) == "d4465b7aca2a"
            )
    finally:
        with pg_engine.begin() as connection:
            connection.execute(text("UPDATE alembic_version SET version_num='b7f3c2d91a06'"))


@pytest.mark.parametrize(
    "grant",
    [
        "GRANT UPDATE ON runner_receipts",
        "GRANT DELETE ON runner_cleanups",
        "GRANT UPDATE (run_id) ON scheduled_reports",
        "REVOKE UPDATE (generation) ON runner_dispatches",
    ],
)
def test_readiness_refuses_changed_grants(readiness_role, pg_engine, grant):
    with pg_engine.begin() as connection:
        preposition = " FROM " if grant.startswith("REVOKE") else " TO "
        connection.exec_driver_sql(grant + preposition + f'"{readiness_role}"')
    with pg_engine.connect() as connection:
        with pytest.raises(RuntimeError, match="runtime grants"):
            check(connection, role=readiness_role)


def test_readiness_refuses_reserved_lab(readiness_role, pg_engine):
    with pg_engine.begin() as connection:
        connection.execute(
            text("UPDATE laboratories SET active_run_id=:run"), {"run": str(uuid4())}
        )
    with pg_engine.connect() as connection:
        with pytest.raises(RuntimeError, match="reserved laboratory"):
            check(connection, role=readiness_role)


@pytest.fixture
def smoke_module():
    spec = importlib.util.spec_from_file_location(
        "linux_smoke_test", "scripts/smoke_linux_platform.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize(
    "revoke_fails,accounts_fail", [(False, False), (True, False), (False, True), (True, True)]
)
def test_smoke_attempts_both_cleanup_actions(
    smoke_module, monkeypatch, revoke_fails, accounts_fail
):
    calls = []

    def revoke():
        calls.append("revoke")
        if revoke_fails:
            raise RuntimeError("private detail must not appear")

    def disable(accounts, disable):
        assert disable and accounts == [{"username": "test"}]
        calls.append("disable")
        if accounts_fail:
            raise RuntimeError("private detail must not appear")

    monkeypatch.setattr(smoke_module, "local_accounts", disable)
    if revoke_fails or accounts_fail:
        with pytest.raises(ExceptionGroup) as raised:
            smoke_module.finish_assay([{"username": "test"}], revoke)
        assert len(raised.value.exceptions) == int(revoke_fails) + int(accounts_fail)
        assert "private detail" not in str(raised.value.exceptions)
    else:
        smoke_module.finish_assay([{"username": "test"}], revoke)
    assert calls == ["revoke", "disable"]


def test_campaign_overlay_removes_automatic_migration_and_requires_pinned_inputs():
    # Compose rendering is checked separately with the real CLI. This regression
    # keeps the opt-in renewal path from restoring the historical migrate/seed.
    import yaml

    class ComposeLoader(yaml.SafeLoader):
        pass

    ComposeLoader.add_constructor("!reset", lambda loader, node: None)
    config = yaml.load(Path("labs/linux/campaign.yml").read_text(), Loader=ComposeLoader)
    services = config["services"]
    assert services["migrate"]["command"] == [
        "python",
        "-m",
        "aegis.operations.linux_campaign_readiness",
    ]
    assert services["migrate"]["build"] is None and services["runner"]["build"] is None
    assert all(":?" in service["image"] for service in services.values())


@pytest.mark.parametrize("fail_path", [None, "/campaigns", "/reports/run-1"])
def test_smoke_records_one_attempt_and_cleans_up_after_midflow_failure(
    smoke_module, tmp_path, monkeypatch, fail_path
):
    import httpx

    calls = []
    lab_id = str(uuid4())

    class Client:
        headers = {}

        def __init__(self, **kwargs):
            assert kwargs["trust_env"] is False

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def post(self, path, **kwargs):
            return httpx.Response(
                200, json={"csrf_token": "test"}, request=httpx.Request("POST", path)
            )

        def request(self, method, path, **kwargs):
            calls.append((method, path, kwargs.get("json")))
            body = {
                "/labs": {
                    "items": [
                        {
                            "id": lab_id,
                            "kind": "linux",
                            "authorized": False,
                            "trust": {"matches_deployment": True},
                        }
                    ]
                },
                f"/labs/{lab_id}/preflight": {"success": True},
                "/coverage?mode=demo": {"completed_tests": 3},
                "/coverage?mode=linux": {"completed_tests": 2},
                "/campaigns": {"id": "campaign-1"},
                "/campaigns/campaign-1/runs": {"id": "run-1", "scope_hash": "a" * 64},
                "/executions/run-1": {
                    "state": "COMPLETED",
                    "executions": [
                        {
                            "executed": True,
                            "synthetic": False,
                            "result": {"outcome": "INCONCLUSIVE"},
                            "events": [],
                            "evidence": [],
                            "runner_receipt": {"content": {"artifact_bytes": 43}},
                            "runner_cleanup": {"content": {"cleanup_state": "CLEANED"}},
                        }
                    ],
                },
                "/reports/run-1": {"synthetic": False},
            }.get(path, {})
            return httpx.Response(
                500 if path == fail_path else 200, json=body, request=httpx.Request(method, path)
            )

        def get(self, path):
            return httpx.Response(
                200, text="COMPROVANTES DO EXECUTOR", request=httpx.Request("GET", path)
            )

    def accounts(values, disable=False):
        calls.append(("accounts", disable))

    attempt = str(uuid4())
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        smoke_module, "dotenv_values", lambda path: {"AEGIS_RUNNER_LABORATORY_ID": lab_id}
    )
    monkeypatch.setattr(smoke_module.httpx, "Client", Client)
    monkeypatch.setattr(smoke_module, "local_accounts", accounts)
    monkeypatch.setattr(
        "sys.argv", ["smoke", "--confirm-integrated-marker", "--attempt-id", attempt]
    )
    if fail_path:
        with pytest.raises(httpx.HTTPStatusError):
            smoke_module.main()
    else:
        smoke_module.main()
    assert calls[-1] == ("accounts", True)
    assert calls[-2] == ("PATCH", f"/labs/{lab_id}/authorization", {"authorized": False})
    assert sum(item[:2] == ("POST", "/executions/run-1/start") for item in calls) <= 1
    consumed = tmp_path / ".local/linux-lab" / f"campaign-attempt-{attempt}.jsonl"
    assert consumed.stat().st_mode & 0o777 == 0o600
    before = list(calls)
    with pytest.raises(FileExistsError):
        smoke_module.main()
    assert calls == before
