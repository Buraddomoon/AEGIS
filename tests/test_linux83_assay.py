"""Native assay preparation/authority fixtures; never starts a Docker resource."""

import copy
import json
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from aegis.lab_runner import behavior_policy
from aegis.lab_runner.assay_profile import selected
from test_atomic_assay import modules as modules


def proposal(kind):
    identifier = uuid4().hex
    return {
        "id": identifier,
        "profile": "linux83-" + kind,
        "format": "linux83-one-attempt/1",
        "project": "aegis-linux83-" + identifier[:12],
        "identity": {key: str(uuid4()) for key in ("runner_id", "laboratory_id", "asset_id")},
        "review": behavior_policy.review(kind),
        "expires_at": (datetime.now(UTC) + timedelta(hours=12)).isoformat(),
        "images": {
            key: "sha256:" + "a" * 64 for key in ("application", "runner", "postgres", "redis")
        },
    }


@pytest.mark.parametrize("kind", ["process", "shell"])
def test_fresh_recipe_is_single_profile_and_has_no_originals_or_owner_secret_in_runtime(
    modules, tmp_path, kind
):
    plan = proposal(kind)
    recipe = modules["atomic_assay"].recipe(plan, tmp_path)
    assert (
        recipe["services"]["runner"]["environment"]["AEGIS_RUNNER_TEST_ID"]
        == behavior_policy.TEST_IDS[kind]
    )
    assert recipe["services"]["db"]["environment"]["POSTGRES_DB"] == "linux83_assay"
    assert recipe["services"]["db"]["environment"]["POSTGRES_USER"] == "linux83_owner"
    assert set(recipe["volumes"]) == {"database", "journal", "evidence"}
    assert all(v["name"].startswith(plan["project"] + "_") for v in recipe["volumes"].values())
    assert all(n["internal"] and not n["enable_ipv6"] for n in recipe["networks"].values())
    for name in ("api", "worker"):
        assert "plan" in recipe["services"][name]["secrets"]
        assert not {"owner_url", "accounts", "app_password"}.intersection(
            recipe["services"][name]["secrets"]
        )
    assert not any(
        s.get("ports") or s.get("build") or s.get("privileged") or s.get("network_mode")
        for s in recipe["services"].values()
    )
    assert all("ca.key" not in s["file"] for s in recipe["secrets"].values())


@pytest.mark.parametrize(
    "change",
    [
        {"profile": "atomic80", "format": "linux83-one-attempt/1"},
        {"profile": "other"},
        {"profile": "linux83-shell", "format": "atomic80-one-attempt/1"},
        {"profile": "linux83-process", "format": None},
    ],
)
def test_unknown_or_legacy_envelope_cannot_select_a_behavior(change):
    with pytest.raises(ValueError):
        selected({**proposal("process"), **change})


@pytest.mark.parametrize("kind", ["process", "shell"])
@pytest.mark.parametrize(
    "authority",
    [
        None,
        {},
        {"proposal_sha256": "b" * 64, "approved_by": "user", "one_attempt": True},
        {"proposal_sha256": "a" * 64, "approved_by": "agent", "one_attempt": True},
    ],
)
def test_missing_or_mismatched_authority_never_starts_or_consumes(
    modules, tmp_path, monkeypatch, kind, authority
):
    host = modules["atomic_assay"]
    monkeypatch.setattr(host, "verify", lambda *a: (tmp_path, proposal(kind)))
    monkeypatch.setattr(
        host, "docker", lambda *a, **kw: pytest.fail("No Docker operation authorized")
    )
    if authority is not None:
        host.put(tmp_path / "authorization.json", authority)
    with pytest.raises((OSError, ValueError)):
        host.run(uuid4().hex, "a" * 64)
    assert not (tmp_path / "attempt.json").exists()


@pytest.mark.parametrize("kind", ["process", "shell"])
def test_consumed_behavior_attempt_preserves_fence(modules, tmp_path, monkeypatch, kind):
    host = modules["atomic_assay"]
    monkeypatch.setattr(host, "verify", lambda *a: (tmp_path, proposal(kind)))
    host.put(
        tmp_path / "authorization.json",
        {"proposal_sha256": "a" * 64, "approved_by": "user", "one_attempt": True},
    )
    host.put(tmp_path / "attempt.json", {"original": True})
    before = (tmp_path / "attempt.json").read_bytes()
    with pytest.raises(ValueError, match="consumed"):
        host.run(uuid4().hex, "a" * 64)
    assert (tmp_path / "attempt.json").read_bytes() == before


@pytest.mark.parametrize("kind", ["process", "shell"])
@pytest.mark.parametrize("changed", [False, True])
def test_controller_review_drift_blocks_before_even_login(modules, kind, changed):
    plan = proposal(kind)
    if changed:
        plan = copy.deepcopy(plan)
        plan["review"]["program_sha256"] = "0" * 64
    else:
        plan["review"] = behavior_policy.review("shell" if kind == "process" else "process")
    with pytest.raises(ValueError, match="review"):
        modules["atomic_assay_client"].assay(
            plan,
            [
                {"username": role, "role": role, "password": "fixture-only"}
                for role in ("administrator", "operator")
            ],
            None,
        )


@pytest.mark.parametrize("kind", ["process", "shell"])
@pytest.mark.parametrize("database", ["aegis", "atomic_assay", "linux83_assay?options=x"])
def test_service_rejects_original_or_other_profile_database_before_engine(
    modules, tmp_path, monkeypatch, kind, database
):
    service = modules["atomic_assay_service"]
    plan = proposal(kind)
    (tmp_path / "plan").write_text(json.dumps(plan))
    monkeypatch.setattr(service, "SECRETS", tmp_path)
    monkeypatch.setattr(
        service,
        "secret",
        lambda name: f"postgresql+psycopg://linux83_owner:test@db:5432/{database}",
    )
    with pytest.raises(ValueError, match="Fresh"):
        service.configure(owner=True)
