"""Owned diagnostic rechecks over Git/PKI/intents and daemon fixtures only."""

import sys
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest
from test_build_review_runner import prepared as prepared
from test_runner_activation_image_source import repository as repository
from test_runner_activation_ownership import FakeDocker as Owner
from test_runner_diagnostic_plan import diagnostic as diagnostic

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import runner_diagnostic_recheck as review  # noqa: E402
from runner_activation_intents import ActivationIntents  # noqa: E402


class World:
    def __init__(self, store, docker, images, role, phase):
        self.owners, self.docker = {}, docker
        operation = store.summary()["id"]
        for i, key in enumerate(["db"] if role == "db" else ["db", role]):
            store.request(key)
            exists = key != role or phase != "create"
            owner = Owner(operation, key, present=exists)
            owner.details["plan"] = store.review()["header"]["plan_sha256"]
            owner.details["id"] = f"{i + 1:064x}"
            owner.details["image"] = images["postgres" if key == "db" else "runner"]
            owner.details["running"] = key == "db" and (key != role or phase == "running")
            owner.named = owner.labelled = owner.known = (
                (owner.details["id"] + "\n").encode() if exists else b""
            )
            self.owners[key] = owner
            if exists:
                store.append("observed", {"role": key, "resource_id": owner.details["id"]})
            if key == "db" and (role != "db" or phase == "running"):
                store.append(
                    "database_start_requested",
                    {
                        "role": key,
                        "recipe_sha256": "1" * 64,
                        "gates_sha256": "2" * 64,
                        "policy_sha256": "3" * 64,
                    },
                )
                store.append(
                    "database_runtime_observed", {"role": key, "runtime_evidence_sha256": "4" * 64}
                )
        docker.responses["containers", None] = b"".join(
            owner.named for owner in self.owners.values()
        )
        docker.responses["consumers", "postgres-data"] = self.owners["db"].named
        docker.responses["consumers", "journal"] = (
            self.owners[role].named if phase == "start" and role.startswith("journal-") else b""
        )

    def query(self, kind, operation, plan, role, known_id=None):
        return self.owners[role].query(kind, operation, plan, role, known_id)


def check(diagnostic, store, role, phase):
    folder, report, selected, _, options = diagnostic
    world = World(store, options["docker"], selected, role, phase)
    result = review.recheck(
        folder,
        report["plan_sha256"],
        store,
        role,
        phase,
        repo=options["repo"],
        docker=options["docker"],
        ownership_docker=world,
    )
    return result, world


@pytest.mark.parametrize(
    "role,phase",
    [
        (role, phase)
        for role in (
            "journal-before",
            "journal-after",
            "database-review-before",
            "database-review-after",
        )
        for phase in ("create", "start")
    ]
    + [("db", phase) for phase in ("create", "start", "running")],
)
def test_owned_recheck_uses_pinned_build_code_identity_and_exact_consumers(
    diagnostic, tmp_path, role, phase
):
    _, report, _, _, _ = diagnostic
    with ActivationIntents(tmp_path / "intents") as store:
        store.begin(report["plan_id"], report["plan_sha256"], report["scope_sha256"])
        result, world = check(diagnostic, store, role, phase)
        assert result["local_runner_build_inputs_verified"]
        assert result["owned_metadata"]["project_membership_verified"]
        assert result["operation_id"] == store.summary()["id"]
        assert all(result[key] is False for key in review.plan.FLAGS)
        # Public planning still refuses to adopt a running owned project.
        folder, _, _, _, options = diagnostic
        if world.docker.responses["containers", None]:
            with pytest.raises(ValueError):
                review.plan.recheck(
                    folder, report["plan_sha256"], repo=options["repo"], docker=world.docker
                )
        else:
            assert (
                review.plan.recheck(
                    folder, report["plan_sha256"], repo=options["repo"], docker=world.docker
                )["authorization_verified"]
                is False
            )


@pytest.mark.parametrize("scene", ["id", "plan", "scope", "extra_role", "wrong_phase"])
def test_wrong_owned_context_fails_before_input_queries(diagnostic, tmp_path, monkeypatch, scene):
    folder, report, _, _, options = diagnostic
    with ActivationIntents(tmp_path / "intents") as store:
        store.begin(
            uuid4().hex if scene == "id" else report["plan_id"],
            "f" * 64 if scene == "plan" else report["plan_sha256"],
            "f" * 64 if scene == "scope" else report["scope_sha256"],
        )
        if scene == "extra_role":
            store.request("redis")
        monkeypatch.setattr(review, "inputs", lambda *a, **k: pytest.fail("Input access forbidden"))
        with pytest.raises(ValueError, match="owned_context"):
            review.recheck(
                folder,
                report["plan_sha256"],
                store,
                "db",
                "exited" if scene == "wrong_phase" else "create",
                repo=options["repo"],
            )


@pytest.mark.parametrize("scene", ["consumer", "expiry", "code", "deadline"])
def test_mutation_or_expiry_during_native_review_blocks_new_gate(
    diagnostic, tmp_path, monkeypatch, scene
):
    folder, report, selected, _, options = diagnostic
    with ActivationIntents(tmp_path / "intents") as store:
        store.begin(report["plan_id"], report["plan_sha256"], report["scope_sha256"])
        world = World(store, options["docker"], selected, "db", "create")
        original = review.active.review
        ticks = [0.0]
        monkeypatch.setattr(review, "time", SimpleNamespace(monotonic=lambda: ticks[0]))

        def changed(*args, **kwargs):
            if scene == "consumer":
                options["docker"].responses["consumers", "postgres-data"] = (
                    "f" * 64 + "\n"
                ).encode()
            result = original(*args, **kwargs)
            if scene == "expiry":
                future = review.plan.pki.clock() + timedelta(days=2)
                monkeypatch.setattr(review.plan.pki, "clock", lambda: future)
            elif scene == "code":
                (options["repo"] / "pyproject.toml").write_text("changed during review")
            elif scene == "deadline":
                ticks[0] = 31.0
            return result

        monkeypatch.setattr(review.active, "review", changed)
        with pytest.raises(ValueError):
            review.recheck(
                folder,
                report["plan_sha256"],
                store,
                "db",
                "create",
                repo=options["repo"],
                docker=options["docker"],
                ownership_docker=world,
            )
        assert store.review()["resources"]["db"]["state"] == "REQUESTED"
