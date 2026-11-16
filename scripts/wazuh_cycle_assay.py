"""Single-attempt coordinator over reviewed existing Wazuh history.

Internal operator primitive, no activation CLI. The native caller must verify
physical continuity, PKI/runtime, schema/catalog and the specific authorization
in recheck; a fixture/JSON checklist cannot authorize a marker. Clients must be
separate authenticated accounts on the fixed local API. No account bootstrap,
registration, migration, seed or infrastructure startup occurs here.
"""

import hashlib
import re
import time
from pathlib import Path
from uuid import UUID, uuid4

import runner_pki as fs
import wazuh_pki as files
from aegis.domain.validation import digest
from aegis.lab_runner.protocol import JobView, RunnerIdentity
from smoke_wazuh_platform import TERMINAL, Intent, request
from wazuh_cycle_scope import CycleProfile

FORMAT = "aegis-wazuh-cycle-baseline/1"
API = "http://localhost:18786/api/v1/"
FIELDS = {
    "format",
    "review_id",
    "identity",
    "runs",
    "environment_version",
    "runner_descriptor_sha256",
    "telemetry_scope_sha256",
    "historical_intent_sha256",
    "profile_sha256",
}


def check_baseline(baseline, expected_sha256, profile):
    profile.check()
    if (
        not isinstance(baseline, dict)
        or digest(baseline) != expected_sha256
        or set(baseline) != FIELDS
    ):
        raise ValueError("cycle_baseline_integrity_mismatch")
    identity = RunnerIdentity.model_validate(baseline["identity"])
    if (
        baseline["format"] != FORMAT
        or baseline["review_id"] != profile.review_id
        or baseline["profile_sha256"] != digest(profile.document())
        or digest(identity.model_dump(mode="json")) != digest(baseline["identity"])
        or type(baseline["environment_version"]) is not int
        or baseline["environment_version"] < 1
        or not isinstance(baseline["runs"], dict)
        or not 1 <= len(baseline["runs"]) <= 100
    ):
        raise ValueError("cycle_known_history_required")
    for identifier, fingerprint in baseline["runs"].items():
        if str(UUID(identifier)) != identifier or not re.fullmatch(r"[a-f0-9]{64}", fingerprint):
            raise ValueError("cycle_history_identity_invalid")
    for name in ("runner_descriptor_sha256", "telemetry_scope_sha256", "historical_intent_sha256"):
        if not isinstance(baseline[name], str) or not re.fullmatch(r"[a-f0-9]{64}", baseline[name]):
            raise ValueError("cycle_baseline_fingerprint_invalid")
    original = fs.read(profile.source / "assay-intent.jsonl", modes=(0o600,))
    if hashlib.sha256(original).hexdigest() != baseline["historical_intent_sha256"]:
        raise ValueError("cycle_historical_intent_changed")
    return identity


def check_history(admin, baseline, *, new_run=None):
    page = request(admin, "GET", "/executions?offset=0&limit=100")
    expected = set(baseline["runs"]) | ({new_run} if new_run else set())
    items = page["items"]
    if (
        type(page["total"]) is not int
        or page["total"] != len(expected)
        or len(items) != len(expected)
        or {item["id"] for item in items} != expected
    ):
        raise ValueError("cycle_history_changed_or_incomplete")
    for identifier, fingerprint in baseline["runs"].items():
        detail = request(admin, "GET", "/executions/" + identifier)
        if detail["state"] not in TERMINAL - {"CLEANUP_FAILED"} or digest(detail) != fingerprint:
            raise ValueError("cycle_historical_execution_changed")


def _scope(run, baseline, identity):
    scope = run["scope"]
    tests = scope["test_definitions"]
    if (
        run["synthetic"] is not False
        or scope["synthetic"] is not False
        or scope["mode"] != "linux"
        or scope["laboratory_id"] != str(identity.laboratory_id)
        or scope["asset_id"] != str(identity.asset_id)
        or scope["environment_version"] != baseline["environment_version"]
        or digest(scope) != run["scope_hash"]
        or digest(scope["runner"]) != baseline["runner_descriptor_sha256"]
        or digest(scope["telemetry"]) != baseline["telemetry_scope_sha256"]
        or scope["telemetry"]["provider"] != "wazuh-indexer"
        or len(tests) != 1
        or tests[0]["id"] != "linux-file-marker-v1"
        or tests[0]["technique_id"] is not None
        or tests[0]["expected_rule"] != "100200"
    ):
        raise ValueError("cycle_requested_scope_differs_from_review")


def cleanup_confirmed(detail, identity):
    """Terminal state alone never permits removing access to recovery."""
    try:
        if detail["synthetic"] is not False or len(detail["executions"]) != 1:
            return False
        item = detail["executions"][0]
        content = item["runner_cleanup"]["content"]
        proof = JobView.model_validate(content)
        return (
            detail["state"] in TERMINAL - {"CLEANUP_FAILED"}
            and item["synthetic"] is False
            and proof.cleanup_state == "CLEANED"
            and digest(content) == item["runner_cleanup"]["sha256"]
            and digest(proof.spec.model_dump(mode="json")) == proof.spec_hash
            and str(proof.spec.job_id) == item["id"]
            and proof.spec.marker == item["marker"]
            and proof.spec.scope_hash == detail["scope_hash"]
            and all(
                getattr(proof.spec, key) == getattr(identity, key)
                for key in ("runner_id", "laboratory_id", "asset_id")
            )
        )
    except (KeyError, TypeError, ValueError, AttributeError):
        return False


def run_once(
    admin, operator, profile: CycleProfile, baseline, expected_sha256, root: Path, *, recheck
):
    """One new campaign/run/start; any ambiguity retains its deterministic intent.

    recheck is supplied by the trusted native coordinator, not deserialized from
    input. It must raise if any technical or human authorization gate is stale.
    The caller retains temporary accounts until read-only UI/export verification
    or safe recovery; this function never disables recovery access implicitly.
    """
    identity = check_baseline(baseline, expected_sha256, profile)
    if (
        str(admin.base_url) != API
        or str(operator.base_url) != API
        or admin is operator
        or not callable(recheck)
    ):
        raise ValueError("cycle_distinct_fixed_local_clients_required")
    root = fs.absolute(root)
    for protected in (profile.source, profile.runner_candidate, profile.service_candidate):
        files.separate(protected, root)
    root = fs.private_directory(root, create=True)
    # The package ID selects a single immutable claim, even on failure before
    # start. A new directory/ID requires a new reviewed package and approval.
    directory = root / profile.review_id
    directory.mkdir(mode=0o700)
    fs.sync(root)
    intent = Intent(directory / "attempt.jsonl")
    run = detail = None
    authorization_attempted = started = False
    laboratory = str(identity.laboratory_id)
    try:
        intent.append(
            "CYCLE_CLAIMED",
            baseline_sha256=expected_sha256,
            review_id=profile.review_id,
            historical_runs=sorted(baseline["runs"]),
            max_markers=1,
        )
        recheck(stage="before_review", run_id=None)
        admin_identity = request(admin, "GET", "/auth/me")
        operator_identity = request(operator, "GET", "/auth/me")
        if (
            admin_identity["id"] == operator_identity["id"]
            or admin_identity["role"] != "administrator"
            or operator_identity["role"] != "operator"
            or not all(user["active"] is True for user in (admin_identity, operator_identity))
        ):
            raise ValueError("cycle_active_distinct_operator_and_administrator_required")
        check_history(admin, baseline)
        labs = request(admin, "GET", "/labs")["items"]
        matches = [item for item in labs if item["id"] == laboratory]
        if len(matches) != 1:
            raise ValueError("cycle_original_lab_missing_or_duplicated")
        lab = matches[0]
        if (
            lab["id"] != laboratory
            or lab["kind"] != "linux"
            or lab["authorized"] is not False
            or lab["active_run_id"] is not None
            or lab["environment_version"] != baseline["environment_version"]
        ):
            raise ValueError("cycle_original_revoked_idle_lab_required")
        binding = request(admin, "GET", f"/labs/{laboratory}/binding-review")
        if binding["blockers"] or binding["dispatch_history_complete"] is not True:
            raise ValueError("cycle_persisted_binding_review_blocked")
        if request(admin, "POST", "/connectors/wazuh/test")["status"] != "connected":
            raise ValueError("cycle_indexer_connection_unconfirmed")
        if (
            request(admin, "POST", f"/labs/{laboratory}/preflight", {"confirm": True})["success"]
            is not True
        ):
            raise ValueError("cycle_runner_preflight_unconfirmed")
        recheck(stage="before_authorization", run_id=None)
        intent.append("LAB_AUTHORIZATION_INTENT", laboratory_id=laboratory)
        authorization_attempted = True
        request(admin, "PATCH", f"/labs/{laboratory}/authorization", {"authorized": True})
        intent.append("CAMPAIGN_REQUEST_INTENT")
        campaign = request(
            operator,
            "POST",
            "/campaigns",
            {
                "name": "Wazuh · tentativa única " + profile.review_id,
                "objective": "Validar o pipeline da regra própria 100200 para um marcador benigno; zero técnicas ATT&CK avaliadas e sem inferência de eficácia geral.",
                "laboratory_id": laboratory,
                "test_ids": ["linux-file-marker-v1"],
            },
        )
        key = uuid4().hex
        intent.append("RUN_REQUEST_INTENT", campaign_id=campaign["id"], idempotency_key=key)
        run = request(
            operator, "POST", f"/campaigns/{campaign['id']}/runs", {"idempotency_key": key}
        )
        if str(UUID(run["id"])) != run["id"] or run["id"] in baseline["runs"]:
            raise ValueError("cycle_new_run_identity_required")
        intent.append("RUN_CREATED", run_id=run["id"], scope_hash=run["scope_hash"])
        _scope(run, baseline, identity)
        request(
            admin,
            "POST",
            f"/executions/{run['id']}/approve",
            {
                "confirm_scope_hash": run["scope_hash"],
                "confirm_real_execution": True,
                "validity_minutes": 2,
                "max_duration_seconds": 120,
            },
        )
        check_history(admin, baseline, new_run=run["id"])
        recheck(stage="before_start", run_id=run["id"])
        intent.append("START_INTENT", run_id=run["id"], scope_hash=run["scope_hash"])
        started = True
        request(operator, "POST", f"/executions/{run['id']}/start", {"confirm": True})
        until = time.monotonic() + 150
        while time.monotonic() < until:
            detail = request(admin, "GET", "/executions/" + run["id"])
            if detail["state"] in TERMINAL:
                break
            time.sleep(0.5)
        files.write_json(directory / "execution.json", detail)
        if detail is None or detail["state"] not in TERMINAL:
            raise ValueError("cycle_terminal_result_unconfirmed")
        if detail["id"] != run["id"] or detail["scope_hash"] != run["scope_hash"]:
            raise ValueError("cycle_captured_execution_identity_changed")
        check_history(admin, baseline, new_run=run["id"])
        safe = cleanup_confirmed(detail, identity)
        intent.append(
            "RESULT_CAPTURED",
            run_id=run["id"],
            result_sha256=digest(detail),
            physical_cleanup_confirmed=safe,
        )
        if not safe:
            raise ValueError("cycle_original_recovery_required")
        return {
            "run_id": run["id"],
            "execution_path": str(directory / "execution.json"),
            "cleanup_confirmed": True,
            "ui_exports_verified": False,
        }
    except BaseException:
        # Even a lost start response or interruption keeps the account access,
        # run ID and intent needed to inspect/recover the original attempt.
        intent.append(
            "RECOVERY_REQUIRED" if started else "PREPARATION_STOPPED",
            run_id=run["id"] if run else None,
        )
        raise
    finally:
        try:
            if authorization_attempted:
                intent.append("LAB_REVOCATION_INTENT", laboratory_id=laboratory)
                response = request(
                    admin, "PATCH", f"/labs/{laboratory}/authorization", {"authorized": False}
                )
                if response.get("authorized") is not False:
                    raise ValueError("cycle_lab_revocation_unconfirmed")
                intent.append("LAB_REVOKED", laboratory_id=laboratory)
        finally:
            intent.close()
