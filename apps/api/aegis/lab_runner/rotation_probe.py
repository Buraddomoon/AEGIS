"""Closed in-container administrative rotation phases; no jobs, targets or SQL input."""

import argparse
import json
import os
import socket
import ssl
import stat
import sys
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

from aegis.domain.validation import digest
from aegis.lab_runner import activation_review as reviews
from aegis.lab_runner.persisted_probe import _unique
from aegis.lab_runner.protocol import TEST_ID, RunnerIdentity

FORMAT = "aegis-rotation-admin-request/3"
RESULT = "aegis-rotation-admin-result/3"
MODES = ("review-before", "identity-before", "binding", "preflight", "review-after")
LIMIT = 4 * 1024**2
STATE = Path("/state")
CONNECTION = Path("/run/secrets/controller_connection")
PREVIOUS_CA = Path("/run/secrets/rotation_previous_server_ca")
TABLES = frozenset(
    "alembic_version approvals assets attack_techniques audit_events campaign_runs "
    "campaign_tests campaigns detection_evidence detection_rules execution_steps "
    "lab_verifications laboratories linux_lab_bindings rule_versions runner_cleanups "
    "runner_dispatches runner_receipts schedule_authorizations schedule_occurrences "
    "schedules sessions telemetry_events test_definitions test_executions users "
    "validation_results".split()
)


def previous_trust_rejected(config):
    """Only an issuer/path rejection proves this control; expiry/EOF are insufficient."""
    context = ssl.create_default_context(cafile=str(PREVIOUS_CA))
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(str(config.client_cert), str(config.client_key))
    try:
        with socket.create_connection(("192.168.253.2", 8443), timeout=2) as raw:
            with context.wrap_socket(raw, server_hostname="192.168.253.2"):
                return False
    except ssl.SSLCertVerificationError as error:
        # OpenSSL path-building failures; do not attribute certificate expiry,
        # transport errors or an ambiguous EOF to rejection of the old trust.
        return error.verify_code in {18, 19, 20, 21}


def decode(raw, expected):
    if type(raw) is not bytes or len(raw) > LIMIT:
        raise ValueError("rotation_admin_input_limit")
    value = json.loads(raw, object_pairs_hook=_unique)
    fields = {
        "format",
        "operation_id",
        "plan_sha256",
        "scope_sha256",
        "mode",
        "expires_at",
        "identity",
        "old_descriptor_sha256",
        "new_descriptor_sha256",
        "actor_id",
        "registration",
        "baseline",
        "database_password",
    }
    if not isinstance(value, dict) or set(value) != fields or value["format"] != FORMAT:
        raise ValueError("rotation_admin_context_invalid")
    if digest({k: v for k, v in value.items() if k != "database_password"}) != expected:
        raise ValueError("rotation_admin_context_mismatch")
    for key in ("operation_id", "actor_id"):
        if str(UUID(value[key])) != value[key]:
            raise ValueError("rotation_admin_identity_invalid")
    for key in ("plan_sha256", "scope_sha256", "old_descriptor_sha256", "new_descriptor_sha256"):
        if (
            not isinstance(value[key], str)
            or len(value[key]) != 64
            or any(c not in "0123456789abcdef" for c in value[key])
        ):
            raise ValueError("rotation_admin_hash_invalid")
    expires = datetime.fromisoformat(value["expires_at"])
    if (
        expires.utcoffset() != UTC.utcoffset(None)
        or not 0 < (expires - datetime.now(UTC)).total_seconds() <= 240
    ):
        raise ValueError("rotation_admin_deadline_invalid")
    identity = RunnerIdentity.model_validate(value["identity"])
    if (
        identity.model_dump(mode="json") != value["identity"]
        or identity.tests != (TEST_ID,)
        or value["mode"] not in MODES
    ):
        raise ValueError("rotation_admin_identity_invalid")
    password = value["database_password"]
    if type(password) is not str or not 1 <= len(password) <= 512 or "\0" in password:
        raise ValueError("rotation_admin_secret_invalid")
    if value["mode"] == "review-before":
        if value["baseline"] is not None:
            raise ValueError("rotation_admin_baseline_not_allowed")
    else:
        baseline = value["baseline"]
        if not isinstance(baseline, dict) or set(baseline) != {"bundle", "inventory_sha256"}:
            raise ValueError("rotation_admin_baseline_required")
        baseline_identity, _ = reviews.persisted_review.expected_proofs(
            baseline["bundle"], digest(baseline["bundle"])
        )
        if (
            baseline_identity != identity
            or baseline["bundle"]["old_descriptor_sha256"] != value["old_descriptor_sha256"]
        ):
            raise ValueError("rotation_admin_baseline_mismatch")
        if len(baseline["inventory_sha256"]) != 64 or any(
            c not in "0123456789abcdef" for c in baseline["inventory_sha256"]
        ):
            raise ValueError("rotation_admin_inventory_invalid")
    return value


def _engine(password, write):
    if any(key.startswith("PG") for key in os.environ):
        raise ValueError("rotation_admin_ambient_libpq")
    from sqlalchemy import URL, create_engine
    from sqlalchemy.pool import NullPool

    return create_engine(
        URL.create(
            "postgresql+psycopg",
            username="aegis_app",
            password=password,
            host="127.0.0.1",
            port=5432,
            database="aegis",
        ),
        connect_args={
            "hostaddr": "127.0.0.1",
            "connect_timeout": 3,
            "passfile": "/dev/null",
            "options": "-c search_path=public -c statement_timeout=15000 -c lock_timeout=3000 -c idle_in_transaction_session_timeout=15000 -c row_security=off -c default_transaction_read_only="
            + ("off" if write else "on"),
        },
        poolclass=NullPool,
        echo=False,
        hide_parameters=True,
    )


def _guard(value):
    if datetime.now(UTC) >= datetime.fromisoformat(value["expires_at"]):
        raise ValueError("rotation_admin_deadline_expired")
    from aegis import linux_labs

    if linux_labs.configured_hash() != value["new_descriptor_sha256"]:
        raise ValueError("rotation_admin_deployment_changed")


def _bundle(engine, identity, descriptor):
    from aegis.lab_runner.persisted_probe import _require_fixed_database

    return reviews.persisted_review.collect(
        engine, identity, descriptor, verify=_require_fixed_database
    )


def _baseline_match(value, bundle, inventory=None, *, after=False):
    original = value["baseline"]
    candidate = json.loads(json.dumps(bundle))
    if after:
        if candidate["environment_version"] != original["bundle"]["environment_version"] + 1:
            raise ValueError("rotation_admin_version_changed")
        candidate["old_descriptor_sha256"] = value["old_descriptor_sha256"]
        candidate["environment_version"] -= 1
        candidate["review"]["environment_version"] -= 1
    if reviews.stable_sha256(candidate) != reviews.stable_sha256(original["bundle"]):
        raise ValueError("rotation_admin_history_changed")
    if inventory is not None and inventory != original["inventory_sha256"]:
        raise ValueError("rotation_admin_journal_changed")


def execute(value):
    from sqlalchemy import inspect, select, text
    from sqlalchemy.orm import Session

    from aegis import binding_review, linux_labs, schemas
    from aegis.config import settings
    from aegis.lab_runner.persisted_probe import _require_schema
    from aegis.models import Laboratory, User

    settings().linux_runner_config = CONNECTION
    _guard(value)
    identity = RunnerIdentity.model_validate(value["identity"])
    mode = value["mode"]
    if mode == "identity-before":
        remote = linux_labs.client()
        try:
            if remote.preflight() != identity:
                raise ValueError("rotation_admin_remote_identity_mismatch")
            if not previous_trust_rejected(linux_labs.connection()):
                raise ValueError("rotation_admin_previous_trust_unconfirmed")
        finally:
            remote.close()
        _guard(value)
        return {
            "candidate_identity_verified": True,
            "previous_server_trust_rejected": True,
            "jobs_requested": False,
        }
    engine = _engine(value["database_password"], mode in {"binding", "preflight"})
    try:
        with engine.connect() as connection:
            # The actual retained Lab predates a0: exactly the d446 relation set.
            # These closed helpers do not load the normal API/worker entrypoints.
            _require_schema(connection, "public")
            if set(inspect(connection).get_table_names()) != TABLES:
                raise ValueError("rotation_admin_d446_profile_required")
        descriptor = (
            value["new_descriptor_sha256"]
            if mode in {"preflight", "review-after"}
            else value["old_descriptor_sha256"]
        )
        bundle = _bundle(engine, identity, descriptor)
        if mode in {"review-before", "binding", "review-after"}:
            _, proofs = reviews.persisted_review.expected_proofs(bundle, digest(bundle))
            first = reviews.continuity.review(STATE, identity, proofs)
            second = reviews.continuity.review(STATE, identity, proofs)
            following = _bundle(engine, identity, descriptor)
            if first != second or not reviews.unchanged(bundle, following):
                raise ValueError("rotation_admin_continuity_changed")
            inventory = first["inventory_sha256"]
            if mode == "review-before":
                _guard(value)
                return {"baseline": {"bundle": bundle, "inventory_sha256": inventory}}
            _baseline_match(value, bundle, inventory, after=mode == "review-after")
            if mode == "review-after":
                _guard(value)
                return {
                    "continuity_verified": True,
                    "inventory_sha256": inventory,
                    "environment_version": bundle["environment_version"],
                }
        else:
            _baseline_match(value, bundle, after=True)
        _guard(value)
        with Session(engine, expire_on_commit=False) as db:
            db.execute(text("SET LOCAL statement_timeout='15s'"))
            actor = db.get(User, value["actor_id"])
            if actor is None or not actor.active or actor.role != "administrator":
                raise ValueError("rotation_admin_active_administrator_required")
            if mode == "binding":
                reviewed = reviews.ContinuityReview(
                    identity,
                    descriptor,
                    bundle["environment_version"],
                    digest(bundle),
                    digest(following),
                    reviews.stable_sha256(bundle),
                    inventory,
                    len(bundle["proofs"]),
                )
                lab = linux_labs.register(
                    db,
                    schemas.LinuxRegistration.model_validate(value["registration"]),
                    actor,
                    continuity_review=reviewed,
                )
            else:
                lab = db.scalar(
                    select(Laboratory).where(Laboratory.id == str(identity.laboratory_id))
                )
                if lab is None or lab.authorized:
                    raise ValueError("rotation_admin_revoked_lab_required")
                # No lab lock across TLS IO; preflight refreshes under lock itself.
                verification = linux_labs.preflight(db, lab, actor)
                if not verification.success:
                    raise ValueError("rotation_admin_preflight_unconfirmed")
                lab = db.scalar(
                    select(Laboratory)
                    .where(Laboratory.id == lab.id)
                    .with_for_update()
                    .execution_options(populate_existing=True)
                )
                binding_review.require_review(db, lab)
            if (
                lab.authorized
                or lab.environment_version != value["baseline"]["bundle"]["environment_version"] + 1
            ):
                raise ValueError("rotation_admin_revoked_binding_changed")
            _guard(value)
            return {
                "binding_registered_revoked": True,
                "environment_version": lab.environment_version,
                "preflight_verified": mode == "preflight",
            }
    finally:
        engine.dispose()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--context-sha256", required=True)
    args = parser.parse_args(argv)
    try:
        if (
            os.geteuid() != 10001
            or not Path("/.dockerenv").is_file()
            or not stat.S_ISFIFO(os.fstat(sys.stdin.fileno()).st_mode)
        ):
            raise ValueError("rotation_admin_private_container_pipe_required")
        value = decode(sys.stdin.buffer.read(LIMIT + 1), args.context_sha256)
        result = execute(value)
        response = {
            "format": RESULT,
            "context_sha256": args.context_sha256,
            "mode": value["mode"],
            "status": "phase_verified",
            "result": result,
        }
        raw = json.dumps(response, sort_keys=True).encode()
        if len(raw) > LIMIT:
            raise ValueError("rotation_admin_output_limit")
    except Exception:
        print(json.dumps({"format": RESULT, "status": "phase_unconfirmed"}))
        return 1
    sys.stdout.buffer.write(raw + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
