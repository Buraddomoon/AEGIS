"""Closed two-host synthetic recovery contract; no host effects or credentials."""

import hashlib
import json
import re
from datetime import datetime, timedelta

FORMAT = "aegis-operational-demo-recovery/1"
PROFILE = "two-host-synthetic-demo/1"
FILES = {"bundle.json", "manifest.json", "database.dump", "images.tar"}
MAX_BYTES = 4 * 1024**3


def fingerprint(value):
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def timestamp(value):
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.utcoffset() != timedelta(0):
        raise ValueError("UTC timestamp required")
    return result


def image(value):
    if (
        set(value) != {"id", "os", "architecture"}
        or not re.fullmatch(r"sha256:[a-f0-9]{64}", value["id"])
        or value["os"] != "linux"
        or value["architecture"] != "amd64"
    ):
        raise ValueError("Image identity refused")
    return value


def validate_plan(plan):
    if (
        set(plan)
        != {
            "format",
            "profile",
            "workflow_run",
            "source_commit",
            "approved_by",
            "prepared_at",
            "expires_at",
            "recipient",
            "images",
            "schema",
            "source_host",
            "destination",
            "budget",
            "secret_name",
        }
        or plan["format"] != FORMAT
        or plan["profile"] != PROFILE
        or not re.fullmatch(r"[1-9][0-9]{5,19}", plan["workflow_run"])
        or not re.fullmatch(r"[a-f0-9]{40}", plan["source_commit"])
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}", plan["approved_by"])
        or not re.fullmatch(r"[a-f0-9]{64}", plan["source_host"])
        or not re.fullmatch(r"age1[0-9a-z]{58}", plan["recipient"])
        or plan["destination"] != "fresh-ubuntu-24.04-job-destination-same-workflow"
        or plan["secret_name"] != "AEGIS_RECOVERY29_" + plan["workflow_run"]
        or not re.fullmatch(r"[a-z0-9]{12}", plan["schema"])
        or plan["budget"]
        != {
            "source_normal_api": 1,
            "source_worker": 0,
            "destination_restores": 3,
            "destination_runs": 1,
            "destination_synthetic_tests": 4,
            "originals": False,
            "external_targets": False,
            "persistent_service": False,
            "encrypted_artifact_days": 1,
            "maximum_bytes": MAX_BYTES,
        }
        or set(plan["images"]) != {"application", "postgres", "redis"}
        or not timedelta(0)
        < timestamp(plan["expires_at"]) - timestamp(plan["prepared_at"])
        <= timedelta(minutes=45)
    ):
        raise ValueError("Recovery plan refused")
    for item in plan["images"].values():
        image(item)
    return plan


def approval_text(plan):
    validate_plan(plan)
    return (
        f"AEGIS-29-AUTHORIZE {fingerprint(plan)}\n"
        f"workflow_run={plan['workflow_run']}\n"
        "profile=two-host-synthetic-demo/1\n"
        "source_fixture_fence_and_disposal=true\n"
        "encrypted_artifact_transfer=true\n"
        "temporary_destination_secret=true\n"
        "destination_restores=3\ndestination_runs=1\n"
        "internal_cutover_and_cleanup=true\noriginals=false"
    )


def approved(comment, plan, instant):
    try:
        return (
            comment["user"]["login"] == plan["approved_by"]
            and comment.get("body", "").strip() == approval_text(plan)
            and timestamp(plan["prepared_at"])
            <= timestamp(comment["created_at"])
            <= instant
            < timestamp(plan["expires_at"]) - timedelta(minutes=10)
        )
    except (KeyError, TypeError, ValueError):
        return False


def validate_members(members):
    """Only four fixed regular files, no extraction before complete age authentication."""
    names = set()
    total = 0
    for member in members:
        if (
            member.name not in FILES
            or member.name in names
            or not member.isfile()
            or member.issparse()
            or member.pax_headers
            or not 0 < member.size <= MAX_BYTES
        ):
            raise ValueError("Recovery archive entry refused")
        names.add(member.name)
        total += member.size
        if total > MAX_BYTES:
            raise ValueError("Recovery archive size refused")
    if names != FILES:
        raise ValueError("Recovery archive incomplete")


def validate_envelope(value, *, expected_hash, plan_hash, run, source_commit, host):
    if (
        fingerprint(value) != expected_hash
        or value.get("format") != FORMAT
        or value.get("synthetic") is not True
        or value.get("source_cleaned") is not True
        or fingerprint(value["plan"]) != plan_hash
        or value["plan"]["workflow_run"] != run
        or value["plan"]["source_commit"] != source_commit
        or value["plan"]["source_host"] == host
        or not re.fullmatch(r"[a-f0-9]{64}", host)
        or not re.fullmatch(r"[a-f0-9]{64}", value["ciphertext_sha256"])
        or not 0 < value["ciphertext_bytes"] <= MAX_BYTES
    ):
        raise ValueError("Recovery transport identity refused")
    validate_plan(value["plan"])
    return value


def timing(fenced_at, snapshot_at, accepted_at):
    fence, snapshot, accepted = map(timestamp, (fenced_at, snapshot_at, accepted_at))
    if not fence <= snapshot <= accepted or accepted - fence > timedelta(hours=2):
        raise ValueError("Recovery clock order refused")
    return {
        "rpo_observed_seconds": 0,
        "rpo_basis": "final_snapshot_after_source_fence_no_later_writes",
        "rto_observed_seconds": round((accepted - fence).total_seconds(), 3),
        "rto_basis": "source_stop_requested_to_verified_destination_flow_provider_utc_clocks",
        "sla": False,
    }
