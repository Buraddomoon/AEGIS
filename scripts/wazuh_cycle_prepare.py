"""Prepare/recheck an integrated Wazuh Compose package. Never starts services."""

import argparse
import hashlib
import json
import os
import subprocess
from pathlib import Path
from uuid import uuid4

import runner_activation_metadata as metadata
import runner_pki as runner
import wazuh_pki as services
import wazuh_pki_rotation as rotation
from aegis.domain.validation import digest
from aegis.lab_runner.wazuh_network_profile import RUNNER_URL
from wazuh_cycle_scope import CycleProfile, scoped_compose

FORMAT = "aegis-wazuh-cycle-package/1"
PENDING = [
    "specific_native_preparation_authorization",
    "host_resources_and_subnets",
    "original_database_and_journal_binding",
    "journal_and_observation_log_continuity",
    "explicit_versioned_catalog_adoption",
    "runtime_mounts_tls_acl_rule_agent_observer",
    "reviewed_historical_execution_baseline",
    "specific_single_attempt_authorization",
]
SOURCE_FILES = (
    "scripts/wazuh_cycle_prepare.py",
    "scripts/wazuh_cycle_scope.py",
    "scripts/wazuh_cycle_assay.py",
    "scripts/wazuh_cycle_catalog.py",
    "scripts/wazuh_cycle_continuity.py",
    "scripts/inspect_wazuh_lab.py",
    "scripts/wazuh_cycle_resources.py",
)


def source_snapshot(source):
    result = rotation.snapshot(source)
    result["cycle_tools"] = {
        name: hashlib.sha256(runner.read(services.ROOT / name)).hexdigest() for name in SOURCE_FILES
    }
    return result


def image_snapshot(images):
    result = {}
    for name, reference in sorted(images.items()):
        item = metadata.document(metadata._execute(metadata.command("image", reference)))
        if item["id"] != reference or item["os"] != "linux" or item["architecture"] != "amd64":
            raise ValueError("cycle_local_linux_amd64_image_required")
        result[name] = item
    return result


def render(source):
    # Only the Compose config subcommand. Explicit private env and a clean
    # process environment keep unrelated exported secrets/targets out of it.
    command = [
        "/usr/bin/docker",
        "--host",
        "unix:///var/run/docker.sock",
        "compose",
        "--env-file",
        str(source / "lab.env"),
        "-p",
        "aegis-wazuh-lab",
    ]
    for name in rotation.BASE_COMPOSE:
        command.extend(("-f", str(services.ROOT / name)))
    result = subprocess.run(
        [*command, "config", "--format", "json"],
        cwd=services.ROOT,
        env={"PATH": "/usr/bin:/bin", "HOME": str(source)},
        capture_output=True,
        timeout=15,
        check=True,
    )
    if len(result.stdout) > 1024**2:
        raise ValueError("cycle_compose_output_limit")
    return json.loads(result.stdout)


def candidates(profile, runner_sha256, services_sha256):
    checked = runner.verify(profile.source / "runner", profile.runner_candidate, runner_sha256)
    current, _ = runner.inventory(profile.runner_candidate, current=True)
    if current["connection"]["url"] != RUNNER_URL:
        raise ValueError("cycle_fixed_runner_candidate_required")
    checked_services = services.verify(profile.source, profile.service_candidate, services_sha256)
    if checked_services["native_blockers"]:
        raise ValueError("cycle_current_service_candidate_required")
    return {
        "runner": checked,
        "services": {key: value for key, value in checked_services.items() if key != "candidate"},
    }


def prepare(
    source,
    runner_candidate,
    runner_sha256,
    service_candidate,
    services_sha256,
    images,
    output_root,
    *,
    resource_profile="standard",
):
    profile = CycleProfile(
        uuid4().hex,
        runner.absolute(source),
        runner.absolute(runner_candidate),
        runner.absolute(service_candidate),
        dict(images),
        resource_profile,
    )
    profile.check()
    output_root = runner.absolute(output_root)
    for protected in (profile.source, profile.runner_candidate, profile.service_candidate):
        services.separate(protected, output_root)
    before = source_snapshot(profile.source)
    verified = candidates(profile, runner_sha256, services_sha256)
    local_images = image_snapshot(profile.images)
    compose = scoped_compose(render(profile.source), profile)
    output_root = runner.private_directory(output_root, create=True)
    directory = output_root / profile.review_id
    directory.mkdir(mode=0o700)
    # Compose includes original credentials. Only a private artifact is written;
    # the CLI returns paths/hashes/flags, never the rendered config or daemon text.
    services.write_json(directory / "compose.json", compose)
    plan = {
        "format": FORMAT,
        "profile": profile.document(),
        "runner_manifest_sha256": runner_sha256,
        "services_manifest_sha256": services_sha256,
        "candidates": verified,
        "source_snapshot": before,
        "images": local_images,
        "compose_sha256": digest(compose),
        "pending_native_gates": list(PENDING),
        "effects_authorized": False,
        "services_started": False,
        "marker_permitted": False,
    }
    if (
        source_snapshot(profile.source) != before
        or candidates(profile, runner_sha256, services_sha256) != verified
        or image_snapshot(profile.images) != local_images
    ):
        raise ValueError("cycle_inputs_changed_during_preparation")
    services.write_json(directory / "plan.json", plan)
    runner.sync(output_root)
    return {
        "status": "offline_cycle_package_prepared_not_authorized",
        "package_path": str(directory),
        "package_sha256": digest(plan),
        "pending_native_gates": list(PENDING),
        "marker_permitted": False,
    }


def recheck(directory, expected_sha256):
    directory = runner.private_directory(directory)
    if set(os.listdir(directory)) != {"plan.json", "compose.json"}:
        raise ValueError("cycle_package_partial_or_unexpected")
    plan = json.loads(runner.read(directory / "plan.json", modes=(0o600,), maximum=1024**2))
    if (
        digest(plan) != expected_sha256
        or plan["format"] != FORMAT
        or plan["pending_native_gates"] != PENDING
        or any(
            plan[key] is not False
            for key in ("effects_authorized", "services_started", "marker_permitted")
        )
    ):
        raise ValueError("cycle_package_integrity_mismatch")
    record = plan["profile"]
    profile = CycleProfile(
        record["review_id"],
        Path(record["source"]),
        Path(record["runner_candidate"]),
        Path(record["service_candidate"]),
        record["images"],
        record.get("resource_profile", "standard"),
    )
    profile.check()
    if directory.name != profile.review_id:
        raise ValueError("cycle_package_identity_mismatch")
    for protected in (profile.source, profile.runner_candidate, profile.service_candidate):
        services.separate(protected, directory)
    if (
        source_snapshot(profile.source) != plan["source_snapshot"]
        or candidates(profile, plan["runner_manifest_sha256"], plan["services_manifest_sha256"])
        != plan["candidates"]
        or image_snapshot(profile.images) != plan["images"]
    ):
        raise ValueError("cycle_package_inputs_changed")
    compose = json.loads(runner.read(directory / "compose.json", modes=(0o600,), maximum=1024**2))
    if digest(compose) != plan["compose_sha256"] or compose != scoped_compose(
        render(profile.source), profile
    ):
        raise ValueError("cycle_package_compose_changed")
    # Check source and certificate time after the final render, too.
    if (
        source_snapshot(profile.source) != plan["source_snapshot"]
        or candidates(profile, plan["runner_manifest_sha256"], plan["services_manifest_sha256"])
        != plan["candidates"]
    ):
        raise ValueError("cycle_package_inputs_changed")
    return {
        "status": "offline_cycle_package_verified_not_authorized",
        "package_sha256": expected_sha256,
        "pending_native_gates": list(PENDING),
        "marker_permitted": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    build = commands.add_parser("prepare")
    for name in ("source", "runner-candidate", "service-candidate", "images", "output-root"):
        build.add_argument("--" + name, type=Path, required=True)
    build.add_argument("--runner-sha256", required=True)
    build.add_argument("--services-sha256", required=True)
    build.add_argument(
        "--resource-profile", choices=("standard", "bounded-3360m/1"), default="standard"
    )
    check = commands.add_parser("recheck")
    check.add_argument("--package", type=Path, required=True)
    check.add_argument("--expected-sha256", required=True)
    args = parser.parse_args()
    try:
        result = (
            prepare(
                args.source,
                args.runner_candidate,
                args.runner_sha256,
                args.service_candidate,
                args.services_sha256,
                json.loads(runner.read(args.images, modes=(0o600,))),
                args.output_root,
                resource_profile=args.resource_profile,
            )
            if args.command == "prepare"
            else recheck(args.package, args.expected_sha256)
        )
    except (OSError, ValueError, KeyError, TypeError, AttributeError, subprocess.SubprocessError):
        print(
            json.dumps(
                {
                    "status": "rejected",
                    "reason": "Pacote Wazuh recusado; preservar origem/candidatos e revisar. Nenhum serviço iniciado.",
                    "marker_permitted": False,
                }
            )
        )
        return 1
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
