"""Closed #104 native assay on a fresh hosted Linux runner, after package approval.

prepare builds dedicated images and public fingerprints, never starts a Lab.
wait requires a later comment from the initiating human for the exact package.
run consumes a durable one-attempt fence before creating its own resources.
No original volume, journal, PKI, account or historical package is accepted.
"""

import argparse
import hashlib
import ipaddress
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import httpx
import init_linux_lab
from aegis.domain.validation import digest

ROOT = Path(__file__).resolve().parents[1]
PRIVATE = ROOT / ".local/scheduling104"
PUBLIC = ROOT / ".local/scheduling104-public"
ORIGIN = "http://192.168.253.12:8080"
SUBNETS = ("192.168.253.0/29", "192.168.253.8/29")
EFFECTS = 2
SLOT_INTERVAL = 60
RUN_SECONDS = 30
SCHEMA = "f3b28c5d901a"
SAFE_ENV = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}


class Blocked(ValueError):
    pass


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def write_new(path, value, *, public=False):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    raw = value if isinstance(value, bytes) else canonical(value)
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644 if public else 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    sync_directory(path.parent)


def sync_directory(path):
    directory = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def command(
    args,
    *,
    timeout=30,
    data=None,
    limit=4 * 1024**2,
    build_log=False,
    environment=None,
    redactions=(),
):
    result = subprocess.run(
        args, input=data, capture_output=True, timeout=timeout, env=environment or SAFE_ENV
    )
    if result.returncode or len(result.stdout) + len(result.stderr) > limit:
        if build_log or redactions:
            # Build inputs contain no secrets; browser diagnostics redact the
            # two own passwords before any bounded output reaches CI logs.
            diagnostic = (result.stdout + result.stderr).decode("utf-8", errors="replace")
            for value in redactions:
                diagnostic = diagnostic.replace(value, "[private]")
            print(diagnostic[-6000:], file=sys.stderr)
        raise Blocked("operation_unconfirmed_no_replay")
    return result.stdout


def docker(*args, timeout=30, data=None):
    with tempfile.TemporaryDirectory(prefix="scheduling104-docker-") as config:
        return command(
            ["/usr/bin/docker", "--config", config, "--host", "unix:///var/run/docker.sock", *args],
            timeout=timeout,
            data=data,
            build_log=bool(args and args[0] in {"build", "pull"}),
        )


def browser_environment():
    # Firefox needs its normal own HOME/profile environment. Never inherit tokens,
    # proxy settings, loader hooks or NODE_OPTIONS from the workflow process.
    values = {
        "PATH": os.environ["PATH"],
        "HOME": str(Path.home()),
        "LANG": "C.UTF-8",
        "TMPDIR": tempfile.gettempdir(),
    }
    runtime = os.environ.get("XDG_RUNTIME_DIR")
    if runtime and Path(runtime).is_dir():
        values["XDG_RUNTIME_DIR"] = runtime
    return values


def check_browser():
    node = shutil.which("node")
    if not node:
        raise Blocked("node_unavailable")
    program = (
        "import {createRequire} from 'node:module';"
        f"const require=createRequire({json.dumps(str(ROOT / 'apps/web/package.json'))});"
        "const p=require('puppeteer-core');const puppeteer=p.default||p;"
        "const b=await puppeteer.launch({browser:'firefox',executablePath:'/usr/bin/firefox',headless:true});"
        "try{const page=await b.newPage();await page.goto('about:blank');console.log('HOSTED_BROWSER_READY_NO_LAB')}finally{await b.close()}"
    )
    command(
        [node, "--input-type=module", "-e", program],
        timeout=45,
        environment=browser_environment(),
        build_log=True,
    )


def github_context():
    run = os.environ.get("GITHUB_RUN_ID", "")
    actor = os.environ.get("GITHUB_ACTOR", "")
    if (
        os.environ.get("GITHUB_ACTIONS") != "true"
        or os.environ.get("GITHUB_REPOSITORY") != "Buraddomoon/AEGIS"
        or os.environ.get("GITHUB_REF") != "refs/heads/main"
        or os.environ.get("GITHUB_EVENT_NAME") != "workflow_dispatch"
        or os.environ.get("GITHUB_RUN_ATTEMPT") != "1"
        or not re.fullmatch(r"[1-9][0-9]{5,19}", run)
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}", actor)
    ):
        raise Blocked("fresh_manual_hosted_attempt_required")
    if sys.platform != "linux" or not Path("/usr/bin/firefox").is_file():
        raise Blocked("native_linux_firefox_required")
    return run, actor


def image_info(reference):
    result = json.loads(
        docker(
            "image",
            "inspect",
            "--format",
            '{"id":{{json .Id}},"os":{{json .Os}},"architecture":{{json .Architecture}},"size":{{json .Size}},"user":{{json .Config.User}},"entrypoint":{{json .Config.Entrypoint}},"cmd":{{json .Config.Cmd}}}',
            reference,
        )
    )
    if (
        not re.fullmatch(r"sha256:[a-f0-9]{64}", result["id"])
        or result["os"] != "linux"
        or result["architecture"] != "amd64"
    ):
        raise Blocked("image_identity_refused")
    return result


def network_snapshot():
    identifiers = docker("network", "ls", "--quiet").decode().split()
    networks = json.loads(docker("network", "inspect", *identifiers)) if identifiers else []
    routes = json.loads(command(["/usr/sbin/ip", "-j", "-4", "route", "show", "table", "all"]))
    occupied = []
    for network in networks:
        for config in network.get("IPAM", {}).get("Config") or []:
            if config.get("Subnet"):
                occupied.append(ipaddress.ip_network(config["Subnet"]))
    for route in routes:
        if route.get("dst") not in (None, "default"):
            occupied.append(ipaddress.ip_network(route["dst"], strict=False))
    if any(
        ipaddress.ip_network(proposed).overlaps(existing)
        for proposed in SUBNETS
        for existing in occupied
        if existing.version == 4
    ):
        raise Blocked("subnet_overlap_no_host_changes")
    return {"networks": sorted((n["Id"], n["Name"]) for n in networks), "routes": routes}


def policy(plan):
    identity = plan.get("identity", {})
    if not re.fullmatch(r"[1-9][0-9]{5,19}", plan.get("workflow_run", "")) or plan.get(
        "project"
    ) != "aegis-scheduling104-" + plan.get("workflow_run", ""):
        raise Blocked("new_dedicated_project_required")
    if (
        set(identity) != {"runner_id", "laboratory_id", "asset_id"}
        or len(set(identity.values())) != 3
        or any(str(UUID(value)) != value for value in identity.values())
    ):
        raise Blocked("canonical_separate_identities_required")
    if (
        plan.get("format") != "aegis-scheduling104-native/1"
        or plan.get("occurrences") != EFFECTS
        or plan.get("test_id") != "linux-file-marker/v1"
        or plan.get("definition_id") != "linux-file-marker-v1"
        or plan.get("interval_seconds") != SLOT_INTERVAL
        or plan.get("max_duration_seconds") != RUN_SECONDS
        or plan.get("max_concurrency") != 1
        or plan.get("origin") != ORIGIN
        or plan.get("subnets") != list(SUBNETS)
        or plan.get("original_volumes") != []
        or plan.get("schema") != SCHEMA
        or plan.get("expected_outcome") != "INCONCLUSIVE"
        or plan.get("host_disposal") != "github_ephemeral_after_verified_cleanup"
        or not re.fullmatch(r"[a-f0-9]{40}", plan.get("source_commit", ""))
    ):
        raise Blocked("closed_scope_changed")
    return plan


def approval_text(plan, fingerprint):
    return (
        f"AEGIS-104-AUTHORIZE {fingerprint}\n"
        f"workflow_run={plan['workflow_run']}\n"
        "occurrences=2\nprofile=linux-file-marker/v1\n"
        "fresh_isolated_lab=true\noriginals=false\n"
        "public_sanitized_evidence=true\nephemeral_host_disposal_after_cleanup=true"
    )


def approved(comment, plan, fingerprint, instant):
    try:
        created = datetime.fromisoformat(comment["created_at"].replace("Z", "+00:00"))
        start = datetime.fromisoformat(plan["prepared_at"])
        end = datetime.fromisoformat(plan["expires_at"])
        return bool(
            comment.get("user", {}).get("login") == plan["approved_by"]
            and comment.get("body", "").strip() == approval_text(plan, fingerprint)
            and start <= created <= instant < end - timedelta(minutes=5)
        )
    except (ValueError, KeyError, TypeError):
        return False


def recipe(folder, plan):
    project = plan["project"]
    images = {k: v["id"] for k, v in plan["images"].items()}
    hardening = {
        "read_only": True,
        "cap_drop": ["ALL"],
        "security_opt": ["no-new-privileges:true"],
        "restart": "no",
        "pids_limit": 64,
        "cpus": 1,
    }
    secrets_map = {
        name: {"file": str(folder / "inputs" / name)}
        for name in (
            "owner_url",
            "runtime_url",
            "redis_url",
            "redis_config",
            "accounts",
            "app_password",
            "plan",
            "runner_connection",
        )
    }
    for name, original in {
        "runner_server_key": "runner-server.key",
        "runner_server_cert": "runner-server.crt",
        "runner_client_ca": "client-ca.crt",
        "controller_server_ca": "server-ca.crt",
        "controller_client_cert": "runner-client.crt",
        "controller_client_key": "runner-client.key",
    }.items():
        secrets_map[name] = {"file": str(folder / "pki" / original)}
    runtime_secrets = [
        "runtime_url",
        "redis_url",
        "plan",
        "runner_connection",
        "controller_server_ca",
        "controller_client_cert",
        "controller_client_key",
    ]
    service_command = ["python", "-I", "-B", "/assay/scheduling_assay_service.py"]
    common = {
        **hardening,
        "image": images["application"],
        "volumes": [
            str(ROOT / "scripts/scheduling_assay_service.py")
            + ":/assay/scheduling_assay_service.py:ro"
        ],
        "tmpfs": ["/tmp:rw,nosuid,nodev,size=16m"],
        "secrets": runtime_secrets,
        "command": [],
    }
    services = {
        "db": {
            "image": images["postgres"],
            "env_file": [str(folder / "inputs/postgres.env")],
            "volumes": ["database:/var/lib/postgresql/data"],
            "networks": {"backend": {"ipv4_address": "192.168.253.10"}},
            "mem_limit": "384m",
            "cpus": 1,
            "pids_limit": 128,
            "restart": "no",
            "healthcheck": {
                "test": ["CMD", "pg_isready", "-U", "schedule104_owner", "-d", "schedule104"],
                "interval": "2s",
                "timeout": "2s",
                "retries": 30,
            },
        },
        "redis": {
            **hardening,
            "image": images["redis"],
            "command": ["redis-server", "/run/secrets/redis_config"],
            "secrets": ["redis_config"],
            "networks": {"backend": {"ipv4_address": "192.168.253.11"}},
            "tmpfs": ["/data:rw,nosuid,nodev,size=1m", "/tmp:rw,nosuid,nodev,size=1m"],
            "mem_limit": "128m",
            "user": "999:999",
        },
        "runner": {
            **hardening,
            "image": images["runner"],
            "command": [],
            "environment": {
                f"AEGIS_RUNNER_{key.upper()}": value for key, value in plan["identity"].items()
            },
            "secrets": ["runner_server_key", "runner_server_cert", "runner_client_ca"],
            "networks": {"isolated": {"ipv4_address": "192.168.253.2"}},
            "volumes": ["journal:/state"],
            "tmpfs": ["/work:rw,noexec,nosuid,nodev,size=1m,mode=0700,uid=10001,gid=10001"],
            "mem_limit": "192m",
            "user": "10001:10001",
        },
        "api": {
            **common,
            "entrypoint": [*service_command, "api"],
            "networks": {
                "isolated": {"ipv4_address": "192.168.253.4"},
                "backend": {"ipv4_address": "192.168.253.12"},
            },
            "mem_limit": "512m",
            "user": "10001:10001",
        },
        "worker": {
            **common,
            "entrypoint": [*service_command, "worker"],
            "networks": {
                "isolated": {"ipv4_address": "192.168.253.5"},
                "backend": {"ipv4_address": "192.168.253.13"},
            },
            "mem_limit": "256m",
            "user": "10001:10001",
        },
        "admin": {
            **common,
            "entrypoint": service_command,
            "profiles": ["manual"],
            "networks": ["backend"],
            "secrets": [*runtime_secrets, "owner_url", "accounts", "app_password"],
            "mem_limit": "256m",
            "user": "10001:10001",
        },
    }
    return {
        "name": project,
        "services": services,
        "secrets": secrets_map,
        "volumes": {
            "database": {"name": project + "_database"},
            "journal": {"name": project + "_journal"},
        },
        "networks": {
            "isolated": {
                "internal": True,
                "driver_opts": {"com.docker.network.bridge.gateway_mode_ipv4": "isolated"},
                "ipam": {"config": [{"subnet": SUBNETS[0], "gateway": "192.168.253.1"}]},
            },
            "backend": {
                "internal": True,
                "ipam": {"config": [{"subnet": SUBNETS[1], "gateway": "192.168.253.9"}]},
            },
        },
    }


def prepare():
    run, actor = github_context()
    check_browser()
    if command(["git", "status", "--porcelain"], timeout=10).strip():
        raise Blocked("clean_committed_source_required")
    source = command(["git", "rev-parse", "HEAD"]).decode().strip()
    if source != os.environ.get("GITHUB_SHA"):
        raise Blocked("workflow_source_changed")
    folder = PRIVATE / run
    folder.mkdir(mode=0o700, parents=True, exist_ok=False)
    PUBLIC.mkdir(mode=0o700, parents=True, exist_ok=False)
    # Build only committed blobs: never send .env, local PKI, cache or node_modules.
    archive = command(["git", "archive", "--format=tar", "HEAD"], limit=64 * 1024**2)
    context = folder / "source"
    context.mkdir(mode=0o700)
    import io

    with tarfile.open(fileobj=io.BytesIO(archive)) as bundle:
        bundle.extractall(context, filter="data")
    images = {}
    for name, dockerfile in (("application", "Dockerfile"), ("runner", "labs/linux/Dockerfile")):
        tag = f"aegis-scheduling104-{name}:{run}"
        if docker("image", "ls", "--quiet", tag).strip():
            raise Blocked("dedicated_tag_collision")
        docker(
            "build",
            "--pull",
            "--tag",
            tag,
            "--file",
            str(context / dockerfile),
            str(context),
            timeout=600,
        )
        images[name] = image_info(tag)
    for name, reference in (("postgres", "postgres:17-alpine"), ("redis", "redis:8-alpine")):
        docker("pull", reference, timeout=120)
        images[name] = image_info(reference)
    identity = {name: str(uuid4()) for name in ("runner_id", "laboratory_id", "asset_id")}
    init_linux_lab.initialize(folder / "pki", identifiers=identity)
    inputs = folder / "inputs"
    inputs.mkdir(mode=0o700)
    accounts = [
        {
            "username": f"schedule104-{run}-{role}",
            "role": role,
            "password": secrets.token_urlsafe(36),
        }
        for role in ("operator", "administrator")
    ]
    owner_password, app_password, redis_password = (secrets.token_hex(32) for _ in range(3))
    for name, value in {
        "postgres.env": f"POSTGRES_DB=schedule104\nPOSTGRES_USER=schedule104_owner\nPOSTGRES_PASSWORD={owner_password}\n",
        "owner_url": f"postgresql+psycopg://schedule104_owner:{owner_password}@db:5432/schedule104",
        "runtime_url": f"postgresql+psycopg://aegis_app:{app_password}@db:5432/schedule104",
        "app_password": app_password,
        "redis_url": f"redis://:{redis_password}@redis:6379/0",
        "redis_config": f'requirepass {redis_password}\nmaxmemory 96mb\nmaxmemory-policy noeviction\nsave ""\nappendonly no\n',
        "accounts": accounts,
        "runner_connection": json.loads((folder / "pki/connection.json").read_text()),
    }.items():
        write_new(inputs / name, value.encode() if isinstance(value, str) else value)
        (inputs / name).chmod(0o444)
    network = network_snapshot()
    instant = datetime.now(UTC)
    plan = {
        "format": "aegis-scheduling104-native/1",
        "workflow_run": run,
        "approved_by": actor,
        "source_commit": source,
        "prepared_at": instant.isoformat(),
        "expires_at": (instant + timedelta(minutes=30)).isoformat(),
        "project": "aegis-scheduling104-" + run,
        "identity": identity,
        "images": images,
        "occurrences": EFFECTS,
        "test_id": "linux-file-marker/v1",
        "definition_id": "linux-file-marker-v1",
        "max_concurrency": 1,
        "interval_seconds": SLOT_INTERVAL,
        "max_duration_seconds": RUN_SECONDS,
        "origin": ORIGIN,
        "subnets": list(SUBNETS),
        "original_volumes": [],
        "schema": SCHEMA,
        "expected_outcome": "INCONCLUSIVE",
        "host_disposal": "github_ephemeral_after_verified_cleanup",
        "network_before_sha256": digest(network),
        "certificates": {
            name: hashlib.sha256((folder / "pki" / name).read_bytes()).hexdigest()
            for name in ("server-ca.crt", "client-ca.crt", "runner-server.crt", "runner-client.crt")
        },
        "service_sha256": hashlib.sha256(
            (ROOT / "scripts/scheduling_assay_service.py").read_bytes()
        ).hexdigest(),
        "browser_sha256": hashlib.sha256(
            (ROOT / "apps/web/scheduling-native.mjs").read_bytes()
        ).hexdigest(),
    }
    policy(plan)
    compiled = recipe(folder, plan)
    plan["recipe_sha256"] = digest(compiled)
    plan["private_files_sha256"] = {
        str(path.relative_to(folder)): hashlib.sha256(path.read_bytes()).hexdigest()
        for directory in (folder / "pki", inputs)
        for path in sorted(directory.iterdir())
        if path.is_file()
    }
    write_new(folder / "plan.json", plan)
    write_new(inputs / "plan", plan)
    (inputs / "plan").chmod(0o444)
    write_new(folder / "compose.json", compiled)
    docker(
        "compose",
        "--project-name",
        plan["project"],
        "--file",
        str(folder / "compose.json"),
        "config",
        "--quiet",
    )
    fingerprint = digest(plan)
    write_new(PUBLIC / "manifest.json", {"plan": plan, "sha256": fingerprint}, public=True)
    summary = f"# Native #104 proposal, no Lab started\n\nPackage SHA256: `{fingerprint}`\n\nSource: `{source}`\n\nTwo occurrences; fixed benign marker; fresh isolated identities; no originals; no SIEM.\n\nExpires: {plan['expires_at']}. Private PKI and passwords remain on this hosted VM only. Sanitized native proof is uploaded; the provider discards the ephemeral VM after cleanup.\n\nExact later authorization comment on issue104, by `{actor}`:\n\n```text\n{approval_text(plan, fingerprint)}\n```\n"
    Path(os.environ["GITHUB_STEP_SUMMARY"]).write_text(summary)
    print(
        json.dumps(
            {
                "status": "PREPARED_NOT_AUTHORIZED",
                "sha256": fingerprint,
                "workflow_run": run,
                "effects": 0,
            }
        )
    )


def load():
    run, _ = github_context()
    folder = PRIVATE / run
    plan = policy(json.loads((folder / "plan.json").read_text()))
    if (
        plan["workflow_run"] != run
        or plan["source_commit"] != command(["git", "rev-parse", "HEAD"]).decode().strip()
    ):
        raise Blocked("host_or_source_changed")
    if digest(json.loads((folder / "compose.json").read_text())) != plan["recipe_sha256"]:
        raise Blocked("recipe_changed")
    for name, expected in plan["private_files_sha256"].items():
        if hashlib.sha256((folder / name).read_bytes()).hexdigest() != expected:
            raise Blocked("private_input_changed")
    if (ROOT / "scripts/scheduling_assay_service.py").read_bytes() != (
        folder / "source/scripts/scheduling_assay_service.py"
    ).read_bytes():
        raise Blocked("service_changed")
    if (
        hashlib.sha256((ROOT / "apps/web/scheduling-native.mjs").read_bytes()).hexdigest()
        != plan["browser_sha256"]
        or json.loads((folder / "inputs/plan").read_text()) != plan
    ):
        raise Blocked("browser_or_runtime_plan_changed")
    return folder, plan, digest(plan)


def wait():
    folder, plan, fingerprint = load()
    # Nothing is created while waiting. An old comment, another actor or another
    # package cannot authorize this host; the window cannot be renewed here.
    with httpx.Client(
        timeout=15, trust_env=False, headers={"Authorization": "Bearer " + os.environ["GH_TOKEN"]}
    ) as client:
        while datetime.now(UTC) < datetime.fromisoformat(plan["expires_at"]) - timedelta(minutes=5):
            response = client.get(
                "https://api.github.com/repos/Buraddomoon/AEGIS/issues/104/comments",
                params={"per_page": 100},
            )
            response.raise_for_status()
            instant = datetime.now(UTC)
            for comment in response.json():
                if approved(comment, plan, fingerprint, instant):
                    write_new(
                        folder / "authorization.json",
                        {
                            "comment_id": comment["id"],
                            "created_at": comment["created_at"],
                            "approved_by": plan["approved_by"],
                            "sha256": fingerprint,
                        },
                    )
                    print(
                        json.dumps(
                            {
                                "status": "EXACT_PACKAGE_AUTHORIZED",
                                "comment_id": comment["id"],
                                "effects": EFFECTS,
                            }
                        )
                    )
                    return
            time.sleep(15)
    raise Blocked("authorization_expired_zero_effects")


def compose(folder, plan, *args, timeout=45):
    return docker(
        "compose",
        "--project-name",
        plan["project"],
        "--file",
        str(folder / "compose.json"),
        *args,
        timeout=timeout,
    )


def runtime_check(folder, plan):
    rows = []
    expected = recipe(folder, plan)
    for service, cap in (
        ("db", 384),
        ("redis", 128),
        ("runner", 192),
        ("api", 512),
        ("worker", 256),
    ):
        identifier = compose(folder, plan, "ps", "--quiet", service).decode().strip()
        item = json.loads(
            docker(
                "container",
                "inspect",
                "--format",
                '{"id":{{json .Id}},"image":{{json .Image}},"user":{{json .Config.User}},"entrypoint":{{json .Config.Entrypoint}},"cmd":{{json .Config.Cmd}},"labels":{{json .Config.Labels}},"memory":{{json .HostConfig.Memory}},"cpus":{{json .HostConfig.NanoCpus}},"pids":{{json .HostConfig.PidsLimit}},"readonly":{{json .HostConfig.ReadonlyRootfs}},"privileged":{{json .HostConfig.Privileged}},"caps":{{json .HostConfig.CapDrop}},"security":{{json .HostConfig.SecurityOpt}},"ports":{{json .HostConfig.PortBindings}},"mounts":{{json .Mounts}},"networks":{{json .NetworkSettings.Networks}}}',
                identifier,
            )
        )
        image = (
            "application"
            if service in ("api", "worker")
            else "postgres"
            if service == "db"
            else service
        )
        if (
            item["image"] != plan["images"][image]["id"]
            or item["labels"].get("com.docker.compose.project") != plan["project"]
            or item["memory"] != cap * 1024**2
            or item["privileged"]
            or item["ports"]
        ):
            raise Blocked("native_runtime_identity_changed")
        if service != "db" and (
            not item["readonly"]
            or item["caps"] != ["ALL"]
            or "no-new-privileges:true" not in item["security"]
        ):
            raise Blocked("native_runtime_hardening_changed")
        if (
            item["cpus"] != 1000000000
            or item["pids"] != (128 if service == "db" else 64)
            or service in {"api", "worker", "runner"}
            and item["user"] != "10001:10001"
        ):
            raise Blocked("native_runtime_limits_changed")
        expected_networks = {
            plan["project"] + "_" + name
            for name in (
                ("isolated", "backend")
                if service in {"api", "worker"}
                else ("isolated",)
                if service == "runner"
                else ("backend",)
            )
        }
        if set(item["networks"]) != expected_networks:
            raise Blocked("native_runtime_network_changed")
        service_recipe = expected["services"][service]
        if (item["entrypoint"] or []) != (
            service_recipe.get("entrypoint", plan["images"][image]["entrypoint"]) or []
        ) or (item["cmd"] or []) != (
            service_recipe.get("command", plan["images"][image]["cmd"]) or []
        ):
            raise Blocked("native_runtime_command_changed")
        allowed_binds = {
            Path(expected["secrets"][name]["file"]) for name in service_recipe.get("secrets", [])
        }
        if service in {"api", "worker"}:
            allowed_binds.add(ROOT / "scripts/scheduling_assay_service.py")
        for mount in item["mounts"]:
            if mount["Type"] == "volume" and mount["Name"] not in {
                plan["project"] + "_database",
                plan["project"] + "_journal",
            }:
                raise Blocked("unexpected_volume")
            if mount["Type"] == "bind" and (
                mount["RW"] or Path(mount["Source"]) not in allowed_binds
            ):
                raise Blocked("unexpected_bind_mount")
        rows.append(
            {key: item[key] for key in ("id", "image", "user", "memory", "readonly")}
            | {"service": service}
        )
    write_new(PUBLIC / "runtime.json", rows, public=True)


def run():
    folder, plan, fingerprint = load()
    authorization = json.loads((folder / "authorization.json").read_text())
    if (
        authorization["sha256"] != fingerprint
        or authorization["approved_by"] != plan["approved_by"]
        or datetime.now(UTC) >= datetime.fromisoformat(plan["expires_at"]) - timedelta(minutes=5)
    ):
        raise Blocked("specific_authorization_required")
    with httpx.Client(timeout=15, trust_env=False) as client:
        response = client.get(
            "https://api.github.com/repos/Buraddomoon/AEGIS/issues/comments/"
            + str(authorization["comment_id"]),
            headers={"Authorization": "Bearer " + os.environ["GH_TOKEN"]},
        )
        response.raise_for_status()
        if not approved(response.json(), plan, fingerprint, datetime.now(UTC)):
            raise Blocked("human_authorization_changed")
    if digest(network_snapshot()) != plan["network_before_sha256"]:
        raise Blocked("network_changed_before_effects")
    available = int(
        next(
            line.split()[1]
            for line in Path("/proc/meminfo").read_text().splitlines()
            if line.startswith("MemAvailable:")
        )
    )
    if available < 3072 * 1024:
        raise Blocked("memory_budget_unavailable_no_host_changes")
    for value in plan["images"].values():
        if image_info(value["id"])["id"] != value["id"]:
            raise Blocked("image_changed")
    for kind in ("container", "network", "volume"):
        if docker(
            kind, "ls", "--quiet", "--filter", "label=com.docker.compose.project=" + plan["project"]
        ).strip():
            raise Blocked("project_collision_no_reuse")
        names = (
            docker(
                kind,
                "ls",
                *(["--all"] if kind == "container" else []),
                "--format",
                "{{.Names}}" if kind == "container" else "{{.Name}}",
            )
            .decode()
            .splitlines()
        )
        if any(name.startswith((plan["project"] + "_", plan["project"] + "-")) for name in names):
            raise Blocked("named_resource_collision_no_reuse")
    write_new(
        folder / "attempt.json",
        {
            "sha256": fingerprint,
            "authorization": authorization,
            "reserved_occurrences": EFFECTS,
            "started_at": datetime.now(UTC).isoformat(),
        },
    )
    failure = None
    safe = False
    stage = "startup"
    try:
        compose(
            folder,
            plan,
            "up",
            "--no-build",
            "--pull",
            "never",
            "--wait",
            "db",
            "redis",
            "runner",
            timeout=90,
        )
        stage = "bootstrap"
        compose(folder, plan, "run", "--rm", "--no-deps", "-T", "admin", "bootstrap", timeout=90)
        stage = "runtime"
        compose(folder, plan, "up", "--no-build", "--pull", "never", "-d", "api", "worker")
        runtime_check(folder, plan)
        with httpx.Client(timeout=2, trust_env=False) as client:
            for _ in range(60):
                try:
                    if client.get(ORIGIN + "/api/v1/health/ready").status_code == 200:
                        break
                except httpx.HTTPError:
                    pass
                time.sleep(1)
            else:
                raise Blocked("api_not_ready")
        stage = "browser"
        own_accounts = json.loads((folder / "inputs/accounts").read_text())
        client_input = {
            "plan": plan,
            "package_sha256": fingerprint,
            "accounts": own_accounts,
            "proof_directory": str(PUBLIC),
        }
        node = shutil.which("node")
        if not node:
            raise Blocked("node_unavailable")
        command(
            [node, str(ROOT / "apps/web/scheduling-native.mjs")],
            timeout=240,
            data=canonical(client_input),
            environment=browser_environment(),
            redactions=[row["password"] for row in own_accounts],
        )
        assert (
            json.loads((PUBLIC / "browser.json").read_text())["status"]
            == "NATIVE_RECURRENCE_VERIFIED"
        )
    except BaseException as error:
        failure = type(error).__name__
    finally:
        try:
            disabled = json.loads(
                compose(
                    folder, plan, "run", "--rm", "--no-deps", "-T", "admin", "disable", timeout=60
                )
            )
            write_new(PUBLIC / "disabled.json", disabled, public=True)
            safe = disabled["safe_to_stop"] is True
            if safe:
                workspace = json.loads(
                    compose(
                        folder,
                        plan,
                        "exec",
                        "-T",
                        "runner",
                        "python",
                        "-I",
                        "-c",
                        "import json,pathlib; print(json.dumps({'workspace_empty':not any(pathlib.Path('/work').iterdir())}))",
                    )
                )
                safe = workspace["workspace_empty"] is True
                write_new(PUBLIC / "workspace.json", workspace, public=True)
            if safe:
                compose(folder, plan, "down", "--timeout", "10", timeout=60)
                consumers = docker(
                    "container",
                    "ls",
                    "--all",
                    "--quiet",
                    "--filter",
                    "label=com.docker.compose.project=" + plan["project"],
                ).strip()
                if consumers:
                    raise Blocked("own_container_retained")
                for suffix in ("database", "journal"):
                    if docker(
                        "container",
                        "ls",
                        "--all",
                        "--quiet",
                        "--filter",
                        "volume=" + plan["project"] + "_" + suffix,
                    ).strip():
                        raise Blocked("own_volume_consumer_retained")
        except BaseException:
            safe = False
            failure = failure or "cleanup_unconfirmed"
        result = {
            "status": "NATIVE_RECURRENCE_VERIFIED_CLEANED"
            if not failure and safe
            else "FAILED_QUARANTINED",
            "package_sha256": fingerprint,
            "workflow_run": plan["workflow_run"],
            "source_commit": plan["source_commit"],
            "authorization_comment": authorization["comment_id"],
            "synthetic": False,
            "approved_occurrences": EFFECTS,
            "cleanup_confirmed": safe,
            "failure_code": failure,
            "last_stage": stage,
            "originals_accessed": False,
            "host_disposal": plan["host_disposal"],
        }
        write_new(PUBLIC / "summary.json", result, public=True)
    if failure or not safe:
        raise Blocked("native_assay_failed_no_replay")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("prepare", "wait", "run"))
    action = parser.parse_args().action
    {"prepare": prepare, "wait": wait, "run": run}[action]()


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(
            json.dumps(
                {
                    "status": "BLOCKED_OR_FAILED_NO_REPLAY",
                    "reason": str(error) if isinstance(error, Blocked) else type(error).__name__,
                }
            ),
            file=sys.stderr,
        )
        raise SystemExit(1) from None
