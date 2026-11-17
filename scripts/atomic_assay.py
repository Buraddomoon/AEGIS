"""Closed #80 preparation/one-attempt lifecycle. Originals are never mounted.

Prepare/build are development operations. Run additionally requires a concrete
package hash and a separate, explicit human authorization record for that hash.
"""

import argparse
import hashlib
import json
import os
import re
import secrets
import subprocess
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import build_review_runner as builder
import init_linux_lab
import runner_activation_image_source as source
import runner_activation_subnet_review as subnet
import runner_image_wheels as wheels
from aegis.domain.validation import digest
from aegis.lab_runner import atomic_policy

ROOT = source.ROOT
PACKAGES = ROOT / ".local/atomic80-packages"
BUILDS = ROOT / ".local/atomic80-builds"
BASE_IMAGE = "sha256:9e3488c42adecf3c6a3ffb5588752bc75bae5e31f72e215d9777e950de7dd527"
SUBNETS = ("192.168.253.0/29", "192.168.253.8/29")
ENTRY = ["python", "-I", "-B", "/assay/atomic_assay_service.py"]
ENV = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "DOCKER_HOST": "unix:///var/run/docker.sock"}


def identifier(value):
    if UUID(value).hex != value:
        raise ValueError("Canonical package identifier required")
    return value


def put(path, value, mode=0o600):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    raw = value if isinstance(value, bytes) else json.dumps(value, sort_keys=True).encode()
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def read(path, maximum=4 * 1024**2):
    return builder.pki.read(path, modes=(0o600, 0o644, 0o444), maximum=maximum)


def docker(*args, timeout=30, input=None, record=None):
    # Empty Docker configuration, local Unix daemon, no ambient proxies/tokens.
    with tempfile.TemporaryDirectory(prefix="atomic80-docker-") as config:
        result = subprocess.run(
            ["/usr/bin/docker", "--config", config, "--host", "unix:///var/run/docker.sock", *args],
            input=input,
            capture_output=True,
            env=ENV,
            timeout=timeout,
        )
    if record is not None:
        put(record, result.stdout)
        put(record.with_suffix(".stderr.txt"), result.stderr)
    if result.returncode or len(result.stdout) + len(result.stderr) > 4 * 1024**2:
        raise RuntimeError("Docker operation unconfirmed; do not replay")
    return result.stdout


def context_inventory(folder, allowed):
    actual, result, total = set(), {}, 0
    for path in folder.rglob("*"):
        if path.is_symlink():
            raise ValueError("Build context link refused")
        if path.is_file():
            name = path.relative_to(folder).as_posix()
            if name not in allowed or len(result) >= 256 or path.stat().st_mode & 0o777 != 0o644:
                raise ValueError("Unexpected build context asset")
            raw = read(path, 32 * 1024**2)
            total += len(raw)
            if total > 128 * 1024**2:
                raise ValueError("Build context too large")
            actual.add(name)
            result[name] = {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
        elif not path.is_dir():
            raise ValueError("Regular build context assets required")
    if actual != set(allowed):
        raise ValueError("Build context asset missing")
    return result


def image(identifier):
    if not re.fullmatch(r"sha256:[a-f0-9]{64}", identifier):
        raise ValueError("Immutable local image required")
    # Projection excludes image environment values and potential credentials.
    return json.loads(
        docker(
            "image",
            "inspect",
            "--format",
            '{"id":{{json .Id}},"descriptor":{{json (index . "Descriptor")}},"user":{{json .Config.User}},"os":{{json .Os}},"architecture":{{json .Architecture}}}',
            identifier,
        )
    )


def committed_asset(commit, path):
    # The reviewed normalized ATT&CK document is 1.3 MiB; it is a data asset,
    # separate from the runner's unchanged 1 MiB Python/blob source profile.
    maximum = 2 * 1024**2 if path == "fixtures/attack/enterprise.json" else source.MAX_FILE
    header = (
        source._git(ROOT, "ls-tree", "-l", commit, "--", path, maximum=1024)
        .split(b"\t", 1)[0]
        .split()
    )
    if len(header) != 4 or header[:2] != [b"100644", b"blob"] or not 0 < int(header[3]) <= maximum:
        raise ValueError("Committed asset mode/size refused")
    raw = source._git(ROOT, "show", commit + ":" + path, maximum=maximum)
    if len(raw) != int(header[3]):
        raise ValueError("Committed asset size changed")
    return raw


def retain_base(folder):
    # Docker29/containerd resolves a bare FROM sha256:ID as a registry name.
    # A fresh retained tag plus independent immutable-ID checks pins the local base.
    tag = "aegis-atomic80-base:" + folder.name
    if docker("image", "ls", "--quiet", tag).strip():
        raise ValueError("Base retention tag already exists")
    put(folder / "base-tag-intent.json", {"tag": tag, "image_id": BASE_IMAGE})
    docker("image", "tag", BASE_IMAGE, tag)
    if docker("image", "inspect", "--format", "{{.Id}}", tag).decode().strip() != BASE_IMAGE:
        raise ValueError("Retained base identity mismatch")
    return tag


def build_application(runner_build_id, runner_plan_sha, cache_id, cache_sha):
    commit = source._state(ROOT)
    runner = builder.review_existing(builder.ROOT / identifier(runner_build_id), runner_plan_sha)
    cache = wheels.verify(wheels.ROOT / identifier(cache_id), cache_sha)
    assert cache["source_sha256"] == runner["source_sha256"]
    files = source._collect(ROOT, commit)
    paths = [
        "alembic.ini",
        "fixtures/attack/enterprise.json",
        "fixtures/attack/LICENSE.txt",
        "scripts/atomic_assay_service.py",
        "scripts/atomic_assay_client.py",
    ]
    paths += [
        path
        for path in source._git(
            ROOT, "ls-tree", "-r", "--name-only", commit, "--", "apps/api/migrations"
        )
        .decode()
        .splitlines()
        if path.endswith(".py")
    ]
    for path in paths:
        files[path] = committed_asset(commit, path)
    assert files["requirements.lock"] == read(wheels.ROOT / cache_id / "runtime.lock", 65536)
    base = image(BASE_IMAGE)
    assert base["id"] == BASE_IMAGE and base["user"] == "10001:10001"
    folder = BUILDS / uuid4().hex
    folder.mkdir(mode=0o700, parents=True)
    base_tag = retain_base(folder)
    context = folder / "context"
    for path, raw in files.items():
        put(context / path, raw, 0o644)
    for item in cache["wheels"].values():
        raw = read(wheels.ROOT / cache_id / "wheels" / item["filename"], wheels.MAX_WHEEL)
        assert hashlib.sha256(raw).hexdigest() == item["sha256"]
        put(context / "wheels" / item["filename"], raw, 0o644)
    runtime, tools = (
        files["requirements.lock"],
        source._git(ROOT, "show", commit + ":requirements-image-build.lock", maximum=65536),
    )
    expected = {
        "format": "aegis-runner-image-package/1",
        "source_sha256": digest({p: hashlib.sha256(v).hexdigest() for p, v in files.items()}),
        "source_commit": commit,
        "project_version": "0.2.0",
        "package_files": {
            p.removeprefix(source.PACKAGE): {
                "bytes": len(v),
                "sha256": hashlib.sha256(v).hexdigest(),
            }
            for p, v in files.items()
            if p.startswith(source.PACKAGE)
        },
    }
    assets = {p: hashlib.sha256(files[p]).hexdigest() for p in paths}
    checker = (
        "import hashlib,json,pathlib,sys\n"
        "expected=json.loads(pathlib.Path('/assay/assets.json').read_text())\n"
        "for name,sha in expected.items():\n"
        " assert hashlib.sha256(pathlib.Path('/app',name).read_bytes()).hexdigest()==sha\n"
        "import aegis.main,aegis.worker\n"
        "assert not pathlib.Path('/app/.env').exists()\n"
        f"print(json.dumps({{'status':'atomic80_application_assets_verified','build_id':'{folder.name}','assets':len(assets)}}))\n"
    )
    for name, raw in [
        ("runtime.lock", runtime),
        ("build.lock", tools),
        ("source.json", json.dumps(expected).encode()),
        (
            "check.py",
            source._git(ROOT, "show", commit + ":scripts/runner_image_assert.py", maximum=65536),
        ),
        ("assets.json", json.dumps(assets).encode()),
        ("assets_check.py", checker.encode()),
        ("build-id", folder.name.encode()),
    ]:
        put(context / name, raw, 0o644)
    recipe = f"""FROM {base_tag}
USER root
ENV PYTHONDONTWRITEBYTECODE=1 WEB_DIST=/assay/no-web
COPY wheels/ /review/wheels/
COPY runtime.lock build.lock /review/
RUN PIP_CONFIG_FILE=/dev/null NETRC=/dev/null python -I -m pip --isolated install --no-index --find-links=/review/wheels --require-hashes --no-deps --no-compile --no-cache-dir -r /review/runtime.lock -r /review/build.lock
COPY pyproject.toml alembic.ini /app/
COPY apps/ /app/apps/
COPY fixtures/ /app/fixtures/
WORKDIR /app
RUN PIP_CONFIG_FILE=/dev/null NETRC=/dev/null python -I -m pip --isolated install --force-reinstall --no-index --no-build-isolation --no-deps --no-compile --no-cache-dir .
COPY scripts/ /app/scripts/
COPY scripts/atomic_assay_service.py scripts/atomic_assay_client.py /assay/
USER root
RUN mkdir /evidence && chown 10001:10001 /evidence && chmod 700 /evidence
COPY assets.json assets_check.py /assay/
COPY source.json check.py build-id /review/
USER 10001:10001
RUN ["python","-I","-B","/review/check.py"]
RUN ["python","-I","-B","/assay/assets_check.py"]
ENTRYPOINT ["python","-I","-B","/assay/atomic_assay_service.py"]
CMD ["api"]
"""
    put(context / "Dockerfile", recipe.encode(), 0o644)
    for directory in context.rglob("*"):
        if directory.is_dir():
            directory.chmod(0o755)
    allowed = set(files) | {
        "Dockerfile",
        "runtime.lock",
        "build.lock",
        "source.json",
        "check.py",
        "assets.json",
        "assets_check.py",
        "build-id",
    }
    allowed |= {"wheels/" + item["filename"] for item in cache["wheels"].values()}
    inventory = context_inventory(context, allowed)
    tag = "aegis-atomic80-application:" + folder.name
    assert not docker("image", "ls", "--quiet", tag).strip()
    put(folder / "intent.json", {"tag": tag, "commit": commit, "context_sha256": digest(inventory)})
    log = folder / "build.txt"
    with open(log, "xb") as stream, tempfile.TemporaryDirectory(prefix="atomic80-build-") as config:
        os.chmod(log, 0o600)
        result = subprocess.run(
            [
                "/usr/bin/docker",
                "--config",
                config,
                "--host",
                "unix:///var/run/docker.sock",
                "buildx",
                "build",
                "--builder",
                "default",
                "--network",
                "none",
                "--pull=false",
                "--provenance=false",
                "--sbom=false",
                "--progress",
                "plain",
                "--load",
                "--metadata-file",
                str(folder / "metadata.json"),
                "--tag",
                tag,
                str(context),
            ],
            stdout=stream,
            stderr=subprocess.STDOUT,
            env=ENV,
            timeout=180,
        )
    assert result.returncode == 0
    metadata = json.loads(builder._output(folder / "metadata.json", 256 * 1024))
    native = image(metadata["containerimage.digest"])
    builder._result_identity(metadata, native)
    assert (
        native["user"] == "10001:10001"
        and native["os"] == "linux"
        and native["architecture"] == "amd64"
    )
    output = read(log).decode()
    assert (
        f'"build_id": "{folder.name}"' in output and '"installed_versions_verified": true' in output
    )
    assert context_inventory(context, allowed) == inventory and source._state(ROOT) == commit
    assert (
        docker("image", "inspect", "--format", "{{.Id}}", base_tag).decode().strip() == BASE_IMAGE
    )
    receipt = {
        "format": "atomic80-application-build/1",
        "id": folder.name,
        "source_commit": commit,
        "image_id": native["id"],
        "tag": tag,
        "base_image": BASE_IMAGE,
        "base_retention_tag": base_tag,
        "runner_image": runner["native_image_id"],
        "runner_build_id": runner_build_id,
        "runner_plan_sha256": runner_plan_sha,
        "context_sha256": digest(inventory),
        "assets": assets,
        "image_built": True,
        "lab_started": False,
        "effects_authorized": False,
    }
    put(folder / "receipt.json", receipt)
    return {**receipt, "receipt_sha256": digest(receipt)}


def recipe(plan, folder):
    project, images = plan["project"], plan["images"]
    common = {
        "restart": "no",
        "read_only": True,
        "cap_drop": ["ALL"],
        "security_opt": ["no-new-privileges:true"],
        "pids_limit": 64,
        "cpus": 1,
    }
    app = {
        **common,
        "image": images["application"],
        "entrypoint": ENTRY,
        "tmpfs": ["/tmp:rw,noexec,nosuid,nodev,size=32m"],
        "environment": {"WEB_DIST": "/assay/no-web"},
    }
    runtime = [
        "runtime_url",
        "redis_url",
        "runner_connection",
        "controller_server_ca",
        "controller_client_cert",
        "controller_client_key",
    ]
    admin = ["owner_url", "redis_url", "app_password", "accounts", "plan"]
    services = {
        "db": {
            "image": images["postgres"],
            "environment": {
                "POSTGRES_USER": "atomic_owner",
                "POSTGRES_DB": "atomic_assay",
                "POSTGRES_PASSWORD_FILE": "/run/secrets/owner_password",
                "POSTGRES_INITDB_ARGS": "--auth-host=scram-sha-256",
            },
            "secrets": ["owner_password"],
            "volumes": ["database:/var/lib/postgresql/data"],
            "networks": {"backend": {"ipv4_address": "192.168.253.10"}},
            "healthcheck": {
                "test": ["CMD", "pg_isready", "-U", "atomic_owner", "-d", "atomic_assay"],
                "interval": "2s",
                "timeout": "2s",
                "retries": 30,
            },
            "mem_limit": "384m",
            "pids_limit": 128,
            "cpus": 1,
            "restart": "no",
            "security_opt": ["no-new-privileges:true"],
        },
        "redis": {
            **common,
            "image": images["redis"],
            "user": "999:999",
            "command": ["redis-server", "/run/secrets/redis_config"],
            "secrets": ["redis_config"],
            "tmpfs": [
                "/tmp:rw,noexec,nosuid,nodev,size=1m",
                "/data:rw,noexec,nosuid,nodev,size=1m,uid=999,gid=999",
            ],
            "networks": {"backend": {"ipv4_address": "192.168.253.11"}},
            "mem_limit": "128m",
        },
        "runner": {
            **common,
            "image": images["runner"],
            "environment": {
                **{"AEGIS_RUNNER_" + key.upper(): value for key, value in plan["identity"].items()},
                "AEGIS_RUNNER_TEST_ID": atomic_policy.TEST_ID,
            },
            "volumes": ["journal:/state"],
            "tmpfs": ["/work:rw,noexec,nosuid,nodev,size=1m,mode=0700,uid=10001,gid=10001"],
            "secrets": ["runner_server_cert", "runner_server_key", "runner_client_ca"],
            "networks": {"isolated": {"ipv4_address": "192.168.253.2"}},
            "mem_limit": "192m",
        },
        "api": {
            **app,
            "command": ["api"],
            "secrets": runtime,
            "networks": {
                "backend": {"ipv4_address": "192.168.253.12"},
                "isolated": {"ipv4_address": "192.168.253.4"},
            },
            "mem_limit": "512m",
        },
        "worker": {
            **app,
            "command": ["worker"],
            "secrets": runtime,
            "networks": {
                "backend": {"ipv4_address": "192.168.253.13"},
                "isolated": {"ipv4_address": "192.168.253.5"},
            },
            "mem_limit": "256m",
        },
        "admin": {
            **app,
            "profiles": ["manual"],
            "command": ["check"],
            "secrets": admin,
            "networks": ["backend"],
            "mem_limit": "256m",
        },
        "controller": {
            **common,
            "image": images["application"],
            "profiles": ["manual"],
            "entrypoint": ["python", "-I", "-B", "/assay/atomic_assay_client.py"],
            "secrets": ["accounts", "plan"],
            "volumes": ["evidence:/evidence"],
            "networks": {"isolated": {"ipv4_address": "192.168.253.3"}},
            "mem_limit": "128m",
        },
    }
    secret_paths = {
        name: str(folder / "private" / name)
        for name in admin + runtime + ["owner_password", "redis_config"]
    }
    secret_paths.update(
        {
            name: str(folder / "pki" / path)
            for name, path in {
                "runner_server_cert": "runner-server.crt",
                "runner_server_key": "runner-server.key",
                "runner_client_ca": "client-ca.crt",
                "controller_server_ca": "server-ca.crt",
                "controller_client_cert": "runner-client.crt",
                "controller_client_key": "runner-client.key",
                "runner_connection": "connection.json",
            }.items()
        }
    )
    secret_paths["plan"] = str(folder / "plan.json")
    return {
        "name": project,
        "services": services,
        "volumes": {
            name: {"name": project + "_" + name} for name in ("database", "journal", "evidence")
        },
        "networks": {
            name: {
                "name": project + "_" + name,
                "internal": True,
                "enable_ipv6": False,
                "driver_opts": {"com.docker.network.bridge.gateway_mode_ipv4": "isolated"},
                "ipam": {
                    "config": [
                        {
                            "subnet": cidr,
                            "gateway": cidr.split("/")[0].rsplit(".", 1)[0]
                            + (".1" if name == "isolated" else ".9"),
                        }
                    ]
                },
            }
            for name, cidr in zip(("isolated", "backend"), SUBNETS, strict=True)
        },
        "secrets": {name: {"file": path} for name, path in secret_paths.items()},
    }


def prepare(application_build_id, application_sha):
    application = json.loads(read(BUILDS / identifier(application_build_id) / "receipt.json"))
    assert digest(application) == application_sha
    assert image(application["image_id"])["id"] == application["image_id"]
    network = subnet._review(SUBNETS)
    folder = PACKAGES / uuid4().hex
    folder.mkdir(mode=0o700, parents=True)
    identity = {name: str(uuid4()) for name in ("runner_id", "laboratory_id", "asset_id")}
    init_linux_lab.initialize(folder / "pki", identifiers=identity)
    connection = json.loads((folder / "pki/connection.json").read_text())
    connection["test_id"] = atomic_policy.TEST_ID
    # Newly generated candidate only. No original PKI/configuration is touched.
    (folder / "pki/connection.json").chmod(0o600)
    (folder / "pki/connection.json").write_text(json.dumps(connection))
    (folder / "pki/connection.json").chmod(0o444)
    passwords = {name: secrets.token_urlsafe(40) for name in ("owner", "app", "redis")}
    values = {
        "owner_password": passwords["owner"],
        "app_password": passwords["app"],
        "owner_url": f"postgresql+psycopg://atomic_owner:{passwords['owner']}@db:5432/atomic_assay",
        "runtime_url": f"postgresql+psycopg://aegis_app:{passwords['app']}@db:5432/atomic_assay",
        "redis_url": f"redis://:{passwords['redis']}@redis:6379/0",
        "redis_config": f'requirepass {passwords["redis"]}\nmaxmemory 96mb\nmaxmemory-policy noeviction\nsave ""\nappendonly no\n',
    }
    for name, value in values.items():
        put(folder / "private" / name, value.encode(), 0o444)
    put(
        folder / "private/accounts",
        [
            {
                "username": "atomic80_" + role + "_" + folder.name[:12],
                "role": role,
                "password": secrets.token_urlsafe(40),
            }
            for role in ("administrator", "operator")
        ],
        0o444,
    )
    now = datetime.now(UTC)
    plan = {
        "format": "atomic80-one-attempt/1",
        "id": folder.name,
        "attempt_id": str(uuid4()),
        "project": "aegis-atomic80-" + folder.name[:12],
        "identity": identity,
        "created_at": now.isoformat(),
        "expires_at": (now + timedelta(hours=12)).isoformat(),
        "application_commit": application["source_commit"],
        "images": {
            "application": application["image_id"],
            "runner": application["runner_image"],
            "postgres": "sha256:b0f9560a2de083e2cc7382e75f808c7381a32852a7ec49117deedb300e552b24",
            "redis": "sha256:3811787313eba226a2ef38658c6ccb91cd5e110edc89c37767de373120a0e5a0",
        },
        "review": atomic_policy.review(),
        "subnets": list(SUBNETS),
        "api": "http://192.168.253.4:8080",
        "host_ports": [],
        "original_volumes": [],
        "schema": "c8e4a6d21f90",
        "max_effect_seconds": 5,
        "max_run_seconds": 60,
        "max_lifecycle_seconds": 900,
        "peak_memory_mib": 1728,
        "minimum_available_mib": 3072,
        "telemetry": "unavailable",
        "expected_verdict": "INCONCLUSIVE",
        "effects_authorized": False,
        "network_preflight_sha256": digest(network),
    }
    for value in plan["images"].values():
        assert image(value)["id"] == value
    put(folder / "plan.json", plan, 0o444)
    compiled = recipe(plan, folder)
    put(folder / "compose.json", compiled)
    inventory = {
        str(path.relative_to(folder)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in folder.rglob("*")
        if path.is_file()
    }
    proposal = {"plan": plan, "inventory": inventory, "application_receipt_sha256": application_sha}
    put(folder / "proposal.json", proposal)
    # Compose rendering is offline: no create/start, no database or journal open.
    rendered = json.loads(
        docker(
            "compose",
            "--project-name",
            plan["project"],
            "-f",
            str(folder / "compose.json"),
            "config",
            "--format",
            "json",
        )
    )
    assert not any(
        service.get("ports") or service.get("build") or service.get("privileged")
        for service in rendered["services"].values()
    )
    put(folder / "rendered.json", rendered)
    return {
        "package_id": folder.name,
        "proposal_sha256": digest(proposal),
        "plan": plan,
        "lab_started": False,
    }


def verify(package_id, expected_sha):
    folder = PACKAGES / identifier(package_id)
    proposal = json.loads(read(folder / "proposal.json"))
    if digest(proposal) != expected_sha:
        raise ValueError("Proposal hash changed")
    for name, sha in proposal["inventory"].items():
        if (
            name.startswith("/")
            or ".." in Path(name).parts
            or hashlib.sha256(read(folder / name)).hexdigest() != sha
        ):
            raise ValueError("Private package drift")
    plan = proposal["plan"]
    if (
        plan["id"] != package_id
        or plan["review"] != atomic_policy.review()
        or datetime.now(UTC) >= datetime.fromisoformat(plan["expires_at"])
    ):
        raise ValueError("Expired or incompatible proposal")
    if json.loads(read(folder / "compose.json")) != recipe(plan, folder):
        raise ValueError("Unexpected recipe")
    for value in plan["images"].values():
        assert image(value)["id"] == value
    return folder, plan


def validate_runtime(item, service, plan, folder):
    expected_image = plan["images"][
        {"db": "postgres", "redis": "redis", "runner": "runner"}.get(service, "application")
    ]
    assert item["image"] == expected_image
    assert item["privileged"] is False and not item["ports"]
    assert item["project"] == plan["project"] and item["service"] == service
    expected_networks = {plan["project"] + "_backend"}
    if service in {"api", "worker"}:
        expected_networks.add(plan["project"] + "_isolated")
    elif service == "runner":
        expected_networks = {plan["project"] + "_isolated"}
    assert set(item["networks"]) == expected_networks
    if service in {"api", "worker", "runner"}:
        assert item["user"] == "10001:10001" and item["readonly"]
        assert item["cap_drop"] == ["ALL"]
        assert "no-new-privileges:true" in item["security"]
        assert item["pids"] == 64
        assert item["memory"] == {"api": 512, "worker": 256, "runner": 192}[service] * 1024**2
        assert item["cpus"] == 1_000_000_000
    if service == "runner":
        assert item["networks"][plan["project"] + "_isolated"]["IPAddress"] == "192.168.253.2"
        assert all(
            flag in item["tmpfs"]["/work"]
            for flag in ("noexec", "nosuid", "nodev", "uid=10001", "gid=10001")
        )
    allowed_volumes = {plan["project"] + "_database", plan["project"] + "_journal"}
    for mount in item["mounts"]:
        if mount["Type"] == "volume":
            assert mount["Name"] in allowed_volumes
        elif mount["Type"] == "bind":
            assert not mount["RW"] and mount["Destination"].startswith("/run/secrets/")
            assert Path(mount["Source"]).resolve().is_relative_to(folder.resolve())
        else:
            assert mount["Type"] == "tmpfs"


def runtime_review(compose, plan, folder):
    # Deliberately exclude all environment values and command arguments.
    projection = '{"image":{{json .Config.Image}},"user":{{json .Config.User}},"project":{{json (index .Config.Labels "com.docker.compose.project")}},"service":{{json (index .Config.Labels "com.docker.compose.service")}},"readonly":{{json .HostConfig.ReadonlyRootfs}},"privileged":{{json .HostConfig.Privileged}},"ports":{{json .HostConfig.PortBindings}},"cap_drop":{{json .HostConfig.CapDrop}},"security":{{json .HostConfig.SecurityOpt}},"pids":{{json .HostConfig.PidsLimit}},"memory":{{json .HostConfig.Memory}},"cpus":{{json .HostConfig.NanoCpus}},"tmpfs":{{json .HostConfig.Tmpfs}},"mounts":{{json .Mounts}},"networks":{{json .NetworkSettings.Networks}}}'
    result = {}
    for service in ("db", "redis", "runner", "api", "worker"):
        container = docker(*compose, "ps", "--quiet", service, timeout=5).decode().strip()
        assert re.fullmatch(r"[a-f0-9]{64}", container)
        item = json.loads(
            docker("container", "inspect", "--format", projection, container, timeout=5)
        )
        validate_runtime(item, service, plan, folder)
        result[service] = item
    put(folder / "runtime-review.json", result)


def run(package_id, expected_sha):
    folder, plan = verify(package_id, expected_sha)
    authority = json.loads(read(folder / "authorization.json", 16384))
    if (
        authority.get("proposal_sha256") != expected_sha
        or authority.get("approved_by") != "user"
        or authority.get("one_attempt") is not True
    ):
        raise ValueError("Specific human authorization required")
    if (folder / "attempt.json").exists():
        raise ValueError("Attempt already consumed; recovery only")
    available = (
        int(
            next(
                line.split()[1]
                for line in Path("/proc/meminfo").read_text().splitlines()
                if line.startswith("MemAvailable:")
            )
        )
        // 1024
    )
    if available < plan["minimum_available_mib"]:
        raise ValueError("Insufficient available memory; no host changes allowed")
    subnet._review(SUBNETS)
    project = plan["project"]
    for kind in ("container", "network", "volume"):
        if docker(
            kind, "ls", "--quiet", "--filter", "label=com.docker.compose.project=" + project
        ).strip():
            raise ValueError("Project already exists; preserve resources")
    for kind, expected in (
        ("volume", {project + "_" + name for name in ("database", "journal", "evidence")}),
        ("network", {project + "_isolated", project + "_backend"}),
    ):
        names = set(docker(kind, "ls", "--format", "{{.Name}}").decode().splitlines())
        if names & expected:
            raise ValueError("Named resource collision; do not reuse a volume or network")
    # This fence is fsynced before the first Docker mutation and never deleted.
    if datetime.now(UTC) >= datetime.fromisoformat(plan["expires_at"]):
        raise ValueError("Package expired before first mutation")
    put(
        folder / "attempt.json",
        {
            "proposal_sha256": expected_sha,
            "attempt_id": plan["attempt_id"],
            "consumed_at": datetime.now(UTC).isoformat(),
        },
    )
    compose = ("compose", "--project-name", project, "-f", str(folder / "compose.json"))
    client_started = False
    completed = False
    try:
        docker(
            *compose,
            "up",
            "--no-build",
            "--pull",
            "never",
            "-d",
            "--wait",
            "db",
            "redis",
            "runner",
            timeout=90,
        )
        put(
            folder / "bootstrap.txt",
            docker(*compose, "run", "--rm", "--no-deps", "-T", "admin", "bootstrap", timeout=90),
        )
        put(
            folder / "readiness.txt",
            docker(*compose, "run", "--rm", "--no-deps", "-T", "admin", "check", timeout=30),
        )
        docker(*compose, "up", "--no-build", "--pull", "never", "-d", "api", "worker", timeout=45)
        # A fixed, read-only readiness GET before admitting the controller.
        docker(
            *compose,
            "exec",
            "-T",
            "api",
            "python",
            "-I",
            "-c",
            "import time,urllib.request\nfor i in range(30):\n try:\n  urllib.request.urlopen('http://127.0.0.1:8080/api/v1/health/ready',timeout=2);break\n except Exception: time.sleep(1)\nelse: raise SystemExit(1)",
            timeout=45,
        )
        runtime_review(compose, plan, folder)
        if datetime.now(UTC) >= datetime.fromisoformat(plan["expires_at"]):
            raise ValueError("Package expired; do not dispatch")
        client_started = True
        output = docker(
            *compose,
            "run",
            "--rm",
            "--no-deps",
            "-T",
            "controller",
            timeout=120,
            record=folder / "controller.txt",
        )
        result = json.loads(output.decode().splitlines()[-1])
        assert result["status"] == "native_atomic_verified"
        completed = True
    finally:
        stop_permitted = not client_started
        try:
            disabled = docker(
                *compose, "run", "--rm", "--no-deps", "-T", "admin", "disable", timeout=30
            )
            put(folder / "disable.txt", disabled)
            cleanup = json.loads(disabled.decode().splitlines()[-1])
            stop_permitted |= cleanup["safe_to_stop"] is True
            if completed:
                assert cleanup["accounts"] == 2 and cleanup["safe_to_stop"] is True
        finally:
            # An uncertain effect keeps its workspace and resources quarantined.
            # Cleanup/recovery uses the original attempt; it never re-runs this function.
            if stop_permitted:
                docker(*compose, "down", "--timeout", "10", timeout=60)
                assert not docker(
                    "container",
                    "ls",
                    "--all",
                    "--quiet",
                    "--filter",
                    "label=com.docker.compose.project=" + project,
                ).strip()
                for name in ("database", "journal", "evidence"):
                    assert not docker(
                        "container",
                        "ls",
                        "--all",
                        "--quiet",
                        "--filter",
                        "volume=" + project + "_" + name,
                    ).strip()
    put(
        folder / "result.json",
        {
            "status": "VERIFIED_CLEANED",
            "proposal_sha256": expected_sha,
            "attempt_id": plan["attempt_id"],
            "run_id": result["run_id"],
            "verdict": "INCONCLUSIVE",
            "synthetic": False,
        },
    )
    return json.loads(read(folder / "result.json"))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    build = commands.add_parser("build")
    for name in ("runner-build-id", "runner-plan-sha256", "cache-id", "cache-sha256"):
        build.add_argument("--" + name, required=True)
    create = commands.add_parser("prepare")
    create.add_argument("--application-build-id", required=True)
    create.add_argument("--application-sha256", required=True)
    for name in ("verify", "run"):
        command = commands.add_parser(name)
        command.add_argument("--package-id", required=True)
        command.add_argument("--expected-sha256", required=True)
    args = parser.parse_args()
    if args.command == "build":
        result = build_application(
            args.runner_build_id, args.runner_plan_sha256, args.cache_id, args.cache_sha256
        )
    elif args.command == "prepare":
        result = prepare(args.application_build_id, args.application_sha256)
    elif args.command == "verify":
        _, plan = verify(args.package_id, args.expected_sha256)
        result = {"status": "proposal_verified_not_authorized", "plan": plan}
    else:
        result = run(args.package_id, args.expected_sha256)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
