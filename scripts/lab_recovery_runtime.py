"""New isolated PostgreSQL copies only; never normal app/worker/runner startup.

Private workspaces and durable requests are retained on ambiguous cleanup. No
volume deletion, force removal, daemon-wide cleanup or automatic effect replay.
"""

import json
import os
import re
import shutil
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import lab_recovery_transport as transport
from aegis.domain.validation import digest
from aegis.operations import backup, vault
from aegis.operations import lab_backup as snapshot
from sqlalchemy import create_engine, text
from sqlalchemy.engine import URL

LABEL = "io.aegis.lab-recovery"
DATA = "/var/lib/postgresql/data"
MEMORY = 384 * 1024**2
PROJECTION = (
    '{"id":{{json .Id}},"name":{{json .Name}},"image":{{json .Image}},'
    '"labels":{{json .Config.Labels}},"user":{{json .Config.User}},'
    '"entrypoint":{{json .Config.Entrypoint}},"args":{{json .Config.Cmd}},'
    '"state":{{json .State.Status}},"exit":{{json .State.ExitCode}},'
    '"mounts":{{json .Mounts}},"host":{{json .HostConfig}},'
    '"networks":{{json .NetworkSettings.Networks}}}'
)


class Operation:
    def __init__(self, folder: Path, plan_hash: str, *, deadline=None, before_effect=None):
        if not re.fullmatch(r"[a-f0-9]{64}", plan_hash) or os.geteuid() == 0:
            raise snapshot.SnapshotError("recovery_operation_inputs")
        snapshot._new(folder)
        self.folder, self.identifier = folder, uuid4().hex
        self.plan_hash, self.events, self.resources = plan_hash, [], {}
        self.workspace = None
        self.deadline = deadline if deadline is not None else time.monotonic() + 900
        self.before_effect = before_effect
        self.event("begin", {"id": self.identifier, "plan_sha256": plan_hash})

    def event(self, kind, data):
        envelope = {
            "format": "aegis-lab-recovery-event/1",
            "sequence": len(self.events),
            "previous_sha256": digest(self.events[-1]) if self.events else None,
            "at": datetime.now(UTC).isoformat(),
            "kind": kind,
            "data": data,
        }
        envelope = json.loads(json.dumps(envelope))  # Freeze nested recipe dictionaries.
        vault.write_json(self.folder / f"{len(self.events):04d}.json", envelope)
        self.events.append(envelope)

    @classmethod
    def load_cleanup(cls, folder, begin_hash):
        snapshot._directory(folder)
        events = []
        for path in sorted(folder.glob("[0-9][0-9][0-9][0-9].json")):
            event = snapshot._json(snapshot._read(path, snapshot.MAX_JSON))
            if (
                event["format"] != "aegis-lab-recovery-event/1"
                or event["sequence"] != len(events)
                or path.name != f"{len(events):04d}.json"
                or event["previous_sha256"] != (digest(events[-1]) if events else None)
            ):
                raise snapshot.SnapshotError("recovery_event_chain_invalid")
            events.append(event)
            if len(events) > 1024:
                raise snapshot.SnapshotError("recovery_event_limit")
        if not events or digest(events[0]) != begin_hash or events[0]["kind"] != "begin":
            raise snapshot.SnapshotError("recovery_begin_hash_mismatch")
        obj = object.__new__(cls)
        obj.folder, obj.events = folder, events
        obj.identifier, obj.plan_hash = events[0]["data"]["id"], events[0]["data"]["plan_sha256"]
        if not re.fullmatch(r"[a-f0-9]{32}", obj.identifier) or not re.fullmatch(
            r"[a-f0-9]{64}", obj.plan_hash
        ):
            raise snapshot.SnapshotError("recovery_event_identity")
        obj.workspace, obj.resources, obj.deadline, obj.before_effect = None, {}, 0, None
        for event in events[1:]:
            data, kind = event["data"], event["kind"]
            if kind == "workspace":
                path = Path(data["path"])
                if (
                    path.parent != Path(tempfile.gettempdir())
                    or not path.name.startswith("aegis-lr-" + obj.identifier[:12] + "-")
                    or path.is_symlink()
                ):
                    raise snapshot.SnapshotError("recovery_workspace_identity")
                obj.workspace = path
            elif kind == "create_requested":
                role, spec = data["role"], json.loads(json.dumps(data["recipe"]))
                if (
                    role in obj.resources
                    or not re.fullmatch(r"[a-z][a-z0-9-]{0,35}", role)
                    or spec["name"] != "aegis-lab-recovery-" + obj.identifier + "-" + role
                    or spec["id"] is not None
                    or not re.fullmatch(r"sha256:[a-f0-9]{64}", spec["image"])
                ):
                    raise snapshot.SnapshotError("recovery_resource_history_invalid")
                obj.resources[role] = spec
            elif kind in {"created", "ownership_discovered"}:
                spec = obj.resources[data["role"]]
                if not re.fullmatch(r"[a-f0-9]{64}", data["id"]) or spec["id"] not in (
                    None,
                    data["id"],
                ):
                    raise snapshot.SnapshotError("recovery_resource_id_changed")
                spec["id"] = data["id"]
        return obj

    def guard(self):
        if time.monotonic() >= self.deadline:
            raise snapshot.SnapshotError("recovery_effect_deadline_expired")
        if self.before_effect is not None:
            self.before_effect()
        if time.monotonic() >= self.deadline:
            raise snapshot.SnapshotError("recovery_effect_deadline_expired")

    def budget(self, maximum):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise snapshot.SnapshotError("recovery_effect_deadline_expired")
        return min(maximum, remaining)

    def scratch(self):
        if self.workspace is not None:
            return self.workspace
        # Short Unix-socket path, private parent. Keep it if any process is uncertain.
        self.workspace = Path(tempfile.mkdtemp(prefix="aegis-lr-" + self.identifier[:12] + "-"))
        self.event("workspace", {"path": str(self.workspace)})
        return self.workspace

    def create(self, role, image, entrypoint, arguments, mounts, *, user=None, memory=MEMORY):
        self.guard()
        if role in self.resources or not re.fullmatch(r"[a-z][a-z0-9-]{0,35}", role):
            raise snapshot.SnapshotError("recovery_role_replay")
        if not re.fullmatch(r"sha256:[a-f0-9]{64}", image):
            raise snapshot.SnapshotError("recovery_image_required")
        for item in mounts:
            if item["type"] == "volume":
                allowed = {
                    project + "_" + suffix
                    for project in ("aegis-linux-lab", "aegis-wazuh-lab")
                    for suffix in ("postgres-data", "journal")
                }
                if (
                    item["source"] not in allowed
                    or not item["readonly"]
                    or item["target"] != "/source"
                ):
                    raise snapshot.SnapshotError("recovery_original_read_only_required")
            elif item["type"] == "bind":
                path = Path(item["source"])
                if (
                    self.workspace is None
                    or not path.is_relative_to(self.workspace)
                    or item["target"]
                    not in {DATA, "/socket", "/hba", "/pgconf", "/etc/passwd", "/etc/group"}
                ):
                    raise snapshot.SnapshotError("recovery_bind_outside_owned_workspace")
                vault.no_symlink_parents(path)
            else:
                raise snapshot.SnapshotError("recovery_mount_type")
        name = "aegis-lab-recovery-" + self.identifier + "-" + role
        if self.names(name):
            raise snapshot.SnapshotError("recovery_name_collision")
        spec = {
            "name": name,
            "image": image,
            "entrypoint": entrypoint,
            "arguments": arguments,
            "user": user or f"{os.geteuid()}:{os.getegid()}",
            "mounts": mounts,
            "memory": memory,
            "id": None,
        }
        self.event("create_requested", {"role": role, "recipe": spec})
        self.resources[role] = spec  # Retain ambiguity if create loses its response.
        argv = [
            "create",
            "--pull=never",
            "--name",
            name,
            "--label",
            LABEL + "=" + self.identifier,
            "--label",
            "io.aegis.lab-recovery-plan=" + self.plan_hash,
            "--network=none",
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges:true",
            "--memory=" + str(memory),
            "--memory-swap=" + str(memory),
            "--cpus=1",
            "--pids-limit=64",
            "--ipc=private",
            "--cgroupns=private",
            "--restart=no",
            "--stop-timeout=5",
            "--log-driver=none",
            "--no-healthcheck",
            "--user",
            spec["user"],
            "--workdir=/",
            "--entrypoint",
            entrypoint,
            "--env=LANG=C.UTF-8",
            "--env=LC_ALL=C",
            "--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=64m",
        ]
        # Override the image's declared volume even in tar helpers: no anonymous volumes.
        if not any(m["target"] == DATA for m in mounts):
            argv.append("--tmpfs=" + DATA + ":rw,noexec,nosuid,nodev,size=1m")
        for item in mounts:
            source = item["source"]
            if any(c in source for c in (",", "\n", "\r", "\0")):
                raise snapshot.SnapshotError("recovery_mount_path")
            argv.extend(
                (
                    "--mount",
                    "type="
                    + item["type"]
                    + ",source="
                    + source
                    + ",target="
                    + item["target"]
                    + (",readonly" if item["readonly"] else "")
                    + (
                        ",volume-nocopy"
                        if item["type"] == "volume"
                        else ",bind-propagation=rprivate"
                    ),
                )
            )
        identifier = (
            transport.run([*argv, image, *arguments], timeout=self.budget(20)).decode().strip()
        )
        if not re.fullmatch(r"[a-f0-9]{64}", identifier):
            raise snapshot.SnapshotError("recovery_create_unconfirmed")
        spec["id"] = identifier
        self.validate(role)
        self.event("created", {"role": role, "id": identifier})
        return identifier

    def names(self, name):
        return (
            transport.run(
                [
                    "ps",
                    "-a",
                    "--no-trunc",
                    "--filter",
                    "name=^/" + name + "$",
                    "--format",
                    "{{.ID}} {{.Names}}",
                ]
            )
            .decode()
            .splitlines()
        )

    def validate(self, role):
        spec = self.resources[role]
        result = snapshot._json(transport.run(["inspect", "--format", PROJECTION, spec["name"]]))
        host = result["host"]
        if (
            (spec["id"] is not None and result["id"] != spec["id"])
            or not re.fullmatch(r"[a-f0-9]{64}", result["id"])
            or result["name"] != "/" + spec["name"]
            or result["image"] != spec["image"]
            or result["labels"].get(LABEL) != self.identifier
            or result["labels"].get("io.aegis.lab-recovery-plan") != self.plan_hash
            or result["user"] != spec["user"]
            or result["entrypoint"] != [spec["entrypoint"]]
            or result["args"] != spec["arguments"]
            or host["NetworkMode"] != "none"
            or not host["ReadonlyRootfs"]
            or host["Privileged"]
            or host["CapAdd"]
            or host["CapDrop"] != ["ALL"]
            or host["SecurityOpt"] != ["no-new-privileges:true"]
            or host["Memory"] != spec["memory"]
            or host["MemorySwap"] != spec["memory"]
            or host["NanoCpus"] != 1_000_000_000
            or host["PidsLimit"] != 64
            or host["RestartPolicy"]["Name"] != "no"
            or host["AutoRemove"]
            or host["PortBindings"]
            or host["PublishAllPorts"]
            or host["Devices"]
            or host["DeviceRequests"]
            or host["VolumesFrom"]
            or host["Links"]
            or host["PidMode"]
            or host["IpcMode"] != "private"
            or host["CgroupnsMode"] != "private"
            or host["LogConfig"]["Type"] != "none"
        ):
            raise snapshot.SnapshotError("recovery_runtime_mismatch")
        expected = {m["target"]: m for m in spec["mounts"]}
        configured = host.get("Mounts") or []
        if len(configured) != len(expected):
            raise snapshot.SnapshotError("recovery_configured_mounts_mismatch")
        for actual in configured:
            wanted = expected.get(actual["Target"])
            if (
                wanted is None
                or actual["Type"] != wanted["type"]
                or actual["Source"] != wanted["source"]
                or actual.get("ReadOnly", False) is not wanted["readonly"]
                or (
                    wanted["type"] == "volume"
                    and actual.get("VolumeOptions", {}).get("NoCopy") is not True
                )
                or (
                    wanted["type"] == "bind"
                    and actual.get("BindOptions", {}).get("Propagation") != "rprivate"
                )
            ):
                raise snapshot.SnapshotError("recovery_configured_mounts_mismatch")
        tmpfs = {"/tmp": "rw,noexec,nosuid,nodev,size=64m"}
        if DATA not in expected:
            tmpfs[DATA] = "rw,noexec,nosuid,nodev,size=1m"
        if host.get("Tmpfs") != tmpfs:
            raise snapshot.SnapshotError("recovery_tmpfs_profile_mismatch")
        seen = set()
        for item in result["mounts"]:
            target = item["Destination"]
            if item["Type"] == "tmpfs" and target in {"/tmp", DATA} and target not in expected:
                continue
            if target not in expected or target in seen:
                raise snapshot.SnapshotError("recovery_mount_mismatch")
            wanted = expected[target]
            actual_source = item.get("Name") if item["Type"] == "volume" else item["Source"]
            if (
                item["Type"] != wanted["type"]
                or actual_source != wanted["source"]
                or item["RW"] is not (not wanted["readonly"])
            ):
                raise snapshot.SnapshotError("recovery_mount_mismatch")
            seen.add(target)
        if seen != set(expected):
            raise snapshot.SnapshotError("recovery_mount_missing")
        return result

    def start(self, role, *, output=None, maximum=65536, attached=False):
        self.guard()
        result = self.validate(role)
        if result["state"] != "created":
            raise snapshot.SnapshotError("recovery_start_replay")
        self.event("start_requested", {"role": role, "id": result["id"]})
        transport.run(
            ["start", *(["-a"] if attached else []), result["id"]],
            output=output,
            maximum=maximum,
            timeout=self.budget(120 if attached else 20),
        )
        result = self.validate(role)
        if (attached and (result["state"] != "exited" or result["exit"] != 0)) or (
            not attached and result["state"] != "running"
        ):
            raise snapshot.SnapshotError("recovery_start_unconfirmed")
        self.event("started", {"role": role, "id": result["id"], "attached": attached})

    def execute(self, role, program, arguments, *, output=None, source=None, maximum=65536):
        self.guard()
        result = self.validate(role)
        if result["state"] != "running":
            raise snapshot.SnapshotError("recovery_exec_requires_running")
        self.event("exec_requested", {"role": role, "program": program})
        return transport.run(
            ["exec", *(["-i"] if source is not None else []), result["id"], program, *arguments],
            output=output,
            source=source,
            timeout=self.budget(120),
            maximum=maximum,
        )

    def remove(self, role):
        spec = self.resources[role]
        names = self.names(spec["name"])
        if not names:
            self.event("absence_observed", {"role": role, "known_id": spec["id"]})
            if spec["id"] is None:
                raise snapshot.SnapshotError("recovery_absence_does_not_resolve_create_ambiguity")
            return
        if len(names) != 1 or names[0].split()[-1] != spec["name"]:
            raise snapshot.SnapshotError("recovery_cleanup_collision")
        result = self.validate(role)
        if spec["id"] is None:
            self.event("ownership_discovered", {"role": role, "id": result["id"]})
            spec["id"] = result["id"]
        if result["state"] in {"running", "restarting", "paused"}:
            if result["state"] != "running":
                raise snapshot.SnapshotError("recovery_cleanup_unknown_state")
            self.event("stop_requested", {"role": role, "id": result["id"]})
            transport.run(["stop", "--signal=SIGTERM", "--time=5", result["id"]])
            result = self.validate(role)
        if result["state"] not in {"created", "exited"}:
            raise snapshot.SnapshotError("recovery_cleanup_unconfirmed")
        self.event("remove_requested", {"role": role, "id": result["id"]})
        transport.run(["rm", result["id"]])  # No force, no volumes.
        if self.names(spec["name"]):
            raise snapshot.SnapshotError("recovery_cleanup_unconfirmed")
        self.event("absent", {"role": role, "id": result["id"]})

    def cleanup(self):
        failed = []
        for role in reversed(self.resources):
            try:
                self.remove(role)
            except Exception:
                failed.append(role)
        if failed:
            self.event("cleanup_unconfirmed", {"roles": failed})
            raise snapshot.SnapshotError("recovery_cleanup_unconfirmed")
        if self.workspace is not None and self.workspace.exists():
            if (
                self.workspace.is_symlink()
                or self.workspace.parent != Path(tempfile.gettempdir())
                or not self.workspace.name.startswith("aegis-lr-" + self.identifier[:12] + "-")
            ):
                raise snapshot.SnapshotError("recovery_workspace_identity")
            shutil.rmtree(self.workspace)
        self.event("cleanup_verified", {"resources": len(self.resources)})


def mount(source, target, *, readonly=False, kind="bind"):
    return {"type": kind, "source": str(source), "target": target, "readonly": readonly}


def postgres_files(operation, role):
    root = operation.scratch() / role
    snapshot._new(root)
    for name in ("data", "socket"):
        snapshot._new(root / name)
    # Explicit non-root passwd entry also permits initdb under the operator UID.
    vault.write_private(
        root / "passwd",
        f"aegis:x:{os.geteuid()}:{os.getegid()}:recovery:/tmp:/bin/false\n".encode(),
    )
    vault.write_private(root / "group", f"aegis:x:{os.getegid()}:\n".encode())
    vault.write_private(
        root / "hba",
        b"local all all trust\nhost all all 0.0.0.0/0 reject\nhost all all ::/0 reject\n",
    )
    vault.write_private(
        root / "pgconf", b"# Fixed quarantine startup; source configuration remains archived.\n"
    )
    return root


def postgres_mounts(root):
    return [
        mount(root / "data", DATA),
        mount(root / "socket", "/socket"),
        mount(root / "hba", "/hba", readonly=True),
        mount(root / "pgconf", "/pgconf", readonly=True),
        mount(root / "passwd", "/etc/passwd", readonly=True),
        mount(root / "group", "/etc/group", readonly=True),
    ]


def start_postgres(operation, role, image, root, *, fresh):
    if any(
        name in os.environ
        for name in (
            "PGHOST",
            "PGPORT",
            "PGDATABASE",
            "PGUSER",
            "PGPASSWORD",
            "PGPASSFILE",
            "PGSERVICE",
            "PGSERVICEFILE",
            "PGOPTIONS",
            "PGSYSCONFDIR",
        )
    ):
        raise snapshot.SnapshotError("recovery_libpq_environment_refused")
    if fresh:
        init_role = role + "-init"
        operation.create(
            init_role,
            image,
            "/usr/local/bin/initdb",
            ["-D", DATA, "-U", "aegis", "--auth=trust", "--no-locale", "--encoding=UTF8"],
            postgres_mounts(root),
        )
        operation.start(init_role, attached=True)
        operation.remove(init_role)
    auto = root / "data/postgresql.auto.conf"
    if auto.exists():
        auto.rename(root / "original-auto.conf")
    vault.write_private(auto, b"# Quarantine copy: no inherited auto configuration.\n")
    settings = [
        "-D",
        DATA,
        "-c",
        "config_file=/pgconf",
        "-c",
        "shared_preload_libraries=",
        "-c",
        "session_preload_libraries=",
        "-c",
        "local_preload_libraries=",
        "-c",
        "archive_command=",
        "-c",
        "archive_library=",
        "-c",
        "restore_command=",
        "-c",
        "ssl=off",
        "-c",
        "external_pid_file=",
        "-c",
        "logging_collector=off",
        "-c",
        "listen_addresses=",
        "-c",
        "unix_socket_directories=/socket",
        "-c",
        "hba_file=/hba",
        "-c",
        "shared_buffers=32MB",
        "-c",
        "work_mem=2MB",
        "-c",
        "max_connections=12",
        "-c",
        "default_transaction_read_only=on",
        "-c",
        "statement_timeout=15000",
        "-c",
        "max_parallel_workers_per_gather=0",
    ]
    operation.create(role, image, "/usr/local/bin/postgres", settings, postgres_mounts(root))
    operation.start(role)
    for _ in range(30):
        try:
            operation.execute(
                role,
                "/usr/local/bin/pg_isready",
                ["-h", "/socket", "-U", "aegis", "-d", "postgres"],
            )
            break
        except snapshot.SnapshotError:
            time.sleep(0.2)
    else:
        raise snapshot.SnapshotError("recovery_postgres_not_ready")
    return create_engine(
        URL.create(
            "postgresql+psycopg",
            username="aegis",
            database="postgres" if fresh else "aegis",
            query={"host": str(root / "socket")},
        ),
        connect_args={"connect_timeout": 5},
    )


def database_properties(engine):
    with engine.connect() as conn:
        conn.execute(text("SET TRANSACTION READ ONLY"))
        row = (
            conn.execute(
                text(
                    "SELECT pg_encoding_to_char(encoding) AS encoding, datcollate AS lc_collate, datctype AS lc_ctype, datlocprovider AS provider, datcollversion AS collation_version FROM pg_database WHERE datname=current_database()"
                )
            )
            .mappings()
            .one()
        )
    result = {"format": "aegis-pg-database-properties/1", **dict(row)}
    validate_properties(result)
    return result


def validate_properties(properties):
    if (
        not isinstance(properties, dict)
        or set(properties)
        != {"format", "encoding", "lc_collate", "lc_ctype", "provider", "collation_version"}
        or properties["format"] != "aegis-pg-database-properties/1"
        or properties["encoding"] != "UTF8"
        or properties["provider"] != "c"
        or any(
            not isinstance(properties[k], str)
            or not re.fullmatch(r"[A-Za-z0-9_.@-]{1,80}", properties[k])
            for k in ("lc_collate", "lc_ctype")
        )
        or (
            properties["collation_version"] is not None
            and not isinstance(properties["collation_version"], str)
        )
    ):
        raise snapshot.SnapshotError("recovery_database_properties_unsupported")


def restore(operation, folder, manifest_hash, image, properties):
    """Restore a pinned trusted bundle into a fresh cluster; all effects are owned.

    No old approval/session/job is reconciled or activated. Source is read-only;
    cleanup must finish before a verified receipt is returned to the coordinator.
    """
    validate_properties(properties)
    manifest = snapshot.inspect(folder, manifest_hash)
    context = snapshot.Context.model_validate_json(
        snapshot._read(folder / "context.json", snapshot.MAX_JSON)
    )
    if context.images.postgres != image:
        raise snapshot.SnapshotError("recovery_restore_image_mismatch")
    root = postgres_files(operation, "restore")
    engine = start_postgres(operation, "restore", image, root, fresh=True)
    try:
        with engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
            conn.execute(text("SET default_transaction_read_only=off"))
            # Locales are server-observed, constrained literals; no free SQL input.
            conn.exec_driver_sql(
                "CREATE DATABASE aegis_restore TEMPLATE template0 ENCODING 'UTF8' LOCALE_PROVIDER libc LC_COLLATE '"
                + properties["lc_collate"]
                + "' LC_CTYPE '"
                + properties["lc_ctype"]
                + "'"
            )
        engine.dispose()
        engine = create_engine(
            URL.create(
                "postgresql+psycopg",
                username="aegis",
                database="aegis_restore",
                query={"host": str(root / "socket")},
            ),
            connect_args={
                "connect_timeout": 5,
                "options": "-csearch_path=" + context.database_schema + " -ctimezone=UTC",
            },
        )
        if context.database_schema == "public":
            with engine.begin() as conn:
                conn.execute(text("SET LOCAL default_transaction_read_only=off"))
                conn.execute(text("SET TRANSACTION READ WRITE"))
                conn.execute(text("DROP SCHEMA public"))
        if database_properties(engine) != properties:
            raise snapshot.SnapshotError("recovery_database_properties_mismatch")
        archive = snapshot._read(folder / "database.dump", snapshot.MAX_DUMP)
        # Stream immutable verified bytes, never reopen an unchecked mutable path.
        with tempfile.TemporaryFile() as source:
            source.write(archive)
            source.seek(0)
            operation.execute(
                "restore",
                "/usr/bin/env",
                [
                    "PGOPTIONS=-cdefault_transaction_read_only=off",
                    "/usr/local/bin/pg_restore",
                    "-h",
                    "/socket",
                    "-U",
                    "aegis",
                    "-d",
                    "aegis_restore",
                    "--single-transaction",
                    "--exit-on-error",
                    "--no-owner",
                    "--no-privileges",
                ],
                source=source,
            )
        with engine.connect().execution_options(isolation_level="REPEATABLE READ") as conn:
            conn.execute(text("SET TRANSACTION READ ONLY"))
            conn.execute(text("SET LOCAL timezone='UTC'"))
            actual = backup.inventory(
                lambda sql: conn.execute(text(sql)).scalars(), context.database_schema
            )
        expected = snapshot._json(snapshot._read(folder / "inventory.json", snapshot.MAX_JSON))
        vault.write_json(operation.folder / "restored-inventory.json", actual)
        backup.compare(expected, actual)
        # Recheck all journal/fence/context bytes; no rewriting restored history.
        snapshot.inspect(folder, manifest_hash)
        result = {
            "format": "aegis-lab-quarantine-restore/1",
            "snapshot_sha256": manifest_hash,
            "inventory_sha256": digest(actual),
            "database": "aegis_restore",
            "tables": len(actual["tables"]),
            "rows": sum(v["rows"] for v in actual["tables"].values()),
            "snapshot_id": manifest["id"],
            "normal_operation_permitted": False,
            "historical_rows_rewritten": False,
            "old_jobs_resumed": False,
            "database_properties_sha256": digest(properties),
        }
        operation.event("restore_compared", result)
        return result
    finally:
        engine.dispose()
