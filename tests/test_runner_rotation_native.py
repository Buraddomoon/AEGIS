"""Native orchestration with a fake daemon and real disposable SQL/SQLite reviewers."""

import copy
import json
import sys
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest
from aegis.config import settings
from aegis.domain.validation import digest
from aegis.lab_runner import persisted_probe, rotation_probe
from sqlalchemy import text
from test_runner_activation_database_inspection import projection as db_projection
from test_runner_activation_identity_inspection import projection as runner_projection
from test_runner_activation_isolated_network import projection as net_projection
from test_runner_activation_metadata import FakeDocker
from test_runner_activation_plan import code as code
from test_runner_activation_plan import material as material
from test_runner_activation_subnet_review import Docker as Subnets
from test_runner_activation_subnet_review import Routes
from test_runner_mount_templates import render as render
from test_runner_rotation_coordinator import world as world

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import runner_rotation as cli  # noqa: E402
import runner_rotation_native as native  # noqa: E402
import runner_rotation_package as package  # noqa: E402
from runner_activation_intents import ROTATION_RUNNERS  # noqa: E402


def native_package(world, tmp_path):
    artifact = world.c.artifact
    evidence = {
        "format": "aegis-linux-schema-clone-evidence/1",
        "source_volume_sha256": digest(artifact["metadata"]["volumes"]["postgres-data"]),
        "source_schema": "d4465b7aca2a",
        "clone_schema": "b7f3c2d91a06",
        "backup_sha256": "a" * 64,
        "restored_inventory_sha256": "b" * 64,
        "upgraded_old_inventory_sha256": "b" * 64,
        "clone_restore_verified": True,
        "old_rows_preserved": True,
        "grants_verified": True,
        "original_modified": False,
    }
    with world.engine.connect() as connection:
        actor = connection.scalar(text("SELECT id FROM users WHERE username='administrator'"))
    item = {
        "format": package.FORMAT,
        "id": uuid4().hex,
        "profile": package.PROFILE,
        "base_plan_path": str(world.c.path),
        "base_plan_sha256": world.c.plan_sha256,
        "expires_at": artifact["expires_at"],
        "build_inputs": {"fixture": True},
        "postgres_origin": {"fixture": True},
        "clone_evidence": evidence,
        "clone_evidence_sha256": digest(evidence),
        "actor_id": actor,
        "registration": {
            "name": "Native fixture",
            "owner": "Disposable reviewer",
            "isolation_review": "Fake Docker; real disposable SQL and SQLite, no original volume.",
            "confirm_isolation_review": True,
        },
    }
    folder = tmp_path / "packages" / item["id"]
    folder.mkdir(parents=True, mode=0o700)
    path = folder / "package.json"
    path.write_text(json.dumps(item))
    path.chmod(0o600)
    return path, digest(item)


class Daemon:
    def __init__(self, world, monkeypatch, tmp_path):
        self.world, self.objects, self.effects, self.calls = world, {}, [], []
        self.scene, self.counter, self.last_error = None, 0, None
        path, sha = native_package(world, tmp_path)
        self.c = package.NativeConfirmation(path, sha, sha, world.c.store)
        self.c.store.append(
            "rotation_scope_confirmed",
            {"package_sha256": sha, "expires_at": self.c.expires.isoformat()},
        )
        self.client = native.NativeRotation(
            self.c,
            "private-fixture-password",
            rpc=self.rpc,
            root=tmp_path / "native",
            subnet_reader=Subnets(),
            routes=Routes(),
        )
        monkeypatch.setattr(native.image, "review", lambda *a, **kw: {"fixture": True})
        monkeypatch.setattr(native.postgres, "review", lambda *a, **kw: {"fixture": True})
        # SQL physical endpoint is a fixture; production executes the unchanged
        # fixed-database guard and grants as aegis_app in the DB network namespace.
        original_schema = persisted_probe._require_schema
        with world.engine.connect() as connection:
            namespace = connection.scalar(text("SELECT current_schema()"))
        monkeypatch.setattr(
            persisted_probe, "_require_schema", lambda conn, name: original_schema(conn, namespace)
        )
        monkeypatch.setattr(
            persisted_probe,
            "_require_fixed_database",
            lambda conn: original_schema(conn, namespace),
        )
        monkeypatch.setattr(rotation_probe, "_engine", lambda *a: world.engine)
        monkeypatch.setattr(rotation_probe, "STATE", tmp_path / "state")
        monkeypatch.setattr(settings(), "linux_runner_config", settings().linux_runner_config)
        from aegis import linux_labs

        monkeypatch.setattr(linux_labs, "descriptor", lambda: copy.deepcopy(world.new))
        monkeypatch.setattr(linux_labs, "connection", lambda: SimpleNamespace())
        monkeypatch.setattr(rotation_probe, "previous_trust_rejected", lambda config: True)

    def metadata(self, kind, value=None):
        fake = FakeDocker()
        active = {r: o for r, o in self.objects.items() if r != native.network.ROLE}

        def ids(values):
            return "".join(v + "\n" for v in sorted(values)).encode()

        if kind == "containers":
            result = {o["id"] for o in active.values()}
            if self.scene == "foreign_worker":
                result.add("f" * 64)
            return ids(result)
        if kind == "networks":
            return ids(
                {self.objects[native.network.ROLE]["id"]}
                if native.network.ROLE in self.objects
                else set()
            )
        if kind == "network_name":
            return self.metadata("networks") if value == "isolated" else b""
        if kind == "consumers":
            roles = (
                {"db"}
                if value == "postgres-data"
                else ROTATION_RUNNERS | native.runtime.JOURNAL_ROLES
            )
            values = {o["id"] for r, o in active.items() if r in roles}
            if self.scene == "foreign_volume" and value == "journal":
                values.add("f" * 64)
            return ids(values)
        return fake.query(kind, value)

    def ownership(self, args):
        expected = [o for o in self.objects.values() if o["name"] == args[-1]]
        if args[1] == "inspect":
            obj = expected[0]
            labels = native.runtime.resource(self.c.operation, self.c.plan_sha256, obj["role"])[
                "labels"
            ]
            item = {
                "id": obj["id"],
                "name": ("" if obj["role"] == native.network.ROLE else "/") + obj["name"],
                **{key: labels[label] for key, label in native.ownership.LABELS.items()},
            }
            if obj["role"] == native.network.ROLE:
                item["member_count"] = len(self.network()["containers"])
            else:
                item.update(image=obj["spec"]["image"], running=obj["phase"] == "running")
            return json.dumps(item).encode()
        kind, value = args[-1].split("=", 1)
        if kind == "name":
            selected = [o for o in self.objects.values() if value in o["name"]]
        elif kind == "id":
            selected = [o for o in self.objects.values() if value == o["id"]]
        else:
            selected = [
                o
                for o in self.objects.values()
                if value.endswith(self.c.operation + ":" + o["role"])
            ]
        return "".join(o["id"] + "\n" for o in selected).encode()

    def network(self):
        item = net_projection(native.network.recipe(self.c.store))
        item["id"] = self.objects[native.network.ROLE]["id"]
        for role, obj in self.objects.items():
            if role == "db" or role in ROTATION_RUNNERS:
                if obj["phase"] == "running":
                    item["containers"][obj["id"]] = {
                        "Name": obj["name"],
                        "IPv4Address": obj["spec"]["ipv4_address"] + "/29",
                        "IPv6Address": "",
                    }
        return item

    def projection(self, obj):
        spec, phase = obj["spec"], obj["phase"]
        if obj["role"] == "db":
            item = db_projection(spec, phase)
            item["network_names"] = [spec["network_name"], None]
        else:
            item = runner_projection(spec, phase)
            if obj["role"] not in ROTATION_RUNNERS:
                item.update(stdin_open=True, network_names=[None], endpoints=[None])
            if spec["volume"]:
                for name in ("mounts", "configured_mounts"):
                    item[name].append(
                        {
                            "type": "volume",
                            "target": "/state",
                            "source_matches": False,
                            "writable": not spec["volume_readonly"],
                            "propagation": "",
                            "bind_options": None,
                        }
                    )
        item.update(id=obj["id"], image=spec["image"], image_reference=spec["image"])
        volume = native.runtime.dbserver.VOLUME if obj["role"] == "db" else spec["volume"]
        target = native.runtime.dbserver.DATA if obj["role"] == "db" else "/state"
        writable = obj["role"] == "db" or obj["role"] in ROTATION_RUNNERS
        binds = (
            [native.runtime.dbserver.HBA] if obj["role"] == "db" else list(spec["mount_sources"])
        )
        for field, effective in (("native_volumes", True), ("native_configured", False)):
            item[field] = [
                {
                    "type": "bind",
                    "target": k,
                    "name": None,
                    "writable": False,
                    "no_copy": None if effective else False,
                }
                for k in binds
            ]
            if volume:
                item[field].append(
                    {
                        "type": "volume",
                        "target": target,
                        "name": volume,
                        "writable": writable,
                        "no_copy": None if effective else True,
                    }
                )
        if self.scene == "writable_journal" and obj["role"] == "rotation-review-before":
            item["native_volumes"][-1]["writable"] = True
        if self.scene == "integer_mount" and obj["role"] == "rotation-review-before":
            item["native_volumes"][-1]["writable"] = 0
        if obj["role"] == "rotation-review-before":
            if self.scene == "namespace":
                item["host"]["NetworkMode"] = "host"
            if self.scene == "uid":
                item["user"] = "0:0"
            if self.scene == "argv":
                item["arguments"] = ["-c", "untrusted"]
            if self.scene == "writable_key":
                item["mounts"][0]["writable"] = True
            if self.scene == "wrong_key":
                item["mounts"][0]["source_matches"] = False
        return item

    def rpc(self, args, *, payload=None, **kwargs):
        args = tuple(args)
        self.calls.append(args)
        for kind, value in [
            ("daemon", None),
            *[("image", self.client.images[r]) for r in native.metadata.IMAGES],
            *[("volume", v) for v in native.metadata.VOLUMES],
            ("containers", None),
            ("networks", None),
            *[("network_name", v) for v in native.metadata.NETWORKS],
            *[("consumers", v) for v in native.metadata.VOLUMES],
        ]:
            if args == native.metadata.command(kind, value):
                return self.metadata(kind, value)
        if args[:2] == ("image", "inspect"):
            image = args[-1]
            if image == self.client.images["postgres"]:
                return json.dumps(
                    {
                        "id": image,
                        "user": "",
                        "volumes": {native.runtime.dbserver.DATA: {}},
                        "exposed_ports": {"5432/tcp": {}},
                        "label_count": 0,
                        "onbuild": None,
                        "environment": [
                            {"key": k, "valid": True} for k in native.database.ENV_FIXED
                        ],
                    }
                ).encode()
            return json.dumps(
                {
                    "id": image,
                    "user": "10001:10001",
                    "volumes": None,
                    "ports": None,
                    "onbuild": None,
                    "environment": [
                        {"key": k, "valid": True} for k in native.physical.probe.ENV_FIXED
                    ],
                }
            ).encode()
        if args[:2] in (("network", "create"), ("container", "create")):
            labels = [args[i + 1] for i, k in enumerate(args) if k == "--label"]
            role = next(
                k.split("=", 1)[1] for k in labels if k.startswith("io.aegis.activation-role=")
            )
            assert self.c.store.review()["resources"][role]["state"] == "REQUESTED"
            if self.scene == "create_ambiguous" and role == "rotation-review-before":
                raise ValueError("private-fixture-password")
            self.counter += 1
            spec = (
                native.network.recipe(self.c.store)
                if role == native.network.ROLE
                else self.client.recipes[role]
            )
            obj = {
                "id": f"{self.counter:064x}",
                "name": spec["name"],
                "role": role,
                "spec": spec,
                "phase": "created",
            }
            self.objects[role] = obj
            self.effects.append(("create", role))
            return (obj["id"] + "\n").encode()
        if args[:2] == ("container", "start"):
            obj = next(o for o in self.objects.values() if o["id"] == args[-1])
            role = obj["role"]
            assert self.c.store.review()["resources"][role]["state"] == "START_REQUESTED"
            self.effects.append(("start", role))
            obj["phase"] = "exited" if payload else "running"
            if self.scene == "interrupt" and role == "rotation-binding":
                raise KeyboardInterrupt
            if self.scene == "expired" and role == "rotation-identity-before":
                self.c.deadline = 0
            if not payload:
                return b""
            sha = obj["spec"]["arguments"][-1]
            request = rotation_probe.decode(payload, sha)
            try:
                result = rotation_probe.execute(request)
            except Exception as error:
                self.last_error = error
                raise
            if self.scene == "bad_preflight" and request["mode"] == "preflight":
                result["preflight_verified"] = False
            if self.scene == "integer_preflight" and request["mode"] == "preflight":
                result["preflight_verified"] = 1
            if self.scene == "commit_ambiguous" and request["mode"] == "binding":
                raise ValueError("private-fixture-password")
            return json.dumps(
                {
                    "format": rotation_probe.RESULT,
                    "context_sha256": sha,
                    "mode": request["mode"],
                    "status": "phase_verified",
                    "result": result,
                }
            ).encode()
        if args[:2] == ("container", "exec"):
            return b""
        if args[:2] in (("container", "stop"), ("container", "rm"), ("network", "rm")):
            obj = next(o for o in self.objects.values() if o["id"] == args[-1])
            role = obj["role"]
            self.effects.append((args[1], role))
            if self.scene == "cleanup" and role == "rotation-review-before":
                raise native.ActivationError("fixture_cleanup_unconfirmed")
            if args[1] == "stop":
                obj["phase"] = "exited"
            else:
                del self.objects[role]
            return b""
        if (
            args[:2] == ("network", "inspect")
            and args[args.index("--format") + 1] == native.network.FORMAT
        ):
            return json.dumps(self.network()).encode()
        if (
            args[:2] == ("container", "inspect")
            and "native_volumes" in args[args.index("--format") + 1]
        ):
            obj = next(o for o in self.objects.values() if o["id"] == args[-1])
            return json.dumps(self.projection(obj)).encode()
        return self.ownership(args)


@pytest.fixture
def daemon(world, monkeypatch, tmp_path):
    from alembic import command
    from alembic.config import Config

    config = Config("alembic.ini")
    command.downgrade(config, "d4465b7aca2a")
    try:
        yield Daemon(world, monkeypatch, tmp_path)
    finally:
        command.upgrade(config, "head")


def test_native_adapter_runs_every_phase_with_real_reviewers_and_preserves_revocation(daemon):
    result = daemon.client.execute()
    assert result["status"] == "native_rotation_verified_and_closed", (
        result,
        daemon.last_error,
        daemon.effects,
    )
    assert not daemon.objects and daemon.c.store.review()["closed"]
    assert result["binding_commit_state"] == "committed_revoked"
    assert not result["normal_operation_permitted"] and not result["marker_executed"]
    starts = [r for k, r in daemon.effects if k == "start"]
    assert starts == [
        "db",
        "rotation-review-before",
        "rotation-runner-before",
        "rotation-identity-before",
        "rotation-binding",
        "rotation-runner-after",
        "rotation-preflight",
        "rotation-review-after",
    ]
    assert len(daemon.c.store.events) <= 64
    assert "private-fixture-password" not in json.dumps(result)


@pytest.mark.parametrize(
    "scene",
    [
        "foreign_worker",
        "foreign_volume",
        "namespace",
        "uid",
        "argv",
        "writable_key",
        "wrong_key",
        "writable_journal",
        "integer_mount",
        "integer_preflight",
        "create_ambiguous",
        "commit_ambiguous",
        "bad_preflight",
        "interrupt",
        "expired",
        "cleanup",
    ],
)
def test_native_failures_never_replay_and_always_attempt_owned_cleanup(daemon, scene):
    daemon.scene = scene
    if scene == "interrupt":
        with pytest.raises(KeyboardInterrupt):
            daemon.client.execute()
        result = json.loads((daemon.client.folder / "receipt.json").read_bytes())
    else:
        result = daemon.client.execute()
    assert not result["activation_verified"], (result, daemon.last_error)
    assert "private-fixture-password" not in json.dumps(result)
    starts = [r for k, r in daemon.effects if k == "start"]
    assert len(starts) == len(set(starts))
    if scene == "cleanup":
        assert not result["managed_resources_absence_verified"]
        assert "db" in daemon.objects and native.network.ROLE in daemon.objects
    else:
        assert result["managed_resources_absence_verified"] and not daemon.objects


def test_native_cli_requires_explicit_approved_scope_before_loading_or_starting(monkeypatch):
    monkeypatch.setattr(
        cli.package, "load", lambda *a, **kw: pytest.fail("No IO before explicit confirmation")
    )
    with pytest.raises(native.ActivationError, match="explicit_specific"):
        cli.run(Path("absent"), "a" * 64, "a" * 64, "secret")


def test_native_scope_refuses_clone_evidence_from_another_volume(world, tmp_path):
    path, sha = native_package(world, tmp_path)
    item, artifact = package.load(path, sha)
    item["clone_evidence"]["source_volume_sha256"] = "f" * 64
    with pytest.raises(native.ActivationError, match="clone_evidence"):
        package.backup_evidence(item["clone_evidence"], digest(item["clone_evidence"]), artifact)


def test_reconstructing_native_confirmation_cannot_extend_original_expiration(daemon, monkeypatch):
    from datetime import timedelta

    c = daemon.c
    later = c.confirmed_at + timedelta(seconds=20)
    monkeypatch.setattr(native.base.pki, "clock", lambda: later)
    resumed = package.NativeConfirmation(
        c.package_path, c.package_sha256, c.package_sha256, c.store
    )
    assert resumed.expires == c.expires
    assert resumed.deadline < c.deadline


def test_unconfirmed_image_provenance_denies_before_any_docker_effect(daemon, monkeypatch):
    def reject(*args, **kwargs):
        raise native.ActivationError("fixture_unconfirmed_image")

    monkeypatch.setattr(native.image, "review", reject)
    report = daemon.client.execute()
    assert report["status"] == "native_rotation_failed_and_closed"
    assert daemon.effects == []


@pytest.mark.parametrize(
    "change", ["extra", "duplicate", "mode", "hash", "expired", "secret", "identity", "baseline"]
)
def test_private_admin_request_rejects_malformed_context_before_sql(world, change):
    from datetime import timedelta
    from uuid import UUID

    value = {
        "format": rotation_probe.FORMAT,
        "operation_id": str(UUID(hex=world.c.operation)),
        "plan_sha256": world.c.plan_sha256,
        "scope_sha256": world.c.scope,
        "expires_at": world.c.expires.isoformat(),
        "mode": "review-before",
        "identity": world.identity.model_dump(mode="json"),
        "old_descriptor_sha256": digest(world.old),
        "new_descriptor_sha256": digest(world.new),
        "actor_id": str(uuid4()),
        "registration": {},
        "baseline": None,
        "database_password": "private-fixture-password",
    }
    if change == "extra":
        value["command"] = "never permitted"
    if change == "mode":
        value["mode"] = "start"
    if change == "expired":
        value["expires_at"] = (native.base.pki.clock() - timedelta(seconds=1)).isoformat()
    if change == "secret":
        value["database_password"] = ""
    if change == "identity":
        value["identity"]["tests"] = []
    if change == "baseline":
        value["baseline"] = {}
    raw = json.dumps(value).encode()
    if change == "duplicate":
        raw = raw[:-1] + b',"mode":"review-before"}'
    expected = (
        "f" * 64
        if change == "hash"
        else digest({k: v for k, v in value.items() if k != "database_password"})
    )
    with pytest.raises(ValueError):
        rotation_probe.decode(raw, expected)


@pytest.mark.parametrize("effective", [False, True])
def test_native_mount_projection_uses_real_cli_without_leaking_bind_source(render, effective):
    configured = [
        {
            "Type": "volume",
            "Source": native.runtime.STATE_VOLUME,
            "Target": "/state",
            "ReadOnly": True,
            "VolumeOptions": {"NoCopy": True},
        },
        {
            "Type": "bind",
            "Source": "/private/unpublished/key",
            "Target": "/run/secrets/controller_client_key",
            "ReadOnly": True,
        },
    ]
    document = {
        "HostConfig": {"Mounts": configured},
        "Mounts": [
            {
                "Type": "volume",
                "Name": native.runtime.STATE_VOLUME,
                "Source": "/private/daemon/storage",
                "Destination": "/state",
                "RW": False,
            },
            {
                "Type": "bind",
                "Source": "/private/unpublished/key",
                "Destination": "/run/secrets/controller_client_key",
                "RW": False,
            },
        ],
    }
    value = render(native.runtime._volume_projection(effective), document=document)
    assert value[0] == {
        "type": "volume",
        "target": "/state",
        "name": native.runtime.STATE_VOLUME,
        "writable": False,
        "no_copy": None if effective else True,
    }
    assert "/private/" not in json.dumps(value)


def test_expired_gate_after_intent_publication_never_starts_a_service(daemon, monkeypatch):
    original = daemon.client.record
    clock = native.time.monotonic

    def delayed(name, body):
        original(name, body)
        if name == "db-start-gate":
            monkeypatch.setattr(native.time, "monotonic", lambda: clock() + 30)

    monkeypatch.setattr(daemon.client, "record", delayed)
    report = daemon.client.execute()
    assert not report["activation_verified"]
    assert ("start", "db") not in daemon.effects
    assert report["managed_resources_absence_verified"]


def test_native_help_does_not_run_or_prepare_anything(monkeypatch):
    monkeypatch.setattr(cli, "run", lambda *a, **k: pytest.fail("No run on help"))
    monkeypatch.setattr(cli.package, "prepare", lambda *a, **k: pytest.fail("No prepare on help"))
    with pytest.raises(SystemExit) as result:
        cli.main(["--help"])
    assert result.value.code == 0


@pytest.mark.parametrize("revision", ["a0d9c7e21b45", "b7f3c2d91a06"])
def test_d446_native_profile_refuses_newer_schema_without_implicit_downgrade(daemon, revision):
    from alembic import command
    from alembic.config import Config

    command.upgrade(Config("alembic.ini"), revision)
    report = daemon.client.execute()
    assert not report["activation_verified"]
    assert report["binding_commit_state"] == "not_requested"
    assert daemon.world.calls == 0


def test_cleanup_uses_historical_pins_after_package_and_authorization_expire(
    daemon, monkeypatch, tmp_path
):
    import shutil
    from datetime import timedelta

    report = daemon.client.execute()
    assert report["activation_verified"], (report, daemon.last_error)
    root = tmp_path / "cleanup-copy"
    shutil.copytree(daemon.c.store.root, root)
    root.chmod(0o700)
    monkeypatch.setattr(cli, "DEFAULT_ROOT", root)
    monkeypatch.setattr(cli.metadata, "_execute", daemon.rpc)
    current = native.base.pki.clock()
    monkeypatch.setattr(native.base.pki, "clock", lambda: current + timedelta(days=1))
    count = len(daemon.effects)
    result = cli.cleanup(
        daemon.c.package_path, daemon.c.package_sha256, daemon.c.operation, daemon.c.begin_sha256
    )
    assert result["managed_resources_absence_verified"]
    assert len(daemon.effects) == count


def test_native_profile_rejects_integer_substitution_even_with_recomputed_outer_hash(
    world, tmp_path
):
    path, _ = native_package(world, tmp_path)
    value = json.loads(path.read_bytes())
    value["profile"]["executor_implemented"] = 1
    path.write_text(json.dumps(value))
    with pytest.raises(native.ActivationError, match="profile_invalid"):
        package.load(path, digest(value))


@pytest.mark.parametrize("version,profile", [(1, package.PROFILE_B7), (2, package.PROFILE_A0)])
def test_historical_profiles_are_cleanup_only_without_rewriting_their_scope(
    world, tmp_path, version, profile
):
    path, _ = native_package(world, tmp_path)
    value = json.loads(path.read_bytes())
    value["format"] = f"aegis-native-rotation-package/{version}"
    value["profile"] = profile
    value["clone_evidence"]["source_schema"] = "a0d9c7e21b45"
    value["clone_evidence_sha256"] = digest(value["clone_evidence"])
    path.write_text(json.dumps(value))
    assert package.load(path, digest(value), current=False)[0] == value
    with pytest.raises(native.ActivationError, match="profile_invalid"):
        package.load(path, digest(value))


@pytest.mark.parametrize(
    "code,expected",
    [(18, True), (19, True), (20, True), (21, True), (10, False), (9, False), (62, False)],
)
def test_previous_trust_control_distinguishes_path_rejection_from_expiry(
    monkeypatch, code, expected
):
    import ssl
    from contextlib import nullcontext

    config = SimpleNamespace(
        client_cert=Path("/reviewed/client.crt"), client_key=Path("/reviewed/client.key")
    )

    class Context:
        def load_cert_chain(self, cert, key):
            assert (cert, key) == (str(config.client_cert), str(config.client_key))

        def wrap_socket(self, raw, *, server_hostname):
            assert server_hostname == "192.168.253.2"
            error = ssl.SSLCertVerificationError(1, "fixture")
            error.verify_code = code
            raise error

    def connect(endpoint, *, timeout):
        assert endpoint == ("192.168.253.2", 8443) and timeout == 2
        return nullcontext(object())

    monkeypatch.setattr(rotation_probe.ssl, "create_default_context", lambda **kw: Context())
    monkeypatch.setattr(rotation_probe.socket, "create_connection", connect)
    assert rotation_probe.previous_trust_rejected(config) is expected
