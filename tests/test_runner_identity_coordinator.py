"""Complete real gate/intent/artifact flow over fixture RPC; not native TLS evidence."""

import json
import sys
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from test_runner_activation_identity_client_inspection import projected
from test_runner_activation_identity_inspection import projection
from test_runner_activation_identity_network import member
from test_runner_activation_isolated_network import projection as bridge_projection
from test_runner_activation_metadata import FakeDocker
from test_runner_activation_ownership import OBJECT
from test_runner_activation_ownership import FakeDocker as Owner
from test_runner_activation_plan import code as code
from test_runner_activation_plan import material as material
from test_runner_activation_plan import prepare
from test_runner_activation_subnet_review import Docker as SubnetDocker
from test_runner_activation_subnet_review import Routes

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import runner_identity_coordinator as coordinator  # noqa: E402
import runner_identity_review as saved_review  # noqa: E402
from runner_activation_intents import ActivationIntents  # noqa: E402

IDS = {"network-isolated": "c" * 64, "runner": OBJECT, "identity-client": "e" * 64}
SECRET = "private-sensitive-sentinel"


class World:
    def __init__(self, c, root, monkeypatch):
        self.c, self.root, self.monkeypatch = c, root, monkeypatch
        self.effects, self.scene = [], None
        self.meta = FakeDocker()
        self.owners = {}
        image = c.artifact["metadata"]["images"]["runner"]["id"]
        for role, identifier in IDS.items():
            owner = Owner(c.operation, role, present=False)
            owner.details.update(id=identifier, plan=c.plan_sha256)
            if role != "network-isolated":
                owner.details.update(image=image, running=False)
            self.owners[role] = owner
        self.bridge = bridge_projection(coordinator.network.network.recipe(c.store))
        self.bridge["id"] = IDS["network-isolated"]
        self.host_spec, self.client_spec = None, None
        self.host_phase, self.client_phase = "created", "created"
        self.image = {
            "id": image,
            "user": "10001:10001",
            "volumes": None,
            "environment": [
                {"key": k, "valid": True} for k in coordinator.server.inspection.probe.ENV_FIXED
            ],
            "ports": None,
            "onbuild": None,
        }
        # Sealed-source/image proof is an explicit fixture boundary tested in its
        # dedicated suite. All PKI/active/physical/network gate composition is real.
        monkeypatch.setattr(
            coordinator.recorded.server.image,
            "review",
            lambda *a, **kw: {
                "native_image_id": image,
                "tool_commit": c.artifact["tool_commit"],
                "package_and_dependency_sources_current": True,
                "build_client_exit_verified": True,
            },
        )
        monkeypatch.setattr(coordinator.client.driver, "_execute", self.client_rpc)
        c.docker, c.ownership_docker = self.meta, self
        c.subnet_docker, c.routes = SubnetDocker(), Routes()
        self.adapters = coordinator.Adapters(
            bridge_create=SimpleNamespace(create=self.bridge_create),
            bridge_runtime=self,
            server=self,
            server_runtime=self,
            server_network=self,
            client_runtime=self,
            client_network=self,
            cleanup=self,
        )

    def present(self, role, present=True):
        owner = self.owners[role]
        owner.named = owner.labelled = owner.known = (IDS[role] + "\n").encode() if present else b""
        self.meta.responses["containers", None] = b"".join(
            self.owners[r].named for r in ("runner", "identity-client")
        )
        self.meta.responses["networks", None] = self.owners["network-isolated"].named
        self.meta.responses["network_name", "isolated"] = self.owners["network-isolated"].named

    def query(self, *args, **kwargs):
        if isinstance(args[0], str) and args[0] in {"image", "container"}:
            if args[0] == "image":
                value = self.image
            elif kwargs["spec"]["role"] == "runner":
                value = projection(kwargs["spec"], self.host_phase)
                if self.scene == "unsafe_server" and self.host_phase == "running":
                    value["mounts"][0]["writable"] = True
            else:
                value = projected(kwargs["spec"], self.client_phase)
            return json.dumps(value).encode()
        if len(args) == 2:
            return json.dumps(self.bridge).encode()
        return self.owners[args[3]].query(*args)

    def proof(self, name):
        item = json.loads((self.root / self.c.operation / (name + ".json")).read_bytes())
        assert item["plan_sha256"] == self.c.plan_sha256
        assert item["begin_sha256"] == self.c.begin_sha256
        return item["body"]

    def bridge_create(self, store):
        assert store is self.c.store
        assert self.proof("network-create-gate")["gate"]["phase"] == "create"
        assert store.review()["resources"]["network-isolated"]["state"] == "REQUESTED"
        self.effects.append("network_create")
        self.present("network-isolated")
        if self.scene == "network_ambiguous":
            raise OSError(SECRET)
        return IDS["network-isolated"]

    def create(self, c):
        assert c is self.c
        assert self.proof("server-create-gate")["gate"]["phase"] == "create"
        self.host_spec = coordinator.server.runtime.recipe(c.store, c.path, c.plan_sha256)
        self.effects.append("server_create")
        self.present("runner")
        return IDS["runner"]

    def start(self, c, known):
        assert c is self.c and known == IDS["runner"]
        assert self.proof("server-start-gate")["gate"]["phase"] == "start"
        assert c.store.review()["resources"]["runner"]["state"] == "START_REQUESTED"
        self.effects.append("server_start")
        self.owners["runner"].details["running"] = True
        self.host_phase = "running"
        self.bridge["containers"] = {IDS["runner"]: member(self.host_spec)}
        self.owners["network-isolated"].details["member_count"] = 1

    def client_rpc(self, args, *, timeout, payload=None, output_limit=None):
        request = self.proof("client-request")
        spec = coordinator.client.runtime.recipe(
            self.c.store, self.c.path, self.c.plan_sha256, request["context_sha256"]
        )
        if args[:2] == ("container", "create"):
            assert self.proof("client-create-gate")["gate"]["phase"] == "create"
            assert self.c.store.review()["resources"]["identity-client"]["state"] == "REQUESTED"
            self.effects.append("client_create")
            self.client_spec = spec
            self.present("identity-client")
            return (IDS["identity-client"] + "\n").encode()
        assert args == ("container", "start", "--attach", "--interactive", IDS["identity-client"])
        assert self.proof("client-start-gate")["gate"]["phase"] == "start"
        assert self.c.store.review()["resources"]["identity-client"]["state"] == "START_REQUESTED"
        assert json.loads(payload) == request["request"] and output_limit == 4096
        self.effects.append("client_start")
        if self.scene == "interrupt":
            raise KeyboardInterrupt
        self.client_phase = "exited"
        if self.scene == "expired":
            self.monkeypatch.setattr(coordinator.network.plan.pki, "clock", lambda: self.c.expires)
        if self.scene == "bad_wire":
            return json.dumps({"status": "rejected", "error": SECRET}).encode()
        # Closed protocol fixtures are not certificates or native TLS evidence.
        omission = (
            "connection_closed_without_tls_reason"
            if self.scene == "inconclusive"
            else "certificate_required_alert"
        )
        return json.dumps(coordinator.request.probe._result(request["request"], omission)).encode()

    def effect(self, kind, operation, plan, role, known):
        assert operation == self.c.operation and plan == self.c.plan_sha256
        assert role in IDS and known == IDS[role]
        assert self.c.store.review()["resources"][role]["state"] == "REMOVAL_REQUESTED"
        self.effects.append(role + "_" + kind)
        if self.scene == "cleanup_failure" and role == "identity-client":
            raise OSError(SECRET)
        if kind == "stop":
            self.owners[role].details["running"] = False
        else:
            self.present(role, False)
            self.bridge["containers"].pop(known, None)
            self.owners["network-isolated"].details["member_count"] = len(self.bridge["containers"])

    def execute(self):
        return coordinator.execute(
            self.c, {"fixture": "sealed boundary"}, adapters=self.adapters, root=self.root
        )


@pytest.fixture
def world(material, code, tmp_path, monkeypatch):
    prepared, _ = prepare(material, tmp_path)
    with ActivationIntents(tmp_path / "intents") as store:
        store.begin(prepared["id"], prepared["plan_sha256"], prepared["scope_sha256"])
        c = coordinator.network.NetworkGates(
            Path(prepared["plan_path"]),
            prepared["plan_sha256"],
            store,
            prepared["scope_sha256"],
            (coordinator.network.plan.pki.clock() + timedelta(seconds=230)).isoformat(),
        )
        yield World(c, tmp_path / "records", monkeypatch)


@pytest.mark.parametrize("scene", [None, "inconclusive"])
def test_complete_flow_persists_before_each_effect_and_preserves_inconclusive_controls(
    world, scene
):
    world.scene = scene
    result = world.execute()
    expected = "inconclusive" if scene else "verified"
    assert result["status"] == "identity_assay_" + expected + "_and_closed"
    assert result["tls_controls_verified"] is (scene is None)
    assert result["managed_resources_absence_verified"] is True
    assert world.c.store.review()["closed"] is True
    assert all(item["state"] == "ABSENT" for item in world.c.store.review()["resources"].values())
    assert world.effects == [
        "network_create",
        "server_create",
        "server_start",
        "client_create",
        "client_start",
        "identity-client_remove",
        "runner_stop",
        "runner_remove",
        "network-isolated_remove",
    ]
    files = list((world.root / world.c.operation).iterdir())
    assert len(files) == 14
    for name, expected_sha in result["artifacts"].items():
        item = json.loads((world.root / world.c.operation / (name + ".json")).read_bytes())
        assert coordinator.digest(item) == expected_sha
    assert world.proof("receipt") == result
    for key in (
        "marker_executed",
        "worker_started",
        "database_started",
        "journal_opened",
        "wazuh_started",
        "pki_activated",
        "binding_changed",
        "old_client_rejection_verified",
        "normal_operation_permitted",
        "volumes_removed",
    ):
        assert result[key] is False
    before = list(world.effects)
    with pytest.raises(coordinator.ActivationError):
        world.execute()
    assert world.effects == before
    assert SECRET not in b"".join(p.read_bytes() for p in files).decode()
    world.monkeypatch.setattr(
        coordinator.network.plan.pki, "clock", lambda: world.c.expires + timedelta(days=2)
    )
    review = saved_review.review(
        world.c.operation,
        world.c.begin_sha256,
        world.c.plan_sha256,
        world.c.scope,
        coordinator.digest(result),
        root=world.root,
    )
    assert review["recorded_assay_status"] == result["status"]
    assert review["recorded_tls_controls_verified"] is (scene is None)
    assert review["records_reviewed"] == 14 and review["native_runtime_rechecked"] is False


@pytest.mark.parametrize("scene", ["network_ambiguous", "unsafe_server", "bad_wire", "expired"])
def test_failures_close_only_owned_resources_without_claiming_tls_or_replaying(world, scene):
    world.scene = scene
    result = world.execute()
    assert result["status"] == "identity_assay_failed_and_closed"
    assert result["error"] == "identity_assay_execution_unconfirmed"
    assert result["tls_controls_verified"] is False
    assert result["managed_resources_absence_verified"] is True
    assert world.c.store.review()["closed"] is True
    assert all(not item.named for item in world.owners.values())
    if scene == "network_ambiguous":
        assert world.effects == ["network_create", "network-isolated_remove"]
    if scene == "unsafe_server":
        assert "client_create" not in world.effects
    assert SECRET not in json.dumps(result)


def test_uncertain_client_cleanup_retains_parents_and_never_reports_success(world):
    world.scene = "cleanup_failure"
    result = world.execute()
    assert result["status"] == "identity_assay_cleanup_unconfirmed"
    assert result["tls_controls_verified"] is False
    assert result["managed_resources_absence_verified"] is False
    assert world.c.store.review()["closed"] is False
    assert all(item.named for item in world.owners.values())
    assert "runner_stop" not in world.effects and "network-isolated_remove" not in world.effects


def test_failed_client_preserves_a_reviewable_inventory_without_promoting_tls(world):
    world.scene = "bad_wire"
    result = world.execute()
    assert result["status"] == "identity_assay_failed_and_closed"
    assert result["artifact_inventory_verified"] is True
    assert result["artifacts"] is not None
    report = saved_review.review(
        world.c.operation,
        world.c.begin_sha256,
        world.c.plan_sha256,
        world.c.scope,
        coordinator.digest(result),
        root=world.root,
    )
    assert report["recorded_tls_controls_verified"] is False
    assert report["recorded_assay_status"] == "identity_assay_failed_and_closed"


def test_gate_expiring_in_driver_keeps_the_reason_and_cleans_without_start_or_retry(
    world, monkeypatch
):
    command = coordinator.client.driver.command

    def delayed(kind, reviews, known_id=None):
        args = command(kind, reviews, known_id)
        if kind == "start":
            checked = coordinator.client.gates.datetime.fromisoformat(
                reviews._last_gate["checked_at"]
            )
            # Disposable fixture clock models time spent preparing the command.
            monkeypatch.setattr(
                coordinator.network.plan.pki,
                "clock",
                lambda: checked + timedelta(seconds=10.1),
            )
        return args

    monkeypatch.setattr(coordinator.client.driver, "command", delayed)
    result = world.execute()
    assert result["status"] == "identity_assay_failed_and_closed"
    assert result["failure_code"] == "journal_probe_gate_stale"
    assert result["artifact_inventory_verified"] is True
    assert result["artifact_inventory_failure_code"] is None
    assert "client_start" not in world.effects
    assert result["managed_resources_absence_verified"] is True
    assert world.c.store.review()["closed"] is True
    report = saved_review.review(
        world.c.operation,
        world.c.begin_sha256,
        world.c.plan_sha256,
        world.c.scope,
        coordinator.digest(result),
        root=world.root,
    )
    assert report["recorded_tls_controls_verified"] is False


def test_inventory_os_error_is_classified_without_secret_text_or_false_saved_review(
    world, monkeypatch
):
    import errno

    monkeypatch.setattr(
        coordinator.IdentityArtifacts,
        "inventory",
        lambda self: (_ for _ in ()).throw(PermissionError(errno.EACCES, SECRET, SECRET)),
    )
    world.scene = "network_ambiguous"
    result = world.execute()
    assert result["artifact_inventory_verified"] is False
    assert result["artifact_inventory_failure_code"] == "identity_artifact_permission_denied"
    assert result["tls_controls_verified"] is False
    assert result["managed_resources_absence_verified"] is True
    assert SECRET not in json.dumps(result)
    with pytest.raises(saved_review.ActivationError, match="saved_artifacts_unconfirmed"):
        saved_review.review(
            world.c.operation,
            world.c.begin_sha256,
            world.c.plan_sha256,
            world.c.scope,
            coordinator.digest(result),
            root=world.root,
        )


def test_interruption_cleans_then_saves_receipt_and_propagates_without_retry(world):
    world.scene = "interrupt"
    with pytest.raises(KeyboardInterrupt):
        world.execute()
    assert world.proof("receipt")["status"] == "identity_assay_failed_and_closed"
    assert world.proof("receipt")["error"] == "identity_assay_interrupted"
    assert world.c.store.review()["closed"] is True
    assert all(not owner.named for owner in world.owners.values())


def test_partial_gate_write_blocks_start_but_does_not_block_cleanup_or_failed_receipt(
    world, monkeypatch
):
    write = coordinator.IdentityArtifacts.write

    def partial(records, name, body):
        if name == "server-start-gate":
            path = records.folder / (name + ".json")
            path.write_bytes(b'{"partial":')
            path.chmod(0o600)
            raise OSError(SECRET)
        return write(records, name, body)

    monkeypatch.setattr(coordinator.IdentityArtifacts, "write", partial)
    result = world.execute()
    assert result["status"] == "identity_assay_failed_and_closed"
    assert result["artifact_inventory_verified"] is False and result["artifacts"] is None
    assert "server_start" not in world.effects
    assert all(not owner.named for owner in world.owners.values())
    assert (
        world.root / world.c.operation / "server-start-gate.json"
    ).read_bytes() == b'{"partial":'


@pytest.mark.parametrize("adapters", [{}, {"cleanup": "saved-positive-JSON"}])
def test_plain_adapter_inputs_are_refused_before_any_effect_or_artifact(world, adapters):
    with pytest.raises(coordinator.ActivationError, match="trusted_adapters_required"):
        coordinator.execute(world.c, {}, adapters=adapters, root=world.root)
    assert world.effects == [] and not world.root.exists()


def test_receipt_disk_failure_is_static_after_owned_cleanup_and_never_retries(world, monkeypatch):
    world.scene = "network_ambiguous"  # Short complete failure path.
    write = coordinator.IdentityArtifacts.write

    def rejected(records, name, body):
        if name == "receipt":
            raise OSError(SECRET)
        return write(records, name, body)

    monkeypatch.setattr(coordinator.IdentityArtifacts, "write", rejected)
    with pytest.raises(
        coordinator.ActivationError, match="receipt_publication_unconfirmed"
    ) as caught:
        world.execute()
    assert SECRET not in str(caught.value)
    assert world.c.store.review()["closed"] is True
    assert world.effects == ["network_create", "network-isolated_remove"]
