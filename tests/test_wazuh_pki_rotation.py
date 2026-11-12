import copy
import json
import os
import shutil
import socket
import ssl
import subprocess
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import wazuh_pki_rotation as rotation  # noqa: E402
from prepare_wazuh_lab import prepare as fresh_lab  # noqa: E402


@pytest.fixture(scope="module")
def prepared(tmp_path_factory):
    root = tmp_path_factory.mktemp("wazuh-rotation")
    source = fresh_lab(root / "source")
    (source / "internal_users.yml").write_text("_meta: {type: internalusers, config_version: 2}\n")
    (source / "internal_users.yml").chmod(0o444)
    candidate = rotation.pki.prepare(
        source, rotation.pki.inspect(source)["inventory_sha256"], root / "candidates"
    )
    plan = rotation.prepare(
        source, Path(candidate["candidate_path"]), candidate["manifest_sha256"], root / "plans"
    )
    return (
        source,
        Path(candidate["candidate_path"]),
        candidate["manifest_sha256"],
        Path(plan["plan_path"]),
        plan["plan_sha256"],
    )


def test_plan_is_private_offline_coherent_and_does_not_copy_credentials(prepared):
    source, candidate, _, plan, sha = prepared
    result = rotation.recheck(plan, sha)
    assert result["status"] == "offline_procedure_verified_authorization_required"
    assert result["activation_performed"] is result["normal_operation_permitted"] is False
    document = json.loads((plan / "compose.pki.json").read_bytes())
    assert set(document) == {"secrets"}
    assert set(document["secrets"]) == set(rotation.SECRET_FILES)
    assert all(
        Path(value["file"]).parent == candidate / "pki" for value in document["secrets"].values()
    )
    assert "ca-key.pem" not in json.dumps(document)
    assert set(os.listdir(plan)) == {"plan.json", "compose.pki.json"}
    for file in plan.iterdir():
        assert file.stat().st_mode & 0o777 == 0o600
    assert not any(
        secret in (plan / "plan.json").read_text()
        for secret in json.loads((source / "indexer-passwords.json").read_text()).values()
    )


@pytest.mark.parametrize("kind", ["overlay", "source", "candidate", "plan-hash", "extra"])
def test_recheck_rejects_changed_artifacts(prepared, tmp_path, kind):
    source, candidate, candidate_sha, original, sha = prepared
    plan = tmp_path / original.name
    shutil.copytree(original, plan)
    if kind == "overlay":
        (plan / "compose.pki.json").write_text(json.dumps(rotation.overlay(source)))
    elif kind in {"source", "candidate"}:
        changed = tmp_path / "changed-source"
        shutil.copytree(source, changed)
        if kind == "source":
            (changed / "lab.env").write_text((changed / "lab.env").read_text() + "EXTRA=fixture\n")
        record = json.loads((plan / "plan.json").read_text())
        record["source"] = str(changed)
        if kind == "candidate":
            changed_candidate = tmp_path / candidate.name
            shutil.copytree(candidate, changed_candidate)
            (changed_candidate / "pki/indexer-key.pem").chmod(0o600)
            record["candidate"] = str(changed_candidate)
        (plan / "plan.json").write_text(json.dumps(record))
        sha = rotation.digest(record)
    elif kind == "extra":
        (plan / "unexpected.json").write_text("{}")
    else:
        sha = "0" * 64
    with pytest.raises(ValueError):
        rotation.recheck(plan, sha)


def render(source: Path, overlay: Path | None = None) -> dict:
    if not shutil.which("docker"):
        pytest.skip("Docker Compose CLI required; no daemon startup.")
    command = ["docker", "compose", "--env-file", str(source / "lab.env"), "-p", "aegis-wazuh-lab"]
    for file in rotation.BASE_COMPOSE:
        command.extend(["-f", str(rotation.pki.ROOT / file)])
    if overlay:
        command.extend(["-f", str(overlay)])
    result = subprocess.run(
        [*command, "config", "--format", "json"],
        cwd=rotation.pki.ROOT,
        env={"PATH": "/usr/bin:/bin", "HOME": str(source)},
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert result.returncode == 0  # Never echo captured credential-bearing config.
    return json.loads(result.stdout)


@pytest.fixture(scope="module")
def rendered(prepared):
    source, _, _, plan, _ = prepared
    return render(source), render(source, plan / "compose.pki.json")


def test_real_compose_render_only_changes_five_individual_secret_mounts(prepared, rendered):
    source, candidate, _, _, _ = prepared
    original, changed = rendered
    rotation.validate_rendered(original, changed, candidate)
    for name, service in changed["services"].items():
        if name != "api":
            assert not service.get("ports")
        for secret in service.get("secrets", []):
            assert Path(changed["secrets"][secret["source"]]["file"]).name != "ca-key.pem"
    assert changed["volumes"] == original["volumes"]
    assert changed["services"] == original["services"]
    for name in ("api", "worker"):
        assert not {secret["source"] for secret in changed["services"][name]["secrets"]} & {
            "indexer_key",
            "filebeat_key",
        }
    assert render(source) == original  # Rollback selects original Compose paths.


@pytest.mark.parametrize("kind", ["port", "volume", "mixed-ca", "extra-service", "environment"])
def test_compose_validation_rejects_changes_beyond_certificates(prepared, rendered, kind):
    source, candidate, _, _, _ = prepared
    original, captured = rendered
    changed = copy.deepcopy(captured)
    if kind == "port":
        changed["services"]["wazuh.indexer"]["ports"] = [{"published": "9200"}]
    elif kind == "volume":
        changed["volumes"]["indexer-data"] = {"name": "replacement"}
    elif kind == "mixed-ca":
        changed["secrets"]["wazuh_ca"]["file"] = str(source / "pki/root-ca.pem")
    elif kind == "extra-service":
        changed["services"]["unreviewed"] = {}
    else:
        changed["services"]["wazuh.manager"]["environment"]["FILEBEAT_SSL_VERIFICATION_MODE"] = (
            "none"
        )
    with pytest.raises(ValueError):
        rotation.validate_rendered(original, changed, candidate)


@pytest.fixture
def journal(tmp_path):
    directory = tmp_path / "events"
    directory.mkdir(mode=0o700)
    return rotation.ProcedureJournal(directory, "a" * 64)


def complete(journal, steps):
    for step in steps:
        journal.append("INTENT", step)
        journal.append("CONFIRMED", step, "b" * 64)  # Fixture only, no runtime proof.


def test_lifecycle_requires_durable_intent_then_proof_and_exact_order(journal):
    complete(journal, rotation.STEPS)
    reloaded = rotation.ProcedureJournal(journal.directory, journal.plan_sha256)
    assert len(reloaded.events()) == len(rotation.STEPS) * 2
    with pytest.raises(ValueError):
        reloaded.append("INTENT", rotation.STEPS[0])


def test_ambiguous_effect_survives_reload_and_cannot_be_retried(journal):
    journal.append("INTENT", rotation.STEPS[0])
    reloaded = rotation.ProcedureJournal(journal.directory, journal.plan_sha256)
    with pytest.raises(ValueError, match="pending_effect"):
        reloaded.append("INTENT", rotation.STEPS[0])
    with pytest.raises(ValueError):
        reloaded.append("INTENT", rotation.STEPS[1])
    with pytest.raises(ValueError, match="proof"):
        reloaded.append("ROLLBACK", "rollback")
    reloaded.append("ROLLBACK", "rollback", "c" * 64)
    complete(reloaded, rotation.ROLLBACK_STEPS)
    with pytest.raises(ValueError):
        reloaded.append("INTENT", rotation.STEPS[3])


@pytest.mark.parametrize(
    "kind",
    [
        "confirmation-before-intent",
        "skip-step",
        "no-proof",
        "wrong-plan",
        "partial",
        "chain",
        "extra",
    ],
)
def test_invalid_transitions_or_journal_drift_block_acceptance(journal, kind):
    if kind == "confirmation-before-intent":
        with pytest.raises(ValueError):
            journal.append("CONFIRMED", rotation.STEPS[0], "b" * 64)
        return
    if kind == "skip-step":
        with pytest.raises(ValueError):
            journal.append("INTENT", rotation.STEPS[1])
        return
    journal.append("INTENT", rotation.STEPS[0])
    if kind == "no-proof":
        with pytest.raises(ValueError):
            journal.append("CONFIRMED", rotation.STEPS[0])
        return
    if kind == "partial":
        (journal.directory / "0001.json").write_text("{")
    elif kind == "chain":
        event = json.loads((journal.directory / "0000.json").read_text())
        event["previous"] = "0" * 64
        (journal.directory / "0000.json").write_text(json.dumps(event))
    elif kind == "extra":
        (journal.directory / "0002.json").write_text("{}")
    else:
        journal = rotation.ProcedureJournal(journal.directory, "d" * 64)
    with pytest.raises(ValueError):
        journal.events()


def test_fsync_failure_before_operation_retains_pending_intent(journal, monkeypatch):
    def fail(path):
        raise OSError("fixture-fsync")

    monkeypatch.setattr(rotation.pki.fs, "sync", fail)
    with pytest.raises(OSError):
        journal.append("INTENT", rotation.STEPS[0])
    assert journal.events()[-1]["kind"] == "INTENT"
    with pytest.raises(ValueError):
        journal.append("INTENT", rotation.STEPS[0])


def test_cli_has_no_lifecycle_or_marker_action():
    for action in ("apply", "up", "run", "rollback", "marker"):
        result = subprocess.run(
            [sys.executable, "scripts/wazuh_pki_rotation.py", action],
            cwd=rotation.pki.ROOT,
            capture_output=True,
            timeout=10,
        )
        assert result.returncode == 2


@pytest.mark.parametrize(
    "condition", ["new-pair", "old-client", "old-ca", "wrong-hostname", "no-client"]
)
def test_candidate_tls_loopback_rejects_old_trust_and_client(prepared, condition):
    source, candidate, _, _, _ = prepared
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(3)
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.load_cert_chain(candidate / "pki/indexer.pem", candidate / "pki/indexer-key.pem")
    server.load_verify_locations(candidate / "pki/root-ca.pem")
    server.verify_mode = ssl.CERT_REQUIRED
    accepted = []

    def serve():
        try:
            conn, _ = listener.accept()
            with conn:
                conn.settimeout(3)
                with server.wrap_socket(conn, server_side=True) as secure:
                    accepted.append(True)
                    secure.sendall(b"fixture-only")
        except (OSError, ssl.SSLError):
            pass

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    client = ssl.create_default_context(
        cafile=str((source if condition == "old-ca" else candidate) / "pki/root-ca.pem")
    )
    if condition != "no-client":
        pair = source if condition == "old-client" else candidate
        client.load_cert_chain(pair / "pki/filebeat.pem", pair / "pki/filebeat-key.pem")

    def exchange():
        with socket.create_connection(listener.getsockname(), timeout=3) as conn:
            with client.wrap_socket(
                conn,
                server_hostname="unreviewed.example"
                if condition == "wrong-hostname"
                else "wazuh.indexer",
            ) as secure:
                assert secure.recv(64) == b"fixture-only"

    try:
        if condition == "new-pair":
            exchange()
        else:
            with pytest.raises((OSError, ssl.SSLError)):
                exchange()
    finally:
        thread.join(timeout=4)
        listener.close()
        assert not thread.is_alive()
    assert accepted == ([True] if condition == "new-pair" else [])


@pytest.mark.parametrize(
    "kind",
    [
        "legacy-network",
        "endpoint",
        "destination",
        "hostname",
        "tls",
        "gateway",
        "siem-port",
        "host-network",
        "docker-socket",
    ],
)
def test_matching_bad_baseline_cannot_bypass_current_profile_checks(prepared, rendered, kind):
    _, candidate, _, _, _ = prepared
    original, captured = copy.deepcopy(rendered)
    for config in (original, captured):
        if kind == "legacy-network":
            config["networks"]["isolated"]["ipam"]["config"] = [
                {"subnet": "172.30.89.0/29", "gateway": "172.30.89.1"}
            ]
        elif kind == "endpoint":
            config["services"]["wazuh.indexer"]["networks"]["telemetry"]["ipv4_address"] = (
                "172.30.90.2"
            )
        elif kind in {"destination", "hostname"}:
            key = "WAZUH_ALLOWED_IP" if kind == "destination" else "WAZUH_URL"
            config["services"]["api"]["environment"][key] = (
                "172.30.90.2" if kind == "destination" else "https://unreviewed.example:9200"
            )
        elif kind == "tls":
            config["services"]["wazuh.manager"]["environment"]["FILEBEAT_SSL_VERIFICATION_MODE"] = (
                "none"
            )
        elif kind == "gateway":
            config["networks"]["telemetry"]["ipam"]["config"][0]["gateway"] = "192.168.253.1"
        elif kind == "siem-port":
            config["services"]["wazuh.indexer"]["ports"] = [{"published": "9200"}]
        elif kind == "host-network":
            config["services"]["wazuh.manager"]["network_mode"] = "host"
        else:
            config["services"]["wazuh.agent"]["volumes"].append(
                {"type": "bind", "source": "/var/run/docker.sock", "target": "/var/run/docker.sock"}
            )
    with pytest.raises(ValueError):
        rotation.validate_rendered(original, captured, candidate)
