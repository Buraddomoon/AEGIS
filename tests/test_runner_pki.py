import json
import os
import runpy
import shutil
import stat
import subprocess
import sys
from datetime import timedelta
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import runner_pki as pki  # noqa: E402


@pytest.fixture(scope="module")
def source(tmp_path_factory):
    return pki.initialize(tmp_path_factory.mktemp("pki-source") / "source")


@pytest.fixture(scope="module")
def staged(source, tmp_path_factory):
    inventory = pki.inspect(source)
    result = pki.prepare(
        source, inventory["inventory_sha256"], tmp_path_factory.mktemp("pki-stage") / "candidates"
    )
    return Path(result["candidate_path"]), result["manifest_sha256"]


def clone(staged, tmp_path):
    target = tmp_path / staged[0].name
    shutil.copytree(staged[0], target)
    # The candidate env deliberately binds its absolute staging directory.
    env = target / "ids.env"
    env.write_text(env.read_text().replace(str(staged[0]), str(target)))
    return target


def overwrite(path, content):
    mode = stat.S_IMODE(path.stat().st_mode)
    path.chmod(0o600)
    path.write_bytes(content)
    path.chmod(mode)


def test_public_inspection_and_candidate_keep_identity_and_source_untouched(source, staged):
    before = {path.name: (path.read_bytes(), path.stat().st_mtime_ns) for path in source.iterdir()}
    inventory = pki.inspect(source)
    result = pki.verify(source, *staged)
    assert result["status"] == "offline_candidate_verified_not_activated"
    assert all(
        result[field] is False
        for field in [
            "activation_performed",
            "lab_started",
            "database_modified",
            "journal_opened",
            "normal_operation_permitted",
        ]
    )
    assert not inventory["source_private_keys_read"]
    assert result["descriptor_sha256"] != inventory["public"]["descriptor_sha256"]
    assert pki.inspect(staged[0])["public"]["connection"] == inventory["public"]["connection"]
    assert {
        path.name: (path.read_bytes(), path.stat().st_mtime_ns) for path in source.iterdir()
    } == before


def test_prepare_does_not_need_or_read_source_keys_or_journal(tmp_path, monkeypatch):
    source = pki.initialize(tmp_path / "source")
    for name in pki.ROLES:
        (source / (name + ".key")).unlink()
    journal = source / "never-open-journal.sqlite"
    journal.write_bytes(b"preserve-original-fences")
    before = journal.read_bytes(), journal.stat().st_mtime_ns
    read = pki.read

    def only_public(path, **kwargs):
        if path.parent == source:
            assert path.name in pki.PUBLIC
        return read(path, **kwargs)

    monkeypatch.setattr(pki, "read", only_public)
    inspected = pki.inspect(source)
    result = pki.prepare(source, inspected["inventory_sha256"], tmp_path / "candidates")
    assert (
        pki.verify(source, Path(result["candidate_path"]), result["manifest_sha256"])["status"]
        == "offline_candidate_verified_not_activated"
    )
    assert (journal.read_bytes(), journal.stat().st_mtime_ns) == before


def test_unreviewed_source_hash_cannot_create_candidate(source, tmp_path, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("Generation must not run")

    monkeypatch.setattr(pki, "initialize", forbidden)
    with pytest.raises(pki.PKIError, match="source_inventory_drift"):
        pki.prepare(source, "0" * 64, tmp_path / "candidates")
    assert not (tmp_path / "candidates").exists()


def test_hash_mismatch_is_rejected_before_reading_source_or_keys(staged, monkeypatch, tmp_path):
    def forbidden(*args, **kwargs):
        raise AssertionError("Source must not be read")

    monkeypatch.setattr(pki, "inventory", forbidden)
    with pytest.raises(pki.PKIError, match="manifest_integrity_mismatch"):
        pki.verify(tmp_path / "absent", staged[0], "0" * 64)


@pytest.mark.parametrize(
    "problem", ["symlink", "hardlink", "fifo", "world_readable_key", "extra", "directory"]
)
def test_unsafe_candidate_artifacts_are_refused(source, staged, tmp_path, problem):
    target = clone(staged, tmp_path)
    path = target / "runner-server.key"
    if problem == "world_readable_key":
        path.chmod(0o644)
    elif problem == "extra":
        (target / "unexpected.env").write_text("forbidden")
    else:
        path.unlink()
        if problem == "symlink":
            path.symlink_to(staged[0] / "runner-server.key")
        elif problem == "hardlink":
            other = tmp_path / "other-key"
            other.write_bytes((staged[0] / "runner-server.key").read_bytes())
            other.chmod(0o444)
            os.link(other, path)
        elif problem == "fifo":
            os.mkfifo(path, 0o444)
        else:
            path.mkdir(mode=0o700)
    with pytest.raises(pki.PKIError):
        pki.verify(source, target, staged[1])


@pytest.mark.parametrize(
    "problem", ["key_pair", "certificate", "environment", "manifest", "source"]
)
def test_replaced_material_or_environment_never_verifies(source, staged, tmp_path, problem):
    target = clone(staged, tmp_path)
    local_source = source
    if problem == "key_pair":
        overwrite(target / "runner-server.key", (target / "runner-client.key").read_bytes())
    elif problem == "certificate":
        overwrite(target / "runner-server.crt", (target / "runner-client.crt").read_bytes())
    elif problem == "environment":
        (target / "ids.env").write_text("AEGIS_LAB_CONFIG_DIR=/unexpected\n")
    elif problem == "manifest":
        manifest = json.loads((target / "rotation.json").read_text())
        manifest["activation_performed"] = True
        (target / "rotation.json").write_text(json.dumps(manifest))
    else:
        local_source = tmp_path / "changed-source"
        shutil.copytree(source, local_source)
        overwrite(
            local_source / "connection.json",
            (local_source / "connection.json").read_bytes() + b"\n",
        )
    with pytest.raises(pki.PKIError):
        pki.verify(local_source, target, staged[1])


def test_changed_manifest_cannot_claim_a_different_candidate_even_with_new_hash(
    source, staged, tmp_path
):
    target = clone(staged, tmp_path)
    manifest = json.loads((target / "rotation.json").read_text())
    manifest["candidate"]["descriptor_sha256"] = "0" * 64
    (target / "rotation.json").write_text(json.dumps(manifest))
    with pytest.raises(pki.PKIError, match="candidate_inventory_drift"):
        pki.verify(source, target, pki.digest(manifest))


def test_expired_source_is_visible_but_candidate_does_not_ignore_time(source, staged, monkeypatch):
    future = pki.clock() + timedelta(days=3)
    monkeypatch.setattr(pki, "clock", lambda: future)
    inventory = pki.inspect(source)
    assert inventory["valid_now"]["runner-server"] is False
    assert inventory["valid_now"]["runner-client"] is False
    with pytest.raises(pki.PKIError):
        pki.verify(source, *staged)


def test_old_candidate_with_less_than_a_day_remaining_is_rejected(source, staged, monkeypatch):
    future = pki.clock() + timedelta(hours=25)
    monkeypatch.setattr(pki, "clock", lambda: future)
    with pytest.raises(pki.PKIError, match="candidate_lifetime_outside_policy"):
        pki.verify(source, *staged)


@pytest.mark.parametrize(
    "problem",
    [
        "symlink_parent",
        "public_directory",
        "excessive",
        "malformed_json",
        "wrong_paths",
        "wrong_ip",
    ],
)
def test_public_source_policy_refuses_unsafe_input(source, tmp_path, problem):
    target = tmp_path / "source"
    shutil.copytree(source, target)
    if problem == "symlink_parent":
        linked = tmp_path / "linked"
        linked.symlink_to(target, target_is_directory=True)
        target = linked
    elif problem == "public_directory":
        target.chmod(0o755)
    elif problem == "excessive":
        overwrite(target / "connection.json", b"X" * 65537)
    elif problem == "malformed_json":
        overwrite(target / "connection.json", b"private-sentinel")
    else:
        data = json.loads((target / "connection.json").read_text())
        if problem == "wrong_paths":
            data["client_key"] = "/unreviewed/key"
        else:
            data["url"] = "https://10.0.0.1:8443"
        overwrite(target / "connection.json", json.dumps(data).encode())
    with pytest.raises((ValueError, OSError)):
        pki.inspect(target)


def test_failed_generation_leaves_no_success_manifest(source, tmp_path, monkeypatch):
    initial = pki.inspect(source)

    def interrupted(target, **kwargs):
        target.mkdir(mode=0o700)
        (target / "partial").write_text("interrupted")
        raise pki.PKIError("injected")

    monkeypatch.setattr(pki, "initialize", interrupted)
    with pytest.raises(pki.PKIError):
        pki.prepare(source, initial["inventory_sha256"], tmp_path / "output")
    folders = list((tmp_path / "output").iterdir())
    assert len(folders) == 1 and not (folders[0] / "rotation.json").exists()
    assert pki.inspect(source)["inventory_sha256"] == initial["inventory_sha256"]


def test_source_changed_during_generation_is_not_published(source, tmp_path, monkeypatch):
    original = tmp_path / "source"
    shutil.copytree(source, original)
    initial = pki.inspect(original)
    generate = pki.initialize

    def changed(target, **kwargs):
        result = generate(target, **kwargs)
        overwrite(original / "connection.json", (original / "connection.json").read_bytes() + b"\n")
        return result

    monkeypatch.setattr(pki, "initialize", changed)
    with pytest.raises(pki.PKIError, match="source_changed_during_preparation"):
        pki.prepare(original, initial["inventory_sha256"], tmp_path / "output")
    assert not list((tmp_path / "output").glob("*/rotation.json"))


def test_cli_error_redacts_private_content_and_does_not_touch_other_resources(tmp_path):
    source = tmp_path / "source"
    source.mkdir(mode=0o700)
    (source / "connection.json").write_text("private-sensitive-sentinel")
    (source / "connection.json").chmod(0o600)
    result = subprocess.run(
        [sys.executable, "scripts/runner_pki.py", "inspect", "--source", str(source)],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 1
    assert json.loads(result.stdout)["status"] == "rejected"
    assert "private-sensitive-sentinel" not in result.stdout + result.stderr
    assert "Traceback" not in result.stderr


@pytest.mark.parametrize("problem", ["san", "eku"])
def test_wrong_server_identity_extensions_are_rejected(source, staged, tmp_path, problem):
    target = clone(staged, tmp_path)
    config = tmp_path / "extensions.cnf"
    config.write_text(
        "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n"
        "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n"
        + ("extendedKeyUsage=clientAuth\n" if problem == "eku" else "extendedKeyUsage=serverAuth\n")
        + (
            "subjectAltName=IP:172.30.89.2\n"
            if problem == "san"
            else "subjectAltName=IP:172.30.88.2\n"
        )
    )
    generated = tmp_path / "resigned.crt"
    runpy.run_path("scripts/init_linux_lab.py")["openssl"](
        "x509",
        "-req",
        "-in",
        str(target / "runner-server.csr"),
        "-CA",
        str(target / "server-ca.crt"),
        "-CAkey",
        str(target / "server-ca.key"),
        "-CAserial",
        str(target / "server-ca.srl"),
        "-out",
        str(generated),
        "-days",
        "2",
        "-sha256",
        "-extfile",
        str(config),
    )
    overwrite(target / "runner-server.crt", generated.read_bytes())
    with pytest.raises(pki.PKIError, match="certificate_(san|purpose)_mismatch"):
        pki.verify(source, target, staged[1])


def test_wazuh_runner_transport_address_is_supported_without_indexer_access(tmp_path):
    source = pki.initialize(tmp_path / "source", server_ip="172.30.89.2")
    initial = pki.inspect(source)
    result = pki.prepare(source, initial["inventory_sha256"], tmp_path / "out")
    verified = pki.verify(source, Path(result["candidate_path"]), result["manifest_sha256"])
    assert verified["status"] == "offline_candidate_verified_not_activated"
    assert (
        pki.inspect(Path(result["candidate_path"]))["public"]["connection"]["url"]
        == "https://172.30.89.2:8443"
    )


def test_descriptor_contract_matches_backend_and_rotation_invalidates_old_hash(
    source, staged, monkeypatch
):
    from aegis import linux_labs
    from aegis.integrations.linux_runner import RunnerConnection

    hashes = []
    for root in [source, staged[0]]:
        public = pki.inspect(root)["public"]
        configuration = {
            **public["connection"],
            "server_ca": root / "server-ca.crt",
            "client_cert": root / "runner-client.crt",
            "client_key": root / "runner-client.key",
        }
        monkeypatch.setattr(
            linux_labs,
            "connection",
            lambda configuration=configuration: RunnerConnection.model_validate(configuration),
        )
        hashes.append(linux_labs.configured_hash())
        assert hashes[-1] == public["descriptor_sha256"]
    assert hashes[0] != hashes[1]


def test_unsafe_compose_output_path_is_refused_before_creation(source, tmp_path):
    target = tmp_path / "unsafe${INJECT}"
    with pytest.raises(pki.PKIError, match="unsafe_compose_path"):
        pki.prepare(source, pki.inspect(source)["inventory_sha256"], target)
    assert not target.exists()


def test_sync_rejects_fifo_without_blocking(tmp_path):
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo, 0o600)
    with pytest.raises(pki.PKIError, match="unsafe_sync_artifact"):
        pki.sync(fifo)


def test_openssl_has_fixed_environment_timeout_and_redacted_failure(monkeypatch):
    calls = []

    def execute(args, **kwargs):
        calls.append((args, kwargs))
        return subprocess.CompletedProcess(args, 1, b"", b"private-sensitive-sentinel")

    monkeypatch.setattr(subprocess, "run", execute)
    with pytest.raises(pki.PKIError, match="openssl_validation_failed"):
        pki.openssl("x509", "-noout", data=b"input")
    args, kwargs = calls[0]
    assert args[0] == "/usr/bin/openssl"
    assert kwargs["env"] == pki.ENV and kwargs["timeout"] == 5
    assert kwargs["input"] == b"input" and kwargs["capture_output"] is True


@pytest.mark.parametrize("suffix", ["", "/nested"])
def test_candidate_destination_cannot_modify_the_source_directory(source, suffix, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("Generation must not run")

    monkeypatch.setattr(pki, "initialize", forbidden)
    with pytest.raises(pki.PKIError, match="candidate_must_be_separate_from_source"):
        pki.prepare(source, pki.inspect(source)["inventory_sha256"], Path(str(source) + suffix))


@pytest.mark.parametrize("problem", ["unknown_field", "bad_time", "not_utc"])
def test_manifest_schema_and_timestamp_cannot_be_forged(source, staged, tmp_path, problem):
    target = clone(staged, tmp_path)
    manifest = json.loads((target / "rotation.json").read_text())
    if problem == "unknown_field":
        manifest["unknown"] = "unreviewed"
    elif problem == "bad_time":
        manifest["created_at"] = "not-a-timestamp"
    else:
        manifest["created_at"] = "2026-10-26T00:00:00+03:00"
    (target / "rotation.json").write_text(json.dumps(manifest))
    with pytest.raises(ValueError):
        pki.verify(source, target, pki.digest(manifest))


def test_offline_path_never_reads_source_keys_or_starts_network_database_or_docker(
    source, tmp_path
):
    script = r"""
import sys,os,runpy,json
from pathlib import Path
sys.dont_write_bytecode=True
source=Path(sys.argv[1]); output=Path(sys.argv[2])
def audit(event,args):
    if event.startswith('socket.'):
        raise AssertionError('No network in offline PKI')
    if event=='subprocess.Popen':
        assert args[0]=='/usr/bin/openssl' and args[1][1] in {'x509','pkey','verify','req'}
        assert not any(str(source) in str(arg) and str(arg).endswith('.key') for arg in args[1])
    if event=='open' and isinstance(args[0],str) and str(source)+'/' in args[0]:
        assert Path(args[0]).name in {'connection.json','server-ca.crt','client-ca.crt','runner-server.crt','runner-client.crt'}
        assert not args[2] & (os.O_WRONLY|os.O_RDWR|os.O_CREAT|os.O_TRUNC|os.O_APPEND)
sys.addaudithook(audit)
sys.path.insert(0,'scripts')
pki=runpy.run_path('scripts/runner_pki.py')
initial=pki['inspect'](source)
result=pki['prepare'](source,initial['inventory_sha256'],output)
verified=pki['verify'](source,Path(result['candidate_path']),result['manifest_sha256'])
assert verified['status']=='offline_candidate_verified_not_activated'
assert not any(name in sys.modules for name in ['aegis.db','aegis.worker','aegis.lab_runner.server','aegis.lab_runner.engine'])
print(verified['status'])
"""
    result = subprocess.run(
        [sys.executable, "-c", script, str(source), str(tmp_path / "out")],
        capture_output=True,
        text=True,
        timeout=25,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "offline_candidate_verified_not_activated"


def test_new_parent_entries_are_durable_before_key_generation(source, tmp_path, monkeypatch):
    initial = pki.inspect(source)
    flushed = []
    sync = pki.sync

    def observe(path):
        sync(path)
        flushed.append(path)

    monkeypatch.setattr(pki, "sync", observe)
    output = tmp_path / "first" / "second"
    generate = pki.initialize

    def checked(target, **kwargs):
        assert tmp_path in flushed and output.parent in flushed and output in flushed
        assert stat.S_IMODE(output.parent.stat().st_mode) == 0o700
        return generate(target, **kwargs)

    monkeypatch.setattr(pki, "initialize", checked)
    result = pki.prepare(source, initial["inventory_sha256"], output)
    assert (
        pki.verify(source, Path(result["candidate_path"]), result["manifest_sha256"])["status"]
        == "offline_candidate_verified_not_activated"
    )


def test_parent_sync_failure_cannot_generate_keys_or_claim_success(source, tmp_path, monkeypatch):
    initial = pki.inspect(source)
    sync = pki.sync

    def fail(path):
        if path == tmp_path:
            raise OSError("injected parent durability failure")
        sync(path)

    def forbidden(*args, **kwargs):
        raise AssertionError("No key generation before durable root")

    monkeypatch.setattr(pki, "sync", fail)
    monkeypatch.setattr(pki, "initialize", forbidden)
    output = tmp_path / "candidate-root"
    with pytest.raises(OSError):
        pki.prepare(source, initial["inventory_sha256"], output)
    assert output.is_dir() and not list(output.iterdir())
    assert pki.inspect(source)["inventory_sha256"] == initial["inventory_sha256"]
