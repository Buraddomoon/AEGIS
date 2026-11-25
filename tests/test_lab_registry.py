import copy
import json
import os
from uuid import uuid4

import pytest
from aegis import lab_registry
from aegis.config import settings


@pytest.fixture
def registry(tmp_path, monkeypatch):
    files = {}
    for name in ("server_ca", "client_cert", "client_key"):
        path = tmp_path / name
        path.write_text("Fixture bytes only; never used for transport")
        path.chmod(0o600)
        files[name] = str(path)
    entries = [
        {
            "id": f"reviewed-{n}",
            "revision": 1,
            "owner": f"Owner {n}",
            "isolation": "Offline fixture; no network or original laboratory.",
            "connection": {
                "url": f"https://192.168.253.{n + 2}:8443",
                "runner_id": str(uuid4()),
                "laboratory_id": str(uuid4()),
                "asset_id": str(uuid4()),
                **files,
            },
        }
        for n in range(2)
    ]
    document = {"format": "aegis-linux-registry/1", "entries": entries}
    path = tmp_path / "registry.json"
    path.write_text(json.dumps(document))
    path.chmod(0o600)
    monkeypatch.setattr(settings(), "linux_runner_registry", path)
    return path, document


def test_selection_is_exact_and_public_projection_has_no_paths_or_endpoints(registry):
    _, document = registry
    for raw in document["entries"]:
        entry = lab_registry.entry_for(entry_id=raw["id"])
        assert str(entry.connection.laboratory_id) == raw["connection"]["laboratory_id"]
        assert entry == lab_registry.entry_for(laboratory_id=str(entry.connection.laboratory_id))
        public = lab_registry.public(entry)
        assert public["platform"] == "Linux" and public["revision"] == 1
        assert not any(key in json.dumps(public) for key in ("https://", "client_key", "/tmp/"))
    with pytest.raises(ValueError):
        lab_registry.entry_for()
    with pytest.raises(ValueError):
        lab_registry.entry_for(entry_id="unreviewed")


@pytest.mark.parametrize("field", ["url", "runner_id", "laboratory_id", "asset_id", "id"])
def test_duplicate_identity_rejected(registry, field):
    path, document = registry
    first, second = document["entries"]
    if field == "id":
        second[field] = first[field]
    else:
        second["connection"][field] = first["connection"][field]
    path.write_text(json.dumps(document))
    with pytest.raises(ValueError):
        lab_registry.load()


@pytest.mark.parametrize(
    "url",
    [
        "http://192.168.253.2:8443",
        "https://127.0.0.1:8443",
        "https://example.com:8443",
        "https://8.8.8.8:8443",
        "https://192.168.253.2:443",
        "https://u:p@192.168.253.2:8443",
        "https://192.168.253.2:8443/path",
        "https://192.168.253.2:8443?x=y",
    ],
)
def test_unreviewable_endpoints_rejected(registry, url):
    path, document = registry
    document["entries"][0]["connection"]["url"] = url
    path.write_text(json.dumps(document))
    with pytest.raises(ValueError):
        lab_registry.load()


@pytest.mark.parametrize(
    "problem", ["relative", "traversal", "symlink", "directory", "fifo", "mode", "parent"]
)
def test_paths_and_permissions_fail_closed(registry, tmp_path, problem):
    path, document = registry
    key = tmp_path / "client_key"
    if problem == "relative":
        document["entries"][0]["connection"]["client_key"] = "relative.key"
    elif problem == "traversal":
        document["entries"][0]["connection"]["client_key"] = str(tmp_path) + "/../client_key"
    elif problem == "mode":
        key.chmod(0o644)
    elif problem == "parent":
        tmp_path.chmod(0o777)
    else:
        original = key.read_bytes()
        key.unlink()
        if problem == "symlink":
            target = tmp_path / "target"
            target.write_bytes(original)
            key.symlink_to(target)
        elif problem == "directory":
            key.mkdir()
        else:
            os.mkfifo(key)
    path.write_text(json.dumps(document))
    try:
        with pytest.raises((ValueError, OSError)):
            lab_registry.load()
    finally:
        tmp_path.chmod(0o700)


def test_protected_document_rejects_ambiguous_json_and_unknown_fields(registry):
    path, document = registry
    path.chmod(0o644)
    with pytest.raises(ValueError):
        lab_registry.load()
    path.chmod(0o600)
    path.write_text('{"format":"aegis-linux-registry/1","entries":[],"entries":[]}')
    with pytest.raises(ValueError):
        lab_registry.load()
    document["entries"][0]["command"] = "unreviewed"
    path.write_text(json.dumps(document))
    with pytest.raises(ValueError):
        lab_registry.load()


def test_review_metadata_and_public_cert_drift_are_observable(registry):
    path, document = registry
    before = lab_registry.public(lab_registry.entry_for(entry_id="reviewed-0"))
    changed = copy.deepcopy(document)
    changed["entries"][0]["owner"] = "New reviewed owner"
    path.write_text(json.dumps(changed))
    assert (
        lab_registry.public(lab_registry.entry_for(entry_id="reviewed-0"))["review_hash"]
        != before["review_hash"]
    )


def test_certificate_change_invalidates_the_confirmed_review_hash(registry):
    path, document = registry
    before = lab_registry.public(lab_registry.entry_for(entry_id="reviewed-0"))["review_hash"]
    from pathlib import Path

    Path(document["entries"][0]["connection"]["server_ca"]).write_text(
        "changed public certificate fixture"
    )
    assert (
        lab_registry.public(lab_registry.entry_for(entry_id="reviewed-0"))["review_hash"] != before
    )


def test_oversized_document_is_rejected_before_parsing(registry):
    path, _ = registry
    path.write_bytes(b" " * 262145)
    with pytest.raises(ValueError):
        lab_registry.load()
