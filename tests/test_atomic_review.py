"""Inspect official bytes only; never execute an imported Atomic."""

import hashlib
import json
from pathlib import Path

from aegis.integrations.yaml_import import AtomicMetadataProvider, safe_document

GUID = "34ca1464-de9d-40c6-8c77-690adf36a135"
COMMIT = "a0e3f9bc69fed2fd711bd1f1aa87a40c33482fe6"
SHA = "f453e844306df372cf600ddd59d15626a83d3dd83cd5a4b3e5fe5175b4204f3b"
FIXTURE = Path("fixtures/atomic/T1222.002.json")


def test_pinned_source_license_and_selected_behavior():
    envelope = json.loads(FIXTURE.read_text())
    raw = envelope["content"].encode()
    assert envelope["source_commit"] == COMMIT
    assert envelope["source_sha256"] == hashlib.sha256(raw).hexdigest() == SHA
    assert len(raw) == 9653
    license_bytes = Path("fixtures/atomic/LICENSE.txt").read_bytes()
    assert hashlib.sha256(license_bytes).hexdigest() == (
        "65af6027045d23175366eab50e460ab3ee7790e591cb84cc32c78ac63a4c90e1"
    )
    document = safe_document(raw.decode())
    selected = [t for t in document["atomic_tests"] if t["auto_generated_guid"] == GUID]
    assert len(selected) == 1
    test = selected[0]
    assert document["attack_technique"] == "T1222.002"
    assert set(test["supported_platforms"]) == {"linux", "macos"}
    assert test["executor"] == {
        "name": "sh",
        "command": "chmod #{numeric_mode} #{file_or_folder}\n",
    }
    assert set(test["input_arguments"]) == {"numeric_mode", "file_or_folder"}
    assert "dependencies" not in test


def test_reviewed_guid_is_still_metadata_only_when_imported():
    raw = json.loads(FIXTURE.read_text())["content"]
    entries = AtomicMetadataProvider().import_metadata(raw)
    selected = next(t for t in entries if t["guid"] == GUID)
    assert not selected["has_cleanup"]
    for entry in entries:
        assert entry["approved"] is False
        assert entry["executable"] is False
        assert "command" not in entry
