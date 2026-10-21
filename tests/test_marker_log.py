import hashlib
import json
import os
from uuid import uuid4

import pytest
from aegis.marker_log import MAX_BYTES, ObservationLog


@pytest.fixture
def log_scope(tmp_path):
    directory = tmp_path / "log"
    directory.mkdir(mode=0o700)
    lab, asset, execution = uuid4(), uuid4(), uuid4()
    marker = "aegis-" + str(uuid4())
    record = {
        "aegis": {
            "schema": "aegis-json/1",
            "observation": "marker_file_read",
            "behavior": "temporary-marker",
            "laboratory_id": str(lab),
            "asset_id": str(asset),
            "execution_id": str(execution),
            "marker": marker,
            "artifact_bytes": 43,
            "artifact_sha256": hashlib.sha256((marker + "\n").encode()).hexdigest(),
        }
    }
    return directory, lab, asset, execution, record


def test_durable_record_survives_restart_without_duplicate(log_scope):
    directory, lab, asset, execution, record = log_scope
    with ObservationLog(directory, lab, asset) as log:
        assert log.append(record)
        assert not log.append(record)
    with ObservationLog(directory, lab, asset) as log:
        assert str(execution) in log.seen
        assert not log.append(record)
    assert json.loads((directory / "observations.jsonl").read_text()) == record


@pytest.mark.parametrize("threat", ["symlink", "hardlink", "fifo", "public", "partial", "overflow"])
def test_log_refuses_unsafe_or_ambiguous_existing_file(log_scope, tmp_path, threat):
    directory, lab, asset, _, _ = log_scope
    path = directory / "observations.jsonl"
    if threat in {"symlink", "hardlink"}:
        outside = tmp_path / "outside"
        outside.touch(mode=0o600)
        path.symlink_to(outside) if threat == "symlink" else os.link(outside, path)
    elif threat == "fifo":
        os.mkfifo(path, mode=0o600)
    else:
        path.touch(mode=0o600)
        if threat == "public":
            path.chmod(0o644)
        elif threat == "partial":
            path.write_bytes(b'{"aegis":')
        else:
            with path.open("wb") as file:
                file.truncate(MAX_BYTES + 1)
    with pytest.raises((OSError, ValueError)):
        ObservationLog(directory, lab, asset)


def test_log_rejects_other_scope_on_restart_and_preserves_content(log_scope):
    directory, lab, asset, _, record = log_scope
    with ObservationLog(directory, lab, asset) as log:
        log.append(record)
    before = (directory / "observations.jsonl").read_bytes()
    with pytest.raises(ValueError):
        ObservationLog(directory, uuid4(), asset)
    assert (directory / "observations.jsonl").read_bytes() == before


def test_log_stops_at_capacity_without_rotation_or_truncation(log_scope, monkeypatch):
    directory, lab, asset, _, record = log_scope
    with ObservationLog(directory, lab, asset) as log:
        monkeypatch.setattr("aegis.marker_log.MAX_BYTES", 1)
        with pytest.raises(ValueError):
            log.append(record)
        assert not log.seen
    assert (directory / "observations.jsonl").read_bytes() == b""


def test_log_does_not_accept_receipt_as_observation(log_scope):
    directory, lab, asset, _, _ = log_scope
    with ObservationLog(directory, lab, asset) as log:
        with pytest.raises(ValueError):
            log.append({"execution_receipt": {"status": "COMPLETED"}})


def test_second_writer_cannot_share_log(log_scope):
    directory, lab, asset, _, _ = log_scope
    with ObservationLog(directory, lab, asset), pytest.raises(BlockingIOError):
        ObservationLog(directory, lab, asset)
