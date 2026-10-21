import hashlib
import os
from uuid import uuid4

import pytest
from aegis.lab_runner.files import Workspace
from aegis.marker_observer import observe_once


@pytest.fixture
def marker(tmp_path):
    work = tmp_path / "work"
    work.mkdir(mode=0o700)
    job, lab, asset = uuid4(), uuid4(), uuid4()
    workspace = Workspace(work)
    try:
        directory = workspace.create(job)
    finally:
        workspace.close()
    content = ("aegis-" + str(uuid4()) + "\n").encode()
    path = directory / "proof.marker"
    path.write_bytes(content)
    return work, job, lab, asset, path, content


def test_observer_reads_actual_marker_without_receipt_or_execution(marker):
    work, job, lab, asset, path, content = marker
    seen = set()
    records = observe_once(work, lab, asset, seen)
    assert len(records) == 1
    event = records[0]["aegis"]
    assert event["execution_id"] == str(job) and event["laboratory_id"] == str(lab)
    assert event["marker"] == content.decode().strip()
    assert event["artifact_sha256"] == hashlib.sha256(content).hexdigest()
    assert event["observation"] == "marker_file_read" and "rule_id" not in event
    assert path.read_bytes() == content
    assert observe_once(work, lab, asset, seen) == []


@pytest.mark.parametrize(
    "threat",
    [
        "file_link",
        "directory_link",
        "hardlink",
        "fifo",
        "invalid",
        "oversize",
        "missing",
        "wrong_name",
    ],
)
def test_observer_rejects_links_non_regular_and_unexpected_files(marker, threat, tmp_path):
    work, job, lab, asset, path, content = marker
    if threat in ("file_link", "hardlink"):
        outside = tmp_path / "outside"
        outside.write_bytes(content)
        path.unlink()
        if threat == "file_link":
            path.symlink_to(outside)
        else:
            os.link(outside, path)
    elif threat == "directory_link":
        original = path.parent
        moved = tmp_path / "moved"
        original.rename(moved)
        original.symlink_to(moved, target_is_directory=True)
    elif threat == "fifo":
        path.unlink()
        os.mkfifo(path)
    elif threat == "invalid":
        path.write_bytes(b"x" * 43)
    elif threat == "oversize":
        path.write_bytes(content + b"x")
    elif threat == "missing":
        path.unlink()
    else:
        path.rename(path.with_name("unexpected.marker"))
    assert observe_once(work, lab, asset, set()) == []


def test_observer_refuses_symlink_root(marker, tmp_path):
    work, _, lab, asset, _, _ = marker
    link = tmp_path / "root-link"
    link.symlink_to(work, target_is_directory=True)
    with pytest.raises(OSError):
        observe_once(link, lab, asset, set())
