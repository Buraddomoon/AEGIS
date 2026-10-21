import os
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from aegis.lab_runner.files import Workspace
from aegis.lab_runner.protocol import JobSpec
from pydantic import ValidationError


def spec(**changes):
    data = dict(
        job_id=uuid4(),
        laboratory_id=uuid4(),
        asset_id=uuid4(),
        runner_id=uuid4(),
        marker="aegis-" + str(uuid4()),
        scope_hash="a" * 64,
        deadline_at=datetime.now(UTC),
    )
    data.update(changes)
    return JobSpec(**data)


@pytest.mark.parametrize(
    "changes",
    [
        {"command": "anything"},
        {"path": "/etc/passwd"},
        {"test_id": "unreviewed"},
        {"marker": "../../outside"},
        {"marker": "aegis-" + "-" * 36},
        {"deadline_at": "2026-01-01T00:00:00"},
        {"scope_hash": "invalid"},
    ],
)
def test_protocol_refuses_commands_paths_unknown_tests_and_invalid_identity(changes):
    with pytest.raises(ValidationError):
        spec(**changes)


def test_workspace_cleanup_is_scoped_and_idempotent(tmp_path):
    root = tmp_path / "work"
    root.mkdir(mode=0o700)
    workspace = Workspace(root)
    identifier = uuid4()
    try:
        directory = workspace.create(identifier)
        (directory / "proof.marker").write_bytes(b"proof")
        assert workspace.read(identifier, "proof.marker", 256) == b"proof"
        workspace.cleanup(identifier)
        workspace.cleanup(identifier)
        assert not directory.exists()
    finally:
        workspace.close()


def test_workspace_refuses_symlinks_unknown_files_and_shared_directories(tmp_path):
    root = tmp_path / "work"
    root.mkdir(mode=0o700)
    workspace = Workspace(root)
    identifier = uuid4()
    outside = tmp_path / "outside"
    outside.write_text("preserve")
    try:
        directory = workspace.create(identifier)
        (directory / "proof.marker").symlink_to(outside)
        with pytest.raises(OSError):
            workspace.read(identifier, "proof.marker", 256)
        with pytest.raises(ValueError):
            workspace.cleanup(identifier)
        assert outside.read_text() == "preserve"
        (directory / "proof.marker").unlink()
        (directory / "unknown").write_text("preserve")
        with pytest.raises(ValueError):
            workspace.cleanup(identifier)
        assert (directory / "unknown").exists()
    finally:
        workspace.close()
    os.chmod(root, 0o777)
    with pytest.raises(ValueError):
        Workspace(root)
