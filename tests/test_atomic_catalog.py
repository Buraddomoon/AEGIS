import copy
import hashlib
import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
import yaml
from aegis.atomic_catalog import AtomicError, import_document
from aegis.db import session_factory
from aegis.integrations.yaml_import import AtomicMetadataProvider
from aegis.models import AtomicDocument, AtomicEntry, User
from aegis.models import TestDefinition as Definition
from sqlalchemy import func, select, text
from sqlalchemy.exc import DBAPIError

COMMIT = "3c62c9701d1009b991ad0224606c762fa02ba513"
SHA = "2a26f69f3fdcf6f3f2135d4405a184cfd365ed662c42f71fd4a1aa978b018021"
RAW = json.loads(Path("fixtures/atomic/T1059.004.json").read_text())["content"]


def test_official_projection_and_no_execution_fields():
    assert hashlib.sha256(RAW.encode()).hexdigest() == SHA
    result = AtomicMetadataProvider().import_metadata(RAW)
    assert len(result) == 17
    source = yaml.safe_load(RAW)
    assert [x["guid"] for x in result] == [x["auto_generated_guid"] for x in source["atomic_tests"]]
    for item in result:
        assert item["technique_id"] == "T1059.004"
        assert item["approved"] is False and item["executable"] is False
        assert "command" not in item
        assert all(
            set(d) == {"description", "has_prereq", "has_setup"} for d in item["dependencies"]
        )
        assert all(
            set(v) == {"type", "description", "has_default"}
            for v in item["input_arguments"].values()
        )


@pytest.mark.parametrize(
    "raw",
    [
        "x: &a [1]\ny: *a",
        "!!python/object/apply:os.system [id]",
        "x: " + "x" * 65536,
        "a: 1\na: 2",
        "a: 1\n---\na: 2",
        "attack_technique: []\natomic_tests: []",
        "attack_technique: T1059.004\natomic_tests: [null]",
        "attack_technique: T1059.004\natomic_tests: []",
        RAW.replace("attack_technique: T1059.004", "attack_technique: 123"),
        RAW.replace("supported_platforms:", "supported_platforms: null\n  ignored:", 1),
        RAW.replace("elevation_required: false", "elevation_required: 'false'", 1),
        RAW.replace("type: path", "type: [path]", 1),
        "x: " + "[" * 34 + "1" + "]" * 34,
    ],
)
def test_hostile_or_invalid_atomic(raw):
    with pytest.raises((ValueError, yaml.YAMLError)):
        AtomicMetadataProvider().import_metadata(raw)


def test_duplicate_guid_and_metadata_commands_removed():
    data = yaml.safe_load(RAW)
    data["atomic_tests"].append(copy.deepcopy(data["atomic_tests"][0]))
    with pytest.raises(ValueError, match="GUID"):
        AtomicMetadataProvider().import_metadata(yaml.safe_dump(data))
    data["atomic_tests"] = data["atomic_tests"][:1]
    item = data["atomic_tests"][0]
    item["executor"]["command"] = "do-not-execute-unique"
    item["executor"]["cleanup_command"] = "do-not-cleanup-unique"
    item["dependencies"] = [
        {
            "description": "Untrusted requirements",
            "prereq_command": "do-not-check-unique",
            "get_prereq_command": "do-not-install-unique",
        }
    ]
    item["input_arguments"] = {"x": {"type": "string", "default": "do-not-default-unique"}}
    projected = AtomicMetadataProvider().import_metadata(yaml.safe_dump(data))
    assert "do-not-" not in str(projected)


def test_versions_constraints_and_immutable_history(db_ready):
    with session_factory()() as db:
        actor = db.scalar(select(User.id).where(User.username == "administrator"))
        allowlist = list(db.scalars(select(Definition.id).order_by(Definition.id)))
        doc, unchanged = import_document(db, RAW, COMMIT, SHA, actor)
        assert not unchanged
        db.commit()
        first_id = doc.id
        assert import_document(db, RAW, COMMIT, SHA, actor)[1]
        changed = RAW + "\n# synthetic fixture change\n"
        with pytest.raises(AtomicError, match="bytes diferentes"):
            import_document(
                db, changed, COMMIT, hashlib.sha256(changed.encode()).hexdigest(), actor
            )
        db.rollback()
        second, _ = import_document(
            db, changed, "a" * 40, hashlib.sha256(changed.encode()).hexdigest(), actor
        )
        db.commit()
        assert second.id != first_id
        assert db.scalar(select(func.count()).select_from(AtomicEntry)) == 34
        assert list(db.scalars(select(Definition.id).order_by(Definition.id))) == allowlist
        for table in ("atomic_documents", "atomic_entries"):
            for operation in (f"DELETE FROM {table}", f"UPDATE {table} SET created_at=now()"):
                with pytest.raises(DBAPIError, match="history is immutable"):
                    db.execute(text(operation))
                db.rollback()
        with pytest.raises(DBAPIError):
            db.add(
                AtomicDocument(
                    source_commit="invalid",
                    source_sha256=SHA,
                    technique_id="T1059.004",
                    imported_by=actor,
                )
            )
            db.commit()
        db.rollback()
        with pytest.raises(AtomicError):
            import_document(db, RAW, COMMIT, "0" * 64, actor)


def test_concurrent_import_is_idempotent(db_ready):
    with session_factory()() as db:
        actor = db.scalar(select(User.id).where(User.username == "administrator"))

    def publish(_):
        with session_factory()() as db:
            doc, unchanged = import_document(db, RAW, COMMIT, SHA, actor)
            db.commit()
            return doc.id, unchanged

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(publish, range(2)))
    assert results[0][0] == results[1][0]
    assert sorted(x[1] for x in results) == [False, True]


def test_populated_b7_upgrade_preserves_all_existing_rows(db_ready, pg_engine):
    from alembic import command
    from alembic.config import Config
    from sqlalchemy import inspect

    config = Config("alembic.ini")

    def inventory():
        with pg_engine.connect() as conn:
            return {
                table: list(
                    conn.scalars(
                        text(
                            f'SELECT to_jsonb(t)::text FROM "{table}" t ORDER BY to_jsonb(t)::text'
                        )
                    )
                )
                for table in inspect(conn).get_table_names()
                if table != "alembic_version"
            }

    command.downgrade(config, "b7f3c2d91a06")
    try:
        before = inventory()
        assert (
            len(before) == 32 and before["test_definitions"] and before["attack_catalog_releases"]
        )
        command.upgrade(config, "head")
        after = inventory()
        for table in ("atomic_documents", "atomic_entries", "atomic_reviews"):
            assert after.pop(table) == []
        assert after == before
    finally:
        command.upgrade(config, "head")
