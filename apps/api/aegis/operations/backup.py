"""Read-only PostgreSQL inventory for an isolated recovery rehearsal.

Inventories contain counts and hashes, never row contents. Source/target must use
PostgreSQL of the same major version and UTC. ACLs/roles are intentionally outside
this portable data inventory and must be provisioned independently.
"""

import hashlib
import json
import re
from collections.abc import Callable, Iterable
from datetime import datetime, timedelta
from typing import Any

from aegis.domain.validation import digest

FORMAT = "aegis-demo-backup/1"
Query = Callable[[str], Iterable[str]]
STRUCTURE_COMPARISON = "pg17-literal-array-casts/1"
SQL_LITERAL = r"'(?:[^']|'')*'::character varying"
ARRAY_CAST = re.compile(r"\(ARRAY\[(" + SQL_LITERAL + r"(?:, " + SQL_LITERAL + r")*)\]\)::text\[\]")


def constraint_rows(rows: Iterable[str]) -> Iterable[str]:
    """Normalize only PostgreSQL's literal varchar[] -> text[] round trip.

    No general SQL equivalence inference. Functions, NULLs, other casts/types and
    arbitrary expressions are preserved and must compare exactly.
    """
    for encoded in rows:
        row = json.loads(encoded)

        def cast_elements(match: re.Match) -> str:
            literals = re.findall(SQL_LITERAL, match[1])
            return "ARRAY[" + ", ".join("(" + value + ")::text" for value in literals) + "]"

        row["definition"] = ARRAY_CAST.sub(cast_elements, row["definition"])
        yield json.dumps(row)


def identifier(value: str) -> str:
    if not re.fullmatch(r"[a-z_][a-z_0-9]{0,62}", value):
        raise ValueError("Unsupported SQL identifier")
    return '"' + value + '"'


def structure_queries(schema: str) -> dict[str, str]:
    identifier(schema)
    return {
        "table_properties": f"""SELECT to_jsonb(x)::text FROM (
          SELECT c.relname, c.relpersistence, c.relreplident, c.reloptions,
            c.relrowsecurity, c.relforcerowsecurity FROM pg_class c
          JOIN pg_namespace n ON n.oid=c.relnamespace
          WHERE n.nspname='{schema}' AND c.relkind='r'
          ORDER BY c.relname COLLATE "C") x""",
        "column_attributes": f"""SELECT to_jsonb(x)::text FROM (
          SELECT c.relname, a.attnum, a.attname, a.atttypmod,
            format_type(a.atttypid,a.atttypmod) AS formatted_type,
            a.attnotnull, a.attidentity, a.attgenerated,
            cn.nspname AS collation_schema, co.collname AS collation
          FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid
          JOIN pg_namespace n ON n.oid=c.relnamespace
          LEFT JOIN pg_collation co ON co.oid=a.attcollation
          LEFT JOIN pg_namespace cn ON cn.oid=co.collnamespace
          WHERE n.nspname='{schema}' AND c.relkind='r'
            AND a.attnum>0 AND NOT a.attisdropped
          ORDER BY c.relname COLLATE "C", a.attnum) x""",
        "columns": f"""SELECT to_jsonb(x)::text FROM (
          SELECT table_name, ordinal_position, column_name, data_type, udt_name,
            is_nullable, column_default, character_maximum_length
          FROM information_schema.columns WHERE table_schema='{schema}'
          ORDER BY table_name COLLATE "C", ordinal_position) x""",
        "constraints": f"""SELECT to_jsonb(x)::text FROM (
          SELECT c.relname AS table_name, p.conname, p.contype, p.convalidated,
            pg_get_constraintdef(p.oid) AS definition
          FROM pg_constraint p JOIN pg_class c ON c.oid=p.conrelid
          JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='{schema}'
          ORDER BY c.relname COLLATE "C", p.conname COLLATE "C") x""",
        "indexes": f"""SELECT to_jsonb(x)::text FROM (
          SELECT tablename, indexname, indexdef FROM pg_indexes
          WHERE schemaname='{schema}' ORDER BY indexname COLLATE "C") x""",
        "index_state": f"""SELECT to_jsonb(x)::text FROM (
          SELECT c.relname, i.indisvalid, i.indisready, i.indislive, i.indisreplident
          FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid
          JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='{schema}'
          ORDER BY c.relname COLLATE "C") x""",
        "triggers": f"""SELECT to_jsonb(x)::text FROM (
          SELECT c.relname, t.tgname, t.tgenabled, pg_get_triggerdef(t.oid) AS definition
          FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid
          JOIN pg_namespace n ON n.oid=c.relnamespace
          WHERE n.nspname='{schema}' AND NOT t.tgisinternal
          ORDER BY c.relname COLLATE "C", t.tgname COLLATE "C") x""",
        "functions": f"""SELECT to_jsonb(x)::text FROM (
          SELECT p.proname, pg_get_functiondef(p.oid) AS definition
          FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
          WHERE n.nspname='{schema}' AND p.prokind='f'
          ORDER BY p.proname COLLATE "C", pg_get_function_identity_arguments(p.oid)
            COLLATE "C") x""",
    }


def fingerprint(rows: Iterable[str], table: str | None = None) -> dict[str, Any]:
    hasher = hashlib.sha256()
    count = 0
    checks = {
        "telemetry_events": ("raw", "sha256"),
        "rule_versions": ("content", "sha256"),
        "campaign_runs": ("scope", "scope_hash"),
        "schedules": ("scope", "scope_hash"),
    }
    for encoded in rows:
        row = json.loads(encoded)
        if table in checks:
            content, expected = checks[table]
            if digest(row[content]) != row[expected]:
                raise ValueError(f"Stored integrity hash mismatch: {table}")
        # Canonical JSON decouples client JSON spacing from PostgreSQL formatting.
        hasher.update(
            json.dumps(row, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        )
        hasher.update(b"\n")
        count += 1
    return {"rows": count, "sha256": hasher.hexdigest()}


def inventory(query: Query, schema: str = "public") -> dict[str, Any]:
    identifier(schema)
    # Version 1 deliberately rejects objects whose state isn't covered by the
    # snapshot/inventory (e.g. nontransactional sequence counters).
    unsupported = list(
        query(f"""SELECT to_jsonb(c.relname)::text
      FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
      WHERE n.nspname='{schema}' AND c.relkind NOT IN ('r','i','t')""")
    )
    if unsupported:
        raise ValueError("Unsupported relation types in backup schema")
    unsupported_features = [
        f"""SELECT to_jsonb(tablename)::text FROM pg_policies WHERE schemaname='{schema}'""",
        f"""SELECT to_jsonb(c.relname)::text FROM pg_class c
          JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='{schema}'
          AND (c.relrowsecurity OR c.relforcerowsecurity OR c.reloftype<>0 OR c.relispartition)""",
        f"""SELECT to_jsonb(p.proname)::text FROM pg_proc p
          JOIN pg_namespace n ON n.oid=p.pronamespace
          WHERE n.nspname='{schema}' AND p.prokind<>'f'""",
        f"""SELECT to_jsonb(t.typname)::text FROM pg_type t
          JOIN pg_namespace n ON n.oid=t.typnamespace WHERE n.nspname='{schema}'
          AND NOT ((t.typtype='c' AND t.typrelid IN
            (SELECT oid FROM pg_class WHERE relkind='r'))
            OR (t.typtype='b' AND t.typelem IN
              (SELECT oid FROM pg_type WHERE typtype='c' AND typrelid IN
                (SELECT oid FROM pg_class WHERE relkind='r'))))""",
    ]
    if any(list(query(sql)) for sql in unsupported_features):
        raise ValueError("Unsupported database features in backup schema")
    tables = [
        json.loads(row)
        for row in query(f"""SELECT to_jsonb(tablename)::text
      FROM pg_tables WHERE schemaname='{schema}' ORDER BY tablename COLLATE "C" """)
    ]
    if not tables or "alembic_version" not in tables:
        raise ValueError("Missing AEGIS migration schema")
    qualified = identifier(schema)
    return {
        "tables": {
            table: fingerprint(
                query(
                    f"SELECT to_jsonb(t)::text FROM {qualified}.{identifier(table)} t "
                    'ORDER BY to_jsonb(t)::text COLLATE "C"'
                ),
                table,
            )
            for table in tables
        },
        "structure": {
            name: fingerprint(constraint_rows(query(sql)) if name == "constraints" else query(sql))
            for name, sql in structure_queries(schema).items()
        },
        "structure_comparison": STRUCTURE_COMPARISON,
        "migration": [
            json.loads(row)
            for row in query(
                f"SELECT to_jsonb(version_num)::text FROM {qualified}.alembic_version "
                'ORDER BY version_num COLLATE "C"'
            )
        ],
    }


def compare(expected: dict, restored: dict) -> None:
    if expected != restored:
        raise ValueError("Restored inventory differs from backup snapshot")


def retention_plan(records: list[dict], at: datetime) -> list[dict]:
    """Advisory only: no deletion API, preserve at least seven and thirty days."""
    if at.tzinfo is None:
        raise ValueError("Retention timestamps must include timezone")
    parsed = [(record, datetime.fromisoformat(record["created_at"])) for record in records]
    if any(created.tzinfo is None for _, created in parsed):
        raise ValueError("Retention timestamps must include timezone")
    ordered = sorted(parsed, key=lambda pair: pair[1], reverse=True)
    result = []
    for position, (record, created) in enumerate(ordered):
        keep = position < 7 or created >= at - timedelta(days=30)
        result.append(
            {
                "id": record["id"],
                "action": "keep" if keep else "review_only",
                "reason": "recent_or_minimum_count" if keep else "older_than_policy",
                "deletion_performed": False,
            }
        )
    return result
