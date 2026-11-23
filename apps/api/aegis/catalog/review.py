"""Opt-in, read-only inspection of host-prepared ATT&CK plans; no downloader."""

import hashlib
import os
import re

from aegis.catalog import artifacts, store
from aegis.catalog.document import HEX64, VERSION, parse_json
from aegis.config import settings
from aegis.domain.validation import digest

MAX_PLANS = 100
MAX_PLAN_BYTES = 12_000_000


def root():
    path = settings().attack_review_cache
    if path is None:
        return None
    if not path.is_absolute():
        raise ValueError("Review cache must be an absolute deployment path")
    artifacts.private(path.parent)
    artifacts.private(path)
    artifacts.private(path / "plans")
    return path


def load_plan(path, identity):
    if not re.fullmatch(HEX64, identity):
        raise ValueError("Invalid review identity")
    plan = parse_json(
        artifacts.read(path / "plans" / (identity + ".json"), MAX_PLAN_BYTES), MAX_PLAN_BYTES
    )
    if (
        not isinstance(plan, dict)
        or plan.get("format") != store.PLAN_FORMAT
        or plan.get("plan_sha256") != identity
        or digest({k: v for k, v in plan.items() if k != "plan_sha256"}) != identity
        or not re.fullmatch(HEX64, plan.get("candidate_id", ""))
        or not re.fullmatch(VERSION, plan.get("candidate_version", ""))
    ):
        raise ValueError("Invalid review file")
    return plan


def inventory(path):
    # Bound traversal as well as response size. Never silently omit overflow.
    with os.scandir(path / "plans") as entries:
        names = []
        for entry in entries:
            if len(names) >= MAX_PLANS:
                raise ValueError("Review inventory exceeds limit; archive plans on host")
            names.append(entry.name)
    items = []
    for name in sorted(names):
        if re.fullmatch(HEX64 + r"\.json", name):
            plan = load_plan(path, name[:-5])
            items.append(
                {key: plan[key] for key in ("plan_sha256", "candidate_id", "candidate_version")}
            )
    return items


def checked(db, path, identity):
    saved = load_plan(path, identity)
    document = artifacts.load(path, saved["candidate_id"])
    license_hash = hashlib.sha256(
        (settings().fixtures_path / "attack/LICENSE.txt").read_bytes()
    ).hexdigest()
    fresh = store.plan(db, document, license_hash)
    if saved != fresh:
        raise ValueError("Plan drift; regenerate on host")
    return fresh, document


def changes(db, plan, document, offset, limit):
    previous = store.projection(db)
    candidate = {t.id: t.model_dump() for t in document.techniques}
    items = []
    for change in plan["changes"][offset : offset + limit]:
        key = change["id"]
        before = previous.get(key)
        after = (
            {**candidate[key], "present_in_current": True}
            if key in candidate
            else {**before, "present_in_current": False}
        )
        items.append(
            {
                **change,
                "before": {field: before[field] if before else None for field in change["fields"]},
                "after": {field: after[field] for field in change["fields"]},
            }
        )
    return {"items": items, "total": len(plan["changes"]), "offset": offset, "limit": limit}
