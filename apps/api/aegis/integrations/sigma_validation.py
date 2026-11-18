"""Opt-in read-only Sigma assay. Never accepts a query or destination from HTTP."""

import ast
import hashlib
import os
import re
import stat
import time
from datetime import UTC, datetime, timedelta
from threading import BoundedSemaphore
from typing import Literal

import httpx
from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_validator

from aegis.config import require_normal_operation, settings
from aegis.domain.validation import digest
from aegis.integrations import sigma_conversion as conversion
from aegis.integrations.sigma_converter_worker import FIELDS
from aegis.integrations.sigma_index import SHA256, IndexMismatch, IndexProfile, verify_index
from aegis.integrations.wazuh import configured_provider, validate_destination
from aegis.integrations.yaml_import import safe_sigma_document

SLOT = BoundedSemaphore(1)


class ValidationBlocked(Exception):
    pass


class Scope(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    format: Literal["aegis-sigma-validation/1"] = "aegis-sigma-validation/1"
    index_profile: IndexProfile
    connection_sha256: SHA256
    rule_id: str = Field(min_length=36, max_length=36)
    rule_version_id: str = Field(min_length=36, max_length=36)
    content_sha256: SHA256
    contract_sha256: SHA256
    query_sha256: SHA256
    agent_id: str = Field(pattern=r"^0*[1-9][0-9]{0,11}$", min_length=3, max_length=12)
    start: AwareDatetime
    end: AwareDatetime
    approved_at: AwareDatetime
    expires_at: AwareDatetime

    @model_validator(mode="after")
    def windows(self):
        if not timedelta(0) < self.end - self.start <= timedelta(minutes=5):
            raise ValueError("Janela de consulta inválida.")
        if not timedelta(0) < self.expires_at - self.approved_at <= timedelta(minutes=30):
            raise ValueError("Validade de escopo inválida.")
        if self.end > self.approved_at:
            raise ValueError("Consulta exige janela histórica encerrada.")
        return self


def connection_hash() -> str:
    cfg = settings()
    validate_destination(
        cfg.wazuh_url or "", cfg.wazuh_allowed_ip or "", "wazuh-alerts-4.x-*", None
    )
    if not cfg.wazuh_username or not cfg.wazuh_password or not cfg.wazuh_ca_bundle:
        raise ValidationBlocked()
    with open(cfg.wazuh_ca_bundle, "rb") as stream:
        ca = stream.read(1_000_001)
    if len(ca) > 1_000_000:
        raise ValidationBlocked()
    return digest(
        {
            "url": cfg.wazuh_url,
            "ip": cfg.wazuh_allowed_ip,
            "ca_sha256": hashlib.sha256(ca).hexdigest(),
            "principal_sha256": digest(cfg.wazuh_username),
        }
    )


def load_scope() -> Scope:
    try:
        require_normal_operation()
        path = settings().sigma_validation_scope
        if path is None:
            raise ValidationBlocked()
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.getuid()
                or info.st_mode & 0o077
                or info.st_nlink != 1
                or info.st_size > 16384
            ):
                raise ValidationBlocked()
            scope = Scope.model_validate_json(stream.read(16385))
        if (
            not scope.approved_at <= datetime.now(UTC) < scope.expires_at
            or connection_hash() != scope.connection_sha256
        ):
            raise ValidationBlocked()
        return scope
    except (OSError, ValueError, RuntimeError):
        raise ValidationBlocked() from None


def source_value(source: dict, path: str):
    value = source
    for part in path.split("."):
        value = value[part]
    return value


def matches(source: dict, document: dict) -> bool:
    """Independent literal check; server matches are not trusted as semantic proof."""
    detection = document["detection"]
    names = {name: "s" + str(i) for i, name in enumerate(detection) if name != "condition"}
    original_names = {value: key for key, value in names.items()}

    def selection(name):
        for key, expected in detection[name].items():
            try:
                actual = source_value(source, FIELDS[key])
            except (KeyError, TypeError):
                return False
            expected = expected if isinstance(expected, list) else [expected]
            actual = actual if isinstance(actual, list) else [actual]
            if not any(type(value) is str and value in expected for value in actual):
                return False
        return True

    def walk(node):
        if isinstance(node, ast.Expression):
            return walk(node.body)
        if isinstance(node, ast.Name):
            return selection(original_names[node.id])
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            return not walk(node.operand)
        if isinstance(node, ast.BoolOp) and isinstance(node.op, (ast.And, ast.Or)):
            values = [walk(value) for value in node.values]
            return all(values) if isinstance(node.op, ast.And) else any(values)
        raise ValueError("Condição fora do contrato.")

    # Selection identifiers may be Python keywords. Rename tokens without eval;
    # Sigma's reviewed boolean syntax/precedence is otherwise the same here.
    condition = " ".join(
        names.get(token, token)
        for token in re.findall(r"[A-Za-z_][A-Za-z0-9_]*|[()]", detection["condition"])
    )
    return walk(ast.parse(condition, mode="eval"))


def validate_query(content: str, rule_id: str, version_id: str, expected_scope: str) -> dict:
    scope = load_scope()
    scope_hash = digest(scope.model_dump(mode="json"))
    if (
        expected_scope != scope_hash
        or rule_id != scope.rule_id
        or version_id != scope.rule_version_id
        or digest(content) != scope.content_sha256
        or conversion.contract()["sha256"] != scope.contract_sha256
    ):
        raise ValidationBlocked()
    artifact = conversion.convert(content)
    if artifact["status"] != "converted" or artifact["query_sha256"] != scope.query_sha256:
        raise ValidationBlocked()
    document = safe_sigma_document(content)
    fields = {
        FIELDS[field]
        for name, selection in document["detection"].items()
        if name != "condition"
        for field in selection
    }
    # Lucene range delimiters cannot always be escaped. The offline profile is
    # preserved; this execution profile refuses them before any network effect.
    if any(
        c in value
        for name, selection in document["detection"].items()
        if name != "condition"
        for raw in selection.values()
        for value in (raw if isinstance(raw, list) else [raw])
        for c in "<>"
    ):
        raise ValidationBlocked()
    if not SLOT.acquire(blocking=False):
        raise ValidationBlocked()
    provider = None
    begin = datetime.now(UTC)
    deadline = time.monotonic() + 15

    def guard():
        if (
            time.monotonic() >= deadline
            or digest(load_scope().model_dump(mode="json")) != scope_hash
        ):
            raise ValidationBlocked()

    try:
        provider = configured_provider(guard=guard, budget_end=deadline)
        before = verify_index(provider, scope.index_profile, fields)
        result = search(provider, scope, artifact["query"], document)
        after = None
        try:
            guard()
            after = verify_index(provider, scope.index_profile, fields)
            result["index_mapping_verified"] = before == after
        except (IndexMismatch, ValidationBlocked, httpx.HTTPError, TimeoutError, ValueError):
            result["index_mapping_verified"] = False
        result["complete"] &= result["index_mapping_verified"]
        result.update(
            format="aegis-sigma-validation-result/1",
            scope_sha256=scope_hash,
            scope=scope.model_dump(mode="json"),
            conversion=artifact,
            mapping_before=before,
            mapping_after=after,
            rule_id=rule_id,
            rule_version_id=version_id,
            started_at=begin.isoformat(),
            ended_at=datetime.now(UTC).isoformat(),
            siem_queried=True,
            synthetic=False,
            deployment_performed=False,
            historical_classification_changed=False,
            limitations=[
                "Read-only query over the scoped existing alert index; not rule deployment.",
                "No inference about archives, detection efficacy or absent telemetry.",
                "Local literal check verifies returned hits, not recall of missing documents.",
            ],
        )
        result["document_sha256"] = digest(result)
        return result
    finally:
        try:
            if provider is not None:
                provider.close()
        finally:
            SLOT.release()


def search(provider, scope: Scope, query: str, document: dict) -> dict:
    body = {
        "size": 100,
        "sort": ["_doc"],
        "track_total_hits": True,
        "timeout": "2000ms",
        "query": {
            "bool": {
                "filter": [
                    {"term": {"agent.id": scope.agent_id}},
                    {
                        "range": {
                            "timestamp": {
                                "gte": scope.start.isoformat(),
                                "lte": scope.end.isoformat(),
                            }
                        }
                    },
                ],
                "must": [
                    {
                        "query_string": {
                            "query": query,
                            "allow_leading_wildcard": False,
                            "lenient": False,
                        }
                    }
                ],
            }
        },
    }
    cursor, total, complete, exhausted = None, None, True, False
    hits, conflicts = {}, set()
    diagnostics, pages = [], 0
    cleanup = True
    response_known = False
    try:
        response = provider._request(
            "POST",
            f"/{scope.index_profile.index}/_search?scroll=1m&allow_no_indices=false&ignore_unavailable=false",
            body,
        )
        response_known = True
        for _ in range(10):
            pages += 1
            if "_scroll_id" not in response:
                response_known = False
                raise ValueError()
            if "_scroll_id" in response:
                if (
                    not isinstance(response["_scroll_id"], str)
                    or not 1 <= len(response["_scroll_id"]) <= 65536
                ):
                    response_known = False
                    raise ValueError()
                cursor = response["_scroll_id"]
            shards = response["_shards"]
            if (
                response.get("timed_out") is not False
                or response.get("terminated_early", False) is not False
                or any(type(shards[k]) is not int for k in ("total", "successful", "failed"))
                or shards["total"] <= 0
                or shards["failed"] != 0
                or shards["successful"] != shards["total"]
            ):
                complete = False
            reported = response["hits"]["total"]
            count = reported["value"]
            if reported.get("relation") != "eq" or type(count) is not int or count < 0:
                raise ValueError()
            if total is not None and total != count:
                complete = False
            total = count
            batch = response["hits"]["hits"]
            if not isinstance(batch, list) or len(batch) > 100:
                raise ValueError()
            for hit in batch:
                identifier, index, source = hit["_id"], hit["_index"], hit["_source"]
                if (
                    not isinstance(identifier, str)
                    or not 1 <= len(identifier) <= 1024
                    or index != scope.index_profile.index
                ):
                    raise ValueError()
                timestamp = datetime.fromisoformat(source["timestamp"].replace("Z", "+00:00"))
                valid = (
                    timestamp.tzinfo is not None
                    and scope.start <= timestamp <= scope.end
                    and source["agent"]["id"] == scope.agent_id
                    and matches(source, document)
                )
                selected = {"_id": identifier, "_index": index, "_source": source}
                if not valid or identifier in hits and hits[identifier] != selected:
                    conflicts.add(identifier)
                    complete = False
                if identifier not in conflicts:
                    hits[identifier] = selected
            if not batch or not cursor:
                exhausted = True
                break
            if not complete:
                break
            if pages == 10:
                break
            response_known = False
            response = provider._request(
                "POST", "/_search/scroll", {"scroll": "1m", "scroll_id": cursor}
            )
            response_known = True
    except (
        httpx.HTTPError,
        TimeoutError,
        ValueError,
        KeyError,
        TypeError,
        AttributeError,
        ValidationBlocked,
    ):
        complete = False
        # A lost response may have allocated/rotated a cursor whose ID we never
        # received. Even a successful DELETE of an older ID cannot prove cleanup.
        cleanup = response_known
        diagnostics.append("Search incomplete: transport, scope, timeout or response contract.")
    finally:
        if cursor:
            try:
                reply = provider._request("DELETE", "/_search/scroll", {"scroll_id": [cursor]})
                cleanup = cleanup and (
                    reply.get("succeeded") is True
                    and type(reply.get("num_freed")) is int
                    and reply["num_freed"] > 0
                )
            except (httpx.HTTPError, TimeoutError, ValueError, KeyError, TypeError):
                cleanup = False
    for identifier in conflicts:
        hits.pop(identifier, None)
    complete = bool(complete and exhausted and total == len(hits) and cleanup and not conflicts)
    if not complete:
        diagnostics.append(
            "No complete negative conclusion; inspect pages, total, conflicts, shards and cleanup."
        )
    return {
        "hits": list(hits.values()),
        "total": total,
        "returned": len(hits),
        "pages": pages,
        "complete": complete,
        "cleanup_confirmed": cleanup,
        "conflicts": len(conflicts),
        "diagnostics": diagnostics,
    }
