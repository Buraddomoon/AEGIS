"""Fixed offline converter entrypoint; stdlib-only when imported by the API.

Run only with the separately locked interpreter, never the application interpreter.
Input is bounded inert JSON, not YAML, a command, a pipeline or a destination.
"""

import hashlib
import json
import os
import re
import sys
from pathlib import Path
from uuid import UUID

VERSION = "sigma-query/1"
PROFILE_ID = "aegis-marker-lucene/1"
PINS = {
    "pysigma": "1.5.1",
    "pysigma-backend-opensearch": "2.0.3",
    "pysigma-backend-elasticsearch": "2.1.1",
}
LOCK_SHA256 = "6f63d628f1c880058059738e395e68c0dc5b46f129b957599eb40c9745aefe7e"
FIELDS = {
    "AegisSchema": "data.aegis.schema",
    "AegisObservation": "data.aegis.observation",
    "AegisBehavior": "data.aegis.behavior",
    "AegisMarker": "data.aegis.marker",
    "AegisExecutionId": "data.aegis.execution_id",
    "AegisLaboratoryId": "data.aegis.laboratory_id",
    "AegisAssetId": "data.aegis.asset_id",
    "AegisArtifactSHA256": "data.aegis.artifact_sha256",
    "AgentId": "agent.id",
    "RuleId": "rule.id",
}
LOGSOURCE = {"product": "aegis", "service": "marker_observer"}


def sha(value):
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    ).hexdigest()


def definition():
    profile = {
        "id": PROFILE_ID,
        "name": "Consulta Lucene · marcador ÆGIS",
        "target": "opensearch_lucene",
        "logsource": LOGSOURCE,
        "fields": FIELDS,
        "event_schema": "aegis-json/1",
        "index_mapping_verified": False,
        "policy": "literal-boolean/1",
    }
    return {
        "version": VERSION,
        "profile": {**profile, "sha256": sha(profile)},
        "packages": PINS,
        "lock_sha256": LOCK_SHA256,
        "implementation_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "pipeline": "FieldMappingTransformation/1",
        "output_format": "default",
    }


def blocker(document):
    if set(document) != {"title", "id", "logsource", "detection"}:
        return "metadata_unsupported"
    if not isinstance(document["title"], str) or not 1 <= len(document["title"]) <= 240:
        return "identity_invalid"
    try:
        UUID(document["id"])
    except (ValueError, TypeError, AttributeError):
        return "identity_invalid"
    if document["logsource"] != LOGSOURCE:
        return "logsource_mismatch"
    detection = document["detection"]
    if not isinstance(detection, dict):
        return "detection_unsupported"
    condition = detection.get("condition")
    if not isinstance(condition, str) or not 1 <= len(condition) <= 256:
        return "condition_unsupported"
    tokens = re.findall(r"[A-Za-z_][A-Za-z0-9_]*|[()]|\S", condition)
    if len(tokens) > 64 or any(not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*|[()]", t) for t in tokens):
        return "condition_unsupported"
    depth = 0
    for token in tokens:
        depth += (token == "(") - (token == ")")
        if not 0 <= depth <= 8:
            return "condition_unsupported"
    if depth:
        return "condition_unsupported"
    selections = {k: v for k, v in detection.items() if k != "condition"}
    if not 1 <= len(selections) <= 16:
        return "selection_limit"
    references = set(tokens) - {"and", "or", "not", "(", ")"}
    if references != set(selections):
        return "condition_references_unsupported"
    costs = {}
    for name, selection in selections.items():
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", name):
            return "selection_unsupported"
        if (
            name in {"and", "or", "not"}
            or not isinstance(selection, dict)
            or not 1 <= len(selection) <= 8
        ):
            return "selection_unsupported"
        cost = 0
        for field, value in selection.items():
            if field not in FIELDS:
                return "field_or_modifier_unsupported"
            values = value if isinstance(value, list) else [value]
            if not 1 <= len(values) <= 8:
                return "value_limit"
            for item in values:
                if (
                    not isinstance(item, str)
                    or not 1 <= len(item.encode()) <= 512
                    or any(c in item for c in "*?\\")
                    or any(ord(c) < 32 or ord(c) == 127 for c in item)
                ):
                    return "literal_string_required"
            cost += len(FIELDS[field]) + 8 + sum(2 * len(item.encode()) + 8 for item in values)
        costs[name] = cost
    if sum(costs.get(token, 0) for token in tokens) + 8 * len(tokens) > 8192:
        return "query_expansion_limit"
    return None


def audit(event, args):
    if event == "import" and str(args[0]).startswith(
        (
            "diskcache",
            "sigma.plugins",
            "sigma.validators",
            "sigma.data",
            "sigma.processing.resolver",
        )
    ):
        raise RuntimeError("Forbidden dynamic/cache import")
    if event.startswith(
        ("socket.", "subprocess.", "os.system", "os.posix_spawn", "os.exec", "os.fork")
    ):
        raise RuntimeError("Forbidden network/process effect")
    if event in {
        "os.remove",
        "os.rename",
        "os.mkdir",
        "os.rmdir",
        "os.chmod",
        "os.chown",
        "os.link",
        "os.symlink",
        "os.truncate",
        "os.utime",
    }:
        raise RuntimeError("Forbidden filesystem mutation")
    if event == "open" and (
        isinstance(args[1], str)
        and any(c in args[1] for c in "wax+")
        or args[2] & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND)
    ):
        raise RuntimeError("Forbidden file write")


def main():
    import resource
    from importlib.metadata import version

    resource.setrlimit(resource.RLIMIT_CPU, (3, 3))
    resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024, 512 * 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))
    resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
    sys.addaudithook(audit)
    if {name: version(name) for name in PINS} != PINS:
        raise ValueError("Unreviewed converter versions")
    raw = sys.stdin.buffer.read(65537)
    if len(raw) > 65536:
        raise ValueError("Input budget exceeded")
    document = json.loads(raw)
    if not isinstance(document, dict) or blocker(document):
        raise ValueError("Unsupported document")
    from sigma.backends.opensearch import OpensearchLuceneBackend
    from sigma.collection import SigmaCollection
    from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
    from sigma.processing.transformations import FieldMappingTransformation

    collection = SigmaCollection.from_dicts([document])
    if collection.errors or len(collection.rules) != 1:
        raise ValueError("Single rule required")
    rule = collection.rules[0]
    before = rule.detection.to_dict()
    pipeline = ProcessingPipeline(
        items=[ProcessingItem(transformation=FieldMappingTransformation(dict(FIELDS)))]
    )
    queries = OpensearchLuceneBackend(processing_pipeline=pipeline).convert(collection)
    expected = {
        name: {FIELDS[field]: value for field, value in selection.items()}
        if name != "condition"
        else selection
        for name, selection in before.items()
    }
    if rule.detection.to_dict() != expected:
        raise ValueError("Pipeline invariant failed")
    if (
        len(queries) != 1
        or not isinstance(queries[0], str)
        or not 1 <= len(queries[0].encode()) <= 8192
    ):
        raise ValueError("Output budget exceeded")
    if any(n.startswith("diskcache") for n in sys.modules):
        raise ValueError("Cache must remain absent")
    print(json.dumps({"query": queries[0], "definition_sha256": sha(definition())}))


if __name__ == "__main__":
    try:
        main()
    except Exception:
        # Never return parser/backend exceptions or input values to logs/stdout.
        sys.exit(1)
