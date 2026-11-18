"""Bounded query artifacts from a fixed separately locked official converter."""

import hashlib
import json
import subprocess
from pathlib import Path
from threading import BoundedSemaphore

from aegis.domain.validation import digest
from aegis.integrations import sigma_converter_worker as worker
from aegis.integrations.sigma_analysis import analyze
from aegis.integrations.sigma_mapping import METADATA
from aegis.integrations.yaml_import import safe_sigma_document

SLOTS = BoundedSemaphore(2)
SCRIPT = Path(worker.__file__).resolve()


class ConversionUnavailable(Exception):
    pass


def interpreter() -> Path:
    deployed = Path("/opt/aegis-sigma-converter/bin/python")
    return (
        deployed if deployed.is_file() else SCRIPT.parents[4] / ".venv-sigma-converter/bin/python"
    )


def contract() -> dict:
    definition = worker.definition()
    return {**definition, "sha256": digest(definition)}


def profiles() -> dict:
    return {"items": [contract()], "configured": interpreter().is_file()}


def convert(content: str, profile_id: str = worker.PROFILE_ID) -> dict:
    if profile_id != worker.PROFILE_ID:
        raise LookupError("Perfil de consulta não encontrado.")
    document = safe_sigma_document(content)
    source = {key: document.get(key) for key in ("title", "id", "logsource", "detection")}
    reason = "metadata_unsupported" if set(document) - METADATA else worker.blocker(source)
    if reason is None:
        analysis = analyze(content)
        if analysis["findings"] or analysis["skipped_checks"]:
            reason = "static_review_required"
    definition = contract()
    result = {
        "conversion_version": worker.VERSION,
        "sha256": digest(content),
        "contract": definition,
        "status": "unsupported",
        "blockers": [],
        "query": None,
        "query_sha256": None,
        "conversion_performed": False,
        "siem_queried": False,
        "deployment_performed": False,
        "index_mapping_verified": False,
        "limitations": [
            "Consulta offline; não executada, não implantada e sem comprovação de eficácia.",
            "Caminhos candidatos do marcador; tipos/analisadores do índice físico não verificados.",
            "Igualdade de strings/listas e AND/OR/NOT; sem modificadores, fieldref ou seletores.",
            "O conversor usa bibliotecas próprias; parser e histórico da aplicação preservados.",
        ],
    }
    if reason:
        result["blockers"] = [
            {"code": reason, "message": "Fora da política literal-boolean/1: " + reason}
        ]
    else:
        query = execute(source, definition["sha256"])
        result.update(
            status="converted",
            query=query,
            query_sha256=hashlib.sha256(query.encode()).hexdigest(),
            conversion_performed=True,
        )
    result["document_sha256"] = digest(result)
    return result


def execute(document: dict, expected: str) -> str:
    payload = json.dumps(document, ensure_ascii=False).encode()
    if len(payload) > 65536:
        raise ValueError("Documento excede orçamento JSON do conversor.")
    if not SLOTS.acquire(blocking=False):
        raise ConversionUnavailable()
    try:
        completed = subprocess.run(
            [str(interpreter()), "-I", "-B", str(SCRIPT)],
            input=payload,
            capture_output=True,
            timeout=5,
            cwd="/",
            env={"LANG": "C.UTF-8", "PYSIGMA_ALLOW_VARS_EXECUTION": "false"},
        )
        if completed.returncode or completed.stderr or len(completed.stdout) > 65536:
            raise ConversionUnavailable()
        output = json.loads(completed.stdout)
        if set(output) != {"query", "definition_sha256"} or output["definition_sha256"] != expected:
            raise ConversionUnavailable()
        query = output["query"]
        if (
            not isinstance(query, str)
            or not 1 <= len(query.encode()) <= 8192
            or any(ord(c) < 32 or ord(c) == 127 for c in query)
        ):
            raise ConversionUnavailable()
        return query
    except (OSError, subprocess.SubprocessError, ValueError, TypeError, KeyError):
        raise ConversionUnavailable() from None
    finally:
        SLOTS.release()
