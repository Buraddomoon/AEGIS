"""Offline field-mapping diagnostics. Does not import, install or execute a backend."""

import json
import platform
from importlib import metadata

from packaging.requirements import Requirement
from packaging.specifiers import SpecifierSet
from packaging.utils import canonicalize_name

from aegis.config import settings
from aegis.domain.validation import digest
from aegis.integrations.sigma_analysis import analyze

READINESS_VERSION = "sigma-readiness/1"
PROFILE_ID = "wazuh-aegis-marker/1"


def marker_profile() -> dict:
    return {
        "id": PROFILE_ID,
        "name": "Wazuh · observador de marcador ÆGIS",
        "status": "candidate_not_executable",
        "target": "opensearch_lucene",
        "logsource": {"product": "aegis", "service": "marker_observer"},
        "event_schema": "aegis-json/1",
        "source_evidence": "docs/evidence/wazuh-2026-10-22/alert.json",
        "index_mapping_verified": False,
        "fields": {
            "AegisSchema": "data.aegis.schema",
            "AegisObservation": "data.aegis.observation",
            "AegisBehavior": "data.aegis.behavior",
            "AegisMarker": "data.aegis.marker",
            "AegisExecutionId": "data.aegis.execution_id",
            "AegisLaboratoryId": "data.aegis.laboratory_id",
            "AegisAssetId": "data.aegis.asset_id",
            "AegisArtifactBytes": "data.aegis.artifact_bytes",
            "AegisArtifactSHA256": "data.aegis.artifact_sha256",
            "AgentId": "agent.id",
            "RuleId": "rule.id",
        },
    }


def installed_version(name: str) -> str | None:
    try:
        return metadata.version(name)
    except metadata.PackageNotFoundError:
        return None


def backend_status() -> dict:
    raw = (settings().fixtures_path / "sigma/backend-metadata.json").read_text()
    snapshot = json.loads(raw)
    expected = {"pysigma-backend-opensearch", "pysigma-backend-elasticsearch"}
    if (
        snapshot["schema_version"] != 1
        or {canonicalize_name(p["name"]) for p in snapshot["packages"]} != expected
    ):
        raise ValueError("Schema de metadados Sigma desconhecido.")
    packages, blockers = [], []
    for package in snapshot["packages"]:
        current = installed_version(package["name"])
        checks = []
        if current != package["version"]:
            blockers.append(
                {
                    "code": "backend_not_installed"
                    if current is None
                    else "backend_version_unreviewed",
                    "message": f"{package['name']}: versão revisada {package['version']}; instalada {current or 'ausente'}.",
                }
            )
        for text in package["requires_dist"]:
            requirement = Requirement(text)
            if requirement.marker and not requirement.marker.evaluate({"extra": ""}):
                continue
            actual = installed_version(requirement.name)
            satisfied = actual is not None and actual in requirement.specifier
            checks.append(
                {
                    "name": canonicalize_name(requirement.name),
                    "required": str(requirement.specifier),
                    "installed": actual,
                    "satisfied": satisfied,
                }
            )
            if not satisfied:
                blockers.append(
                    {
                        "code": "dependency_unsatisfied",
                        "message": f"{package['name']} exige {requirement}; instalada {actual or 'ausente'}.",
                    }
                )
        python_ok = platform.python_version() in SpecifierSet(package["requires_python"])
        if not python_ok:
            blockers.append(
                {
                    "code": "python_incompatible",
                    "message": f"{package['name']}: Python fora de {package['requires_python']}.",
                }
            )
        packages.append(
            {**package, "installed": current, "requirements": checks, "python_satisfied": python_ok}
        )
    return {
        "status": "blocked" if blockers else "declared_requirements_satisfied_only",
        "snapshot_reviewed_at": snapshot["reviewed_at"],
        "snapshot_sha256": digest(raw),
        "packages": packages,
        "blockers": blockers,
    }


def profiles() -> dict:
    profile = marker_profile()
    return {
        "items": [{**profile, "sha256": digest(profile)}],
        "backend": backend_status(),
        "readiness_version": READINESS_VERSION,
    }


def assess(content: str, profile_id: str = PROFILE_ID) -> dict:
    if profile_id != PROFILE_ID:
        raise LookupError("Perfil de conversão não encontrado.")
    analysis = analyze(content)
    profile, backend = marker_profile(), backend_status()
    facts = analysis["facts"]
    source = {
        k: v for k, v in facts["logsource"].items() if k in {"product", "service", "category"}
    }
    matches = source == profile["logsource"]
    mappings = [
        {"source_field": field, "target_field": profile["fields"].get(field) if matches else None}
        for field in facts["declared_fields"]
    ]
    blockers = list(backend["blockers"])
    if not matches:
        blockers.append(
            {
                "code": "logsource_mismatch",
                "message": "Logsource da regra não corresponde ao perfil de marcador ÆGIS.",
            }
        )
    if any(row["target_field"] is None for row in mappings):
        blockers.append(
            {
                "code": "unmapped_fields",
                "message": "Existem campos declarados sem mapeamento neste perfil.",
            }
        )
    if facts["keyword_selections"]:
        blockers.append(
            {
                "code": "keyword_mapping_unspecified",
                "message": "Seleções de palavras-chave não têm campo de destino definido.",
            }
        )
    if analysis["findings"] or analysis["skipped_checks"]:
        blockers.append(
            {
                "code": "static_review_required",
                "message": "Análise estática contém achados ou checks não executados; revisar a versão.",
            }
        )
    blockers += [
        {
            "code": "index_mapping_unverified",
            "message": "Tipos, analisadores e subcampos do índice não foram verificados.",
        },
        {
            "code": "conversion_pipeline_unimplemented",
            "message": "O perfil é candidato de mapeamento; não existe pipeline executável aprovado.",
        },
    ]
    return {
        "readiness_version": READINESS_VERSION,
        "sha256": analysis["sha256"],
        "profile": {**profile, "sha256": digest(profile)},
        "backend": backend,
        "analysis_version": analysis["analyzer_version"],
        "pysigma_version": analysis["pysigma_version"],
        "status": "blocked",
        "can_convert": False,
        "conversion_performed": False,
        "deployment_performed": False,
        "logsource_matches": matches,
        "field_mapping_complete": matches
        and bool(mappings)
        and all(row["target_field"] is not None for row in mappings)
        and not facts["keyword_selections"],
        "mappings": mappings,
        "keyword_selections": facts["keyword_selections"],
        "blockers": blockers,
        "limitations": [
            "Presença no _source não comprova mapping físico ou disponibilidade atual no SIEM.",
            "Metadados de pacotes são snapshot revisado, não consulta atual ao PyPI.",
            "Mapear nomes de campos não valida valores, modificadores ou equivalência da condição.",
            "Nenhuma consulta gerada, executada ou regra implantada; veredictos permanecem inalterados.",
        ],
    }
