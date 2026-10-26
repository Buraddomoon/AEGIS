"""A fixed pySigma rename pipeline, never a query converter or pipeline loader."""

import re
from importlib.metadata import version
from uuid import UUID

from sigma.collection import SigmaCollection
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations.fields import FieldMappingTransformation

from aegis.domain.validation import digest
from aegis.integrations.sigma_analysis import analyze
from aegis.integrations.sigma_readiness import PROFILE_ID, marker_profile
from aegis.integrations.yaml_import import safe_sigma_document

PREVIEW_VERSION = "sigma-mapping-preview/1"
CORE_VERSION = "2.0.1"
METADATA = {
    "title",
    "id",
    "name",
    "status",
    "description",
    "author",
    "date",
    "modified",
    "references",
    "tags",
    "falsepositives",
    "level",
    "license",
    "related",
    "fields",
    "logsource",
    "detection",
}


class MappingUnavailable(ValueError):
    pass


def definition() -> dict:
    profile = marker_profile()
    return {
        "version": PREVIEW_VERSION,
        "pysigma_version": CORE_VERSION,
        "profile_id": profile["id"],
        "profile_sha256": digest(profile),
        "transformation": "FieldMappingTransformation",
        "mapping": profile["fields"],
        "policy": "flat-string-equality/1",
    }


def unsupported(document: dict, profile: dict) -> str | None:
    if set(document) - METADATA:
        return "metadata_unsupported"
    if document.get("logsource") != profile["logsource"]:
        return "logsource_mismatch"
    detection = document["detection"]
    condition = detection.get("condition")
    if not isinstance(condition, str) or not 1 <= len(condition) <= 2048:
        return "condition_unsupported"
    selections = {key: value for key, value in detection.items() if key != "condition"}
    if not 1 <= len(selections) <= 32:
        return "selection_limit"
    for name, selection in selections.items():
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,79}", name):
            return "selection_unsupported"
        if not isinstance(selection, dict) or not 1 <= len(selection) <= 32:
            return "selection_unsupported"
        for field, value in selection.items():
            if field not in profile["fields"]:
                return "field_or_modifier_unsupported"
            values = value if isinstance(value, list) else [value]
            if not 1 <= len(values) <= 16:
                return "value_limit"
            for item in values:
                if (
                    not isinstance(item, str)
                    or not 1 <= len(item.encode()) <= 1024
                    or any(char in item for char in "*?\\")
                    or any(ord(char) < 32 or ord(char) == 127 for char in item)
                ):
                    return "literal_string_required"
    return None


def preview(content: str, profile_id: str = PROFILE_ID) -> dict:
    if profile_id != PROFILE_ID:
        raise LookupError("Perfil de mapeamento não encontrado.")
    if version("pysigma") != CORE_VERSION:
        raise MappingUnavailable("Versão pySigma não revisada para esta prévia.")
    document = safe_sigma_document(content)  # Before any pySigma model construction.
    if not isinstance(document.get("title"), str) or not 1 <= len(document["title"]) <= 240:
        raise ValueError("Título ausente ou inválido.")
    if not isinstance(document.get("id"), str):
        raise ValueError("UUID ausente ou inválido.")
    UUID(document["id"])
    profile, pipeline_definition = marker_profile(), definition()
    response = {
        "preview_version": PREVIEW_VERSION,
        "sha256": digest(content),
        "profile": {**profile, "sha256": digest(profile)},
        "pipeline": {**pipeline_definition, "sha256": digest(pipeline_definition)},
        "status": "unsupported",
        "blockers": [],
        "before_detection": None,
        "after_detection": None,
        "can_convert": False,
        "query_generated": False,
        "siem_queried": False,
        "deployment_performed": False,
        "index_mapping_verified": False,
        "limitations": [
            "Prévia de rename de campos; não é regra importável, consulta ou conversão SIEM.",
            "Somente seleções planas com igualdade de strings literais, sem modificadores.",
            "Condições/valores normalizados preservados não comprovam semântica no índice real.",
            "Tipos/analisadores do índice e backend compatível permanecem não verificados.",
        ],
    }
    blocker = unsupported(document, profile)
    if blocker is None:
        analysis = analyze(content)
        if analysis["findings"] or analysis["skipped_checks"]:
            blocker = "static_review_required"
    if blocker:
        response["blockers"] = [
            {
                "code": blocker,
                "message": "Regra fora do subconjunto revisado; consulte os limites da prévia de mapeamento.",
            }
        ]
    else:
        # Only inert metadata and the bounded detection are passed to a fresh model.
        rule = SigmaCollection.from_dicts(
            [
                {
                    "title": document["title"],
                    "id": document["id"],
                    "logsource": document["logsource"],
                    "detection": document["detection"],
                }
            ]
        ).rules[0]
        before = rule.detection.to_dict()
        expected = {
            name: (
                {profile["fields"][field]: value for field, value in selection.items()}
                if name != "condition"
                else selection
            )
            for name, selection in before.items()
        }
        pipeline = ProcessingPipeline(
            items=[
                ProcessingItem(
                    transformation=FieldMappingTransformation(dict(profile["fields"])),
                    identifier=PREVIEW_VERSION,
                )
            ]
        )
        pipeline.apply(rule)
        after = rule.detection.to_dict()
        if after != expected or pipeline.applied != [True]:
            raise MappingUnavailable("Transformação divergiu do rename revisado.")
        response.update(status="previewed", before_detection=before, after_detection=after)
    response["document_sha256"] = digest(response)
    return response
