"""Bounded static checks using pySigma's parsed model, without validator discovery/cache."""

import json
from importlib.metadata import version

from sigma.collection import SigmaCollection
from sigma.conditions import ConditionIdentifier, ConditionItem, ConditionSelector
from sigma.exceptions import SigmaError
from sigma.modifiers import SigmaAllModifier, SigmaContainsModifier
from sigma.rule import SigmaDetection, SigmaRule
from sigma.types import SigmaString, SpecialChars

from aegis.domain.validation import digest
from aegis.integrations.yaml_import import safe_document

ANALYZER_VERSION = "sigma-static/1"
CHECKS = [
    "condition_resolution",
    "unused_selection",
    "all_without_contains",
    "consecutive_wildcards",
    "control_character",
]


def analyze(content: str) -> dict:
    document = safe_document(content)
    collection = SigmaCollection.from_dicts([document])
    if collection.errors or len(collection.rules) != 1:
        raise ValueError("Esperada exatamente uma regra Sigma.")
    rule = collection.rules[0]
    if not isinstance(rule, SigmaRule):
        raise ValueError("Análise limitada a regras de detecção Sigma individuais.")
    conditions = rule.detection.condition
    if len(conditions) > 32 or any(len(c) > 2048 for c in conditions):
        raise ValueError("Análise limitada a 32 condições de até 2048 caracteres.")
    if len(rule.detection.detections) > 128:
        raise ValueError("Análise limitada a 128 seleções.")
    fields, keyword_selections, referenced = set(), set(), set()
    findings = []

    def finding(code: str, severity: str, message: str, **context) -> None:
        findings.append(
            {
                "code": code,
                "severity": severity,
                "message": message,
                "origin": "aegis_static",
                **context,
            }
        )

    def visit(detection: SigmaDetection, name: str) -> None:
        for item in detection.detection_items:
            if isinstance(item, SigmaDetection):
                visit(item, name)
                continue
            if item.field is not None:
                fields.add(item.field)
            else:
                keyword_selections.add(name)
            context = {"selection": name, "field": item.field}
            if (
                item.field is not None
                and SigmaAllModifier in item.modifiers
                and SigmaContainsModifier not in item.modifiers
            ):
                finding(
                    "all_without_contains",
                    "HIGH",
                    "Campo usa all sem contains; revisar a lógica de igualdade.",
                    **context,
                )
            for value in item.value:
                if not isinstance(value, SigmaString):
                    continue
                if any(
                    a == b == SpecialChars.WILDCARD_MULTI
                    for a, b in zip(value.s, value.s[1:], strict=False)
                ):
                    finding(
                        "consecutive_wildcards",
                        "LOW",
                        "O valor contém curingas * consecutivos.",
                        **context,
                    )
                if any(
                    isinstance(part, str) and any(ord(c) < 32 for c in part) for part in value.s
                ):
                    finding(
                        "control_character",
                        "HIGH",
                        "O valor contém caractere de controle; revisar escapes.",
                        **context,
                    )

    def references(node) -> None:
        if isinstance(node, ConditionSelector):
            matches = node.resolve_referenced_detections(rule.detection)
            if not matches:
                raise ValueError("Seletor sem correspondência.")
            referenced.update(match.identifier for match in matches)
        elif isinstance(node, ConditionIdentifier):
            referenced.add(node.identifier)
        elif isinstance(node, ConditionItem):
            for arg in node.args:
                references(arg)

    for name, detection in rule.detection.detections.items():
        visit(detection, name)
    invalid_condition = False
    for index, condition in enumerate(rule.detection.parsed_condition):
        try:
            # parse(False) retains selection names; .parsed resolves through the official parser.
            references(condition.parse(False))
            _ = condition.parsed
        except (SigmaError, ValueError, RecursionError):
            invalid_condition = True
            finding(
                "condition_resolution",
                "HIGH",
                "Não foi possível resolver a condição com as seleções declaradas.",
                condition_index=index,
            )
    if not invalid_condition:
        for name in sorted(set(rule.detection.detections) - referenced):
            finding(
                "unused_selection",
                "HIGH",
                "A seleção declarada não é referenciada pela condição.",
                selection=name,
            )
    findings.sort(key=lambda f: json.dumps(f, sort_keys=True, ensure_ascii=False))
    return {
        "analyzer_version": ANALYZER_VERSION,
        "pysigma_version": version("pysigma"),
        "sha256": digest(content),
        "status": "findings" if findings else "no_findings_in_selected_checks",
        "checks": [c for c in CHECKS if not (invalid_condition and c == "unused_selection")],
        "skipped_checks": ["unused_selection"] if invalid_condition else [],
        "facts": {
            "logsource": rule.logsource.to_dict(),
            "conditions": conditions,
            "selections": sorted(rule.detection.detections),
            "declared_fields": sorted(fields),
            "keyword_selections": sorted(keyword_selections),
        },
        "findings": findings,
        "compatibility": {
            "status": "not_configured",
            "backend": None,
            "pipeline": None,
            "conversion_performed": False,
            "deployment_performed": False,
        },
        "limitations": [
            "Análise estática parcial; ausência de achados não comprova correção ou eficácia.",
            "Severidade indica prioridade de revisão da regra, não risco de negócio.",
            "Campos declarados não comprovam disponibilidade ou mapeamento na telemetria.",
            "Sem backend/pipeline configurado; compatibilidade Wazuh não foi avaliada.",
        ],
    }
