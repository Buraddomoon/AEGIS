import re

import yaml
from sigma.collection import SigmaCollection
from yaml.events import AliasEvent


def safe_document(content: str) -> dict:
    if len(content.encode()) > 65536:
        raise ValueError("YAML excede 64 KiB.")
    count = 0
    for event in yaml.parse(content, Loader=yaml.SafeLoader):
        count += 1
        if count > 5000 or isinstance(event, AliasEvent) or getattr(event, "anchor", None):
            raise ValueError("Aliases, âncoras ou YAML excessivamente complexo não são permitidos.")
    value = yaml.safe_load(content)
    if not isinstance(value, dict):
        raise ValueError("Esperado um único documento YAML do tipo objeto.")
    return value


def parse_sigma(content: str) -> dict:
    document = safe_document(content)
    collection = SigmaCollection.from_dicts([document])
    if collection.errors or len(collection.rules) != 1:
        raise ValueError("Forneça exatamente uma regra Sigma válida.")
    rule = collection.rules[0]
    if not rule.id:
        raise ValueError("A regra deve possuir um UUID estável no campo id.")
    techniques = [str(tag).removeprefix("attack.").upper() for tag in rule.tags
                  if re.fullmatch(r"attack\.t\d{4}(\.\d{3})?", str(tag), re.IGNORECASE)]
    return {"title": rule.title, "sigma_id": str(rule.id), "techniques": techniques}


class AtomicMetadataProvider:
    def import_metadata(self, content: str) -> list[dict]:
        document = safe_document(content)
        technique = document.get("attack_technique", "")
        if not re.fullmatch(r"T\d{4}(\.\d{3})?", technique):
            raise ValueError("ID ATT&CK inválido.")
        result = []
        tests = document.get("atomic_tests", [])
        if not isinstance(tests, list) or len(tests) > 100:
            raise ValueError("Lista de testes Atomic inválida.")
        for item in tests:
            executor = item.get("executor", {})
            result.append({"guid": item.get("auto_generated_guid"),
                "name": item["name"], "technique_id": technique,
                "platforms": item.get("supported_platforms", []),
                "dependencies": item.get("dependencies", []),
                "input_arguments": item.get("input_arguments", {}),
                "executor": executor.get("name"),
                "has_cleanup": bool(executor.get("cleanup_command")),
                "elevation_required": executor.get("elevation_required", False),
                "approved": False, "executable": False})
        return result
