import re

import yaml
from sigma.collection import SigmaCollection
from yaml.events import AliasEvent, CollectionEndEvent, CollectionStartEvent


def safe_document(content: str) -> dict:
    if len(content.encode()) > 65536:
        raise ValueError("YAML excede 64 KiB.")
    count = 0
    depth = 0
    for event in yaml.parse(content, Loader=yaml.SafeLoader):
        count += 1
        if isinstance(event, CollectionStartEvent):
            depth += 1
        elif isinstance(event, CollectionEndEvent):
            depth -= 1
        if depth > 32:
            raise ValueError("YAML excede profundidade máxima de 32 coleções.")
        if count > 5000 or isinstance(event, AliasEvent) or getattr(event, "anchor", None):
            raise ValueError("Aliases, âncoras ou YAML excessivamente complexo não são permitidos.")
    value = yaml.safe_load(content)
    if not isinstance(value, dict):
        raise ValueError("Esperado um único documento YAML do tipo objeto.")
    return value


def safe_sigma_document(content: str) -> dict:
    """Reject expansion before pySigma applies modifiers; conservative UTF-8 budgets."""
    document = safe_document(content)
    if any(key in document for key in ("filter", "correlation", "action")) or not isinstance(
        document.get("detection"), dict
    ):
        raise ValueError(
            "Forneça regra individual com detection objeto, sem filter/correlation/action."
        )
    stack = [(document["detection"], ())]
    expanded_bytes = variants_total = 0
    while stack:
        value, modifiers = stack.pop()
        if isinstance(value, dict):
            for key, child in value.items():
                if not isinstance(key, str):
                    raise ValueError("Chaves de detection devem ser strings.")
                chain = tuple(key.split("|")[1:])
                if len(chain) > 6 or len(set(chain)) != len(chain):
                    raise ValueError("Cadeia Sigma limitada a 6 modificadores sem repetição.")
                stack.append((child, chain))
        elif isinstance(value, list):
            stack.extend((child, modifiers) for child in value)
        elif isinstance(value, str):
            size, variants = len(value.encode()), 1
            for modifier in modifiers:
                if modifier in {"wide", "utf16", "utf16le", "utf16be"}:
                    size = 4 * size + 8
                elif modifier == "base64":
                    size = ((size + 2) // 3) * 4 + 8
                elif modifier == "base64offset":
                    size = ((size + 4) // 3) * 4 + 8
                    variants *= 3
                elif modifier == "windash":
                    size = 3 * size + 8
                    variants *= 125  # pySigma2.0.1 caps expansion at three dash positions.
                else:
                    size += 8  # Other pinned modifiers do not multiply strings/variants.
                if size * variants > 262144:
                    raise ValueError("Expansão Sigma excede orçamento por valor de 256 KiB.")
            expanded_bytes += size * variants
            variants_total += variants
            if expanded_bytes > 1048576 or variants_total > 4096:
                raise ValueError("Expansão Sigma excede orçamento total de 1 MiB/4096 variantes.")
    return document


def parse_sigma(content: str) -> dict:
    document = safe_sigma_document(content)
    collection = SigmaCollection.from_dicts([document])
    if collection.errors or len(collection.rules) != 1:
        raise ValueError("Forneça exatamente uma regra Sigma válida.")
    rule = collection.rules[0]
    if not rule.title or len(rule.title) > 240:
        raise ValueError("Título Sigma deve possuir entre 1 e 240 caracteres.")
    if not rule.id:
        raise ValueError("A regra deve possuir um UUID estável no campo id.")
    techniques = [
        str(tag).removeprefix("attack.").upper()
        for tag in rule.tags
        if re.fullmatch(r"attack\.t\d{4}(\.\d{3})?", str(tag), re.IGNORECASE)
    ]
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
            result.append(
                {
                    "guid": item.get("auto_generated_guid"),
                    "name": item["name"],
                    "technique_id": technique,
                    "platforms": item.get("supported_platforms", []),
                    "dependencies": item.get("dependencies", []),
                    "input_arguments": item.get("input_arguments", {}),
                    "executor": executor.get("name"),
                    "has_cleanup": bool(executor.get("cleanup_command")),
                    "elevation_required": executor.get("elevation_required", False),
                    "approved": False,
                    "executable": False,
                }
            )
        return result
