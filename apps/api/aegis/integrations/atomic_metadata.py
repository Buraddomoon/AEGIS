"""Bounded metadata projection. Command/default fields are never retained."""

import re
from uuid import UUID

import yaml

from aegis.integrations.yaml_import import safe_document


class UniqueLoader(yaml.SafeLoader):
    pass


def mapping(loader, node):
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node)
        if not isinstance(key, str) or key in result:
            raise ValueError("Chave Atomic inválida ou duplicada.")
        result[key] = loader.construct_object(value_node)
    return result


UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, mapping)


def string(value, limit=4000, *, empty=True):
    if not isinstance(value, str) or len(value) > limit or (not empty and not value.strip()):
        raise ValueError("Texto Atomic inválido.")
    return value


def parse(content):
    safe_document(content)  # Size, event/depth budgets, tags, aliases before construction.
    document = yaml.load(content, Loader=UniqueLoader)
    technique = document.get("attack_technique")
    if not isinstance(technique, str) or not re.fullmatch(r"T\d{4}(\.\d{3})?", technique):
        raise ValueError("ID ATT&CK inválido.")
    tests = document.get("atomic_tests")
    if not isinstance(tests, list) or not 1 <= len(tests) <= 100:
        raise ValueError("Lista de testes Atomic inválida.")
    result, guids = [], set()
    for item in tests:
        if not isinstance(item, dict):
            raise ValueError("Teste Atomic inválido.")
        guid = string(item.get("auto_generated_guid"), 36, empty=False)
        if str(UUID(guid)) != guid or guid in guids:
            raise ValueError("GUID Atomic inválido ou duplicado.")
        guids.add(guid)
        platforms = item.get("supported_platforms")
        if (
            not isinstance(platforms, list)
            or not 1 <= len(platforms) <= 20
            or any(
                not isinstance(p, str) or not re.fullmatch(r"[a-zA-Z0-9_-]{1,40}", p)
                for p in platforms
            )
            or len(set(platforms)) != len(platforms)
        ):
            raise ValueError("Plataformas Atomic inválidas.")
        executor = item.get("executor")
        if (
            not isinstance(executor, dict)
            or type(executor.get("elevation_required", False)) is not bool
        ):
            raise ValueError("Executor Atomic inválido.")
        cleanup = executor.get("cleanup_command")
        if cleanup is None:
            cleanup = ""
        string(cleanup, 65536)
        inputs = item.get("input_arguments", {})
        deps = item.get("dependencies", [])
        if (
            not isinstance(inputs, dict)
            or len(inputs) > 100
            or not isinstance(deps, list)
            or len(deps) > 100
        ):
            raise ValueError("Requisitos Atomic inválidos.")
        projected_inputs = {}
        for key, value in inputs.items():
            string(key, 120, empty=False)
            if not isinstance(value, dict):
                raise ValueError("Input Atomic inválido.")
            projected_inputs[key] = {
                "type": string(value.get("type"), 40, empty=False),
                "description": string(value.get("description", "")),
                "has_default": "default" in value,
            }
        projected_deps = []
        for dep in deps:
            if not isinstance(dep, dict):
                raise ValueError("Dependência Atomic inválida.")
            projected_deps.append(
                {
                    "description": string(dep.get("description", "")),
                    "has_prereq": bool(string(dep.get("prereq_command", ""), 65536)),
                    "has_setup": bool(string(dep.get("get_prereq_command", ""), 65536)),
                }
            )
        result.append(
            {
                "guid": guid,
                "name": string(item.get("name"), 240, empty=False),
                "description": string(item.get("description", ""), 12000),
                "technique_id": technique,
                "platforms": platforms,
                "dependencies": projected_deps,
                "dependency_executor": string(item.get("dependency_executor_name", ""), 80),
                "input_arguments": projected_inputs,
                "executor": string(executor.get("name"), 80, empty=False),
                "has_cleanup": bool(cleanup.strip()),
                "elevation_required": executor.get("elevation_required", False),
                "approved": False,
                "executable": False,
            }
        )
    return result
