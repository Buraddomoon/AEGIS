import copy
import hashlib
import json
import subprocess
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

import pytest
from aegis.integrations import sigma_converter_worker as worker

ROOT = Path(__file__).resolve().parents[1]
PYTHON = ROOT / ".venv-sigma-converter/bin/python"
SCRIPT = Path(worker.__file__).resolve()
DOCUMENT = {
    "title": "Bounded marker query",
    "id": "9c0b95e4-3ac1-473b-b9b6-3967ef15f2f8",
    "logsource": dict(worker.LOGSOURCE),
    "detection": {"selection": {"AegisSchema": "aegis-json/1"}, "condition": "selection"},
}


def invoke(document):
    return subprocess.run(
        [str(PYTHON), "-I", "-B", str(SCRIPT)],
        input=json.dumps(document),
        text=True,
        capture_output=True,
        timeout=5,
        env={"PYSIGMA_ALLOW_VARS_EXECUTION": "true", "PYTHONPATH": "/not/a/plugin/path"},
    )


def test_compatible_official_worker_keeps_the_application_parser_and_packages_separate():
    assert (
        hashlib.sha256((ROOT / "requirements-sigma-converter.lock").read_bytes()).hexdigest()
        == worker.LOCK_SHA256
    )
    result = invoke(DOCUMENT)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {
        "query": r"data.aegis.schema:aegis\-json\/1",
        "definition_sha256": worker.sha(worker.definition()),
    }
    assert version("pysigma") == "2.0.1"
    with pytest.raises(PackageNotFoundError):
        version("pysigma-backend-opensearch")


@pytest.mark.parametrize(
    "condition,expected",
    [
        ("selection and second", "data.aegis.schema:one AND rule.id:100200"),
        ("selection or second", "data.aegis.schema:one OR rule.id:100200"),
        ("selection and not second", "data.aegis.schema:one AND (NOT rule.id:100200)"),
        (
            "(selection or second) and not third",
            "(data.aegis.schema:one OR rule.id:100200) AND (NOT agent.id:001)",
        ),
    ],
)
def test_official_boolean_golden_queries(condition, expected):
    document = copy.deepcopy(DOCUMENT)
    document["detection"] = {
        "selection": {"AegisSchema": "one"},
        "second": {"RuleId": "100200"},
        "condition": condition,
    }
    if "third" in condition:
        document["detection"]["third"] = {"AgentId": "001"}
    result = invoke(document)
    assert result.returncode == 0
    assert json.loads(result.stdout)["query"] == expected


@pytest.mark.parametrize(
    "selection",
    [
        {"AegisSchema|fieldref": "RuleId"},
        {"AegisSchema|contains": "one"},
        {"AegisArtifactBytes": "43"},
        {"Unknown": "one"},
        {"AegisSchema": "one*"},
        {"AegisSchema": "one\\two"},
        {"AegisSchema": "one\ntwo"},
        {"AegisSchema": None},
        {"AegisSchema": 43},
        {"AegisSchema": ["one"] * 9},
        {"AegisSchema": "x" * 513},
        ["keyword"],
    ],
)
def test_negative_semantics_are_rejected_before_parser_import(selection):
    document = copy.deepcopy(DOCUMENT)
    document["detection"]["selection"] = selection
    assert worker.blocker(document)
    result = invoke(document)
    assert result.returncode == 1 and not result.stdout and not result.stderr


@pytest.mark.parametrize(
    "condition",
    [
        "absent",
        "selection and",
        "1 of sele*",
        "(" * 9 + "selection" + ")" * 9,
        ["selection"],
        "x" * 257,
    ],
)
def test_unsupported_or_invalid_conditions_never_produce_a_query(condition):
    document = copy.deepcopy(DOCUMENT)
    document["detection"]["condition"] = condition
    result = invoke(document)
    assert result.returncode == 1 and not result.stdout and not result.stderr


def test_cache_network_process_and_write_guards_are_enforced():
    for event, args in [
        ("import", ("diskcache",)),
        ("import", ("sigma.plugins",)),
        ("import", ("sigma.processing.resolver",)),
        ("socket.connect", ()),
        ("subprocess.Popen", ()),
        ("os.system", ()),
        ("open", ("ignored", "w", 0)),
    ]:
        with pytest.raises(RuntimeError):
            worker.audit(event, args)


def test_runtime_audit_hook_blocks_actual_effects_in_fresh_process():
    code = f"""
import runpy,sys,socket,subprocess,tempfile,os
module=runpy.run_path({str(SCRIPT)!r})
sys.addaudithook(module['audit'])
for operation in [lambda: __import__('diskcache'), lambda: socket.socket(), lambda: subprocess.run(['true']), lambda: open('/tmp/aegis-forbidden-sigma-write','w')]:
    try: operation()
    except RuntimeError: pass
    else: raise AssertionError('Effect allowed')
print('blocked')
"""
    result = subprocess.run(
        [str(PYTHON), "-I", "-B", "-c", code], capture_output=True, text=True, timeout=5
    )
    assert result.returncode == 0 and result.stdout == "blocked\n", result.stderr
