import copy
import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml
from aegis.domain.validation import digest
from aegis.integrations import sigma_mapping as mapping

CONTENT = Path("fixtures/sigma/aegis-marker-candidate.yml").read_text()
BASE = yaml.safe_load(CONTENT)


def document(change):
    data = copy.deepcopy(BASE)
    change(data)
    return yaml.safe_dump(data, sort_keys=False)


def test_real_official_pipeline_maps_and_preserves_values_condition_and_input():
    result = mapping.preview(CONTENT)
    assert result == mapping.preview(CONTENT)
    assert result["status"] == "previewed"
    assert result["before_detection"] == BASE["detection"]
    assert result["after_detection"] == {
        "selection": {
            "data.aegis.schema": "aegis-json/1",
            "data.aegis.observation": "marker_file_read",
        },
        "condition": "selection",
    }
    assert result["sha256"] == digest(CONTENT)
    unsigned = {key: value for key, value in result.items() if key != "document_sha256"}
    assert result["document_sha256"] == digest(unsigned)
    assert not any(
        result[key]
        for key in [
            "can_convert",
            "query_generated",
            "siem_queried",
            "deployment_performed",
            "index_mapping_verified",
        ]
    )
    assert "query" not in result
    assert result["pipeline"]["sha256"] == digest(mapping.definition())
    assert mapping.marker_profile()["status"] == "candidate_not_executable"


@pytest.mark.parametrize(
    "condition",
    ["selection and second", "selection or second", "selection and not second", "1 of sele*"],
)
def test_boolean_conditions_and_literal_or_lists_remain_unchanged(condition):
    data = copy.deepcopy(BASE)
    data["detection"]["selection"]["AegisSchema"] = ["aegis-json/1", "aegis-json/2"]
    data["detection"]["second"] = {"RuleId": "100200"}
    if condition == "1 of sele*":
        data["detection"].pop("second")
    data["detection"]["condition"] = condition
    result = mapping.preview(yaml.safe_dump(data))
    assert result["status"] == "previewed"
    assert result["after_detection"]["condition"] == condition
    assert result["after_detection"]["selection"]["data.aegis.schema"] == [
        "aegis-json/1",
        "aegis-json/2",
    ]
    if "second" in data["detection"]:
        assert result["after_detection"]["second"] == {"rule.id": "100200"}


@pytest.mark.parametrize(
    "problem",
    [
        "logsource",
        "custom",
        "pipeline",
        "vars",
        "unknown_metadata",
        "keyword",
        "nested",
        "unknown_field",
        "modifier",
        "fieldref",
        "number",
        "bool",
        "null",
        "wildcard",
        "backslash",
        "control",
        "empty_list",
        "long_list",
        "long_value",
        "condition_list",
        "long_condition",
        "many_selections",
        "bad_selection_name",
        "timeframe",
    ],
)
def test_unsupported_inputs_never_reach_parser_or_pipeline(monkeypatch, problem):
    data = copy.deepcopy(BASE)
    selection = data["detection"]["selection"]
    if problem == "logsource":
        data["logsource"]["product"] = "windows"
    elif problem in {"custom", "pipeline", "vars", "unknown_metadata"}:
        data[problem] = {"command": "NEVER_EXECUTE"}
    elif problem == "keyword":
        data["detection"]["selection"] = ["marker"]
    elif problem == "nested":
        selection["AegisSchema"] = {"other": "value"}
    elif problem == "unknown_field":
        selection["CommandLine"] = "marker"
    elif problem == "modifier":
        selection["AegisSchema|contains"] = "marker"
    elif problem == "fieldref":
        selection["AegisMarker|fieldref"] = "AegisSchema"
    elif problem == "number":
        selection["AegisArtifactBytes"] = 43
    elif problem == "bool":
        selection["AegisSchema"] = True
    elif problem == "null":
        selection["AegisSchema"] = None
    elif problem == "wildcard":
        selection["AegisSchema"] = "aegis*"
    elif problem == "backslash":
        selection["AegisSchema"] = "aegis\\value"
    elif problem == "control":
        selection["AegisSchema"] = "aegis\nvalue"
    elif problem == "empty_list":
        selection["AegisSchema"] = []
    elif problem == "long_list":
        selection["AegisSchema"] = ["x"] * 17
    elif problem == "long_value":
        selection["AegisSchema"] = "é" * 513
    elif problem == "condition_list":
        data["detection"]["condition"] = ["selection"]
    elif problem == "long_condition":
        data["detection"]["condition"] = "x" * 2049
    elif problem == "many_selections":
        data["detection"].update({f"sel{x}": {"RuleId": "1"} for x in range(32)})
    elif problem == "bad_selection_name":
        data["detection"]["bad-name"] = {"RuleId": "1"}
    elif problem == "timeframe":
        data["detection"]["timeframe"] = "5m"

    def forbidden(*args, **kwargs):
        raise AssertionError("Parser/pipeline must not run")

    monkeypatch.setattr(mapping, "analyze", forbidden)
    monkeypatch.setattr(mapping.SigmaCollection, "from_dicts", forbidden)
    monkeypatch.setattr(mapping.ProcessingPipeline, "apply", forbidden)
    result = mapping.preview(yaml.safe_dump(data))
    assert result["status"] == "unsupported" and result["blockers"]
    assert result["before_detection"] is result["after_detection"] is None


def test_invalid_condition_and_unused_selection_block_pipeline(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("Pipeline must not run")

    monkeypatch.setattr(mapping.ProcessingPipeline, "apply", forbidden)
    content = document(lambda d: d["detection"].update(condition="absent"))
    assert mapping.preview(content)["blockers"][0]["code"] == "static_review_required"
    content = document(lambda d: d["detection"].update(unused={"RuleId": "1"}))
    assert mapping.preview(content)["status"] == "unsupported"


def test_drift_in_core_or_transformation_is_not_presented_as_success(monkeypatch):
    with monkeypatch.context() as patch:
        patch.setattr(mapping, "version", lambda _: "2.0.2")
        with pytest.raises(mapping.MappingUnavailable):
            mapping.preview(CONTENT)
    monkeypatch.setattr(mapping.ProcessingPipeline, "apply", lambda self, rule: rule)
    with pytest.raises(mapping.MappingUnavailable):
        mapping.preview(CONTENT)


@pytest.mark.parametrize(
    "content",
    [CONTENT + "\nvars: &x [a, *x]\n", CONTENT + "#" * 65536, CONTENT.replace("title:", "other:")],
)
def test_invalid_yaml_budget_or_required_identity_fails(content):
    with pytest.raises((ValueError, yaml.YAMLError)):
        mapping.preview(content)


def test_pipeline_import_and_execution_cannot_use_cache_backend_or_effects():
    script = r"""
import sys,os,json
sys.dont_write_bytecode=True
content=sys.stdin.read()
def audit(event,args):
    if event=='import' and (str(args[0]).startswith('diskcache') or str(args[0]).startswith('sigma.backends')):
        raise AssertionError('Forbidden cache/backend import')
    if event.startswith(('socket.','subprocess.','os.system','os.posix_spawn')):
        raise AssertionError('Forbidden network/process')
    if event=='open' and (isinstance(args[1],str) and any(c in args[1] for c in 'wax+') or args[2] & (os.O_WRONLY|os.O_RDWR|os.O_CREAT|os.O_TRUNC|os.O_APPEND)):
        raise AssertionError('Forbidden file write')
sys.addaudithook(audit)
from aegis.integrations.sigma_mapping import preview
from sigma.processing.pipeline import ProcessingPipeline
def forbidden(*args,**kwargs): raise AssertionError('No pipeline deserialization')
ProcessingPipeline.from_dict=forbidden
ProcessingPipeline.from_yaml=forbidden
result=preview(content)
assert result['status']=='previewed'
assert not any(name.startswith(('diskcache','sigma.backends')) for name in sys.modules)
print(result['document_sha256'])
"""
    result = subprocess.run(
        [sys.executable, "-c", script],
        input=CONTENT,
        text=True,
        capture_output=True,
        timeout=15,
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1", "PYSIGMA_ALLOW_VARS_EXECUTION": "true"},
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == mapping.preview(CONTENT)["document_sha256"]
