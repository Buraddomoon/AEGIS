import sys

import pytest
import yaml
from aegis.domain.validation import digest
from aegis.integrations.sigma_analysis import analyze
from test_integrations import SIGMA


def test_analysis_is_deterministic_and_does_not_imply_detection():
    result = analyze(SIGMA)
    assert result == analyze(SIGMA)
    assert result["sha256"] == digest(SIGMA)
    assert result["analyzer_version"] == "sigma-static/1"
    assert result["pysigma_version"] == "2.0.1"
    assert result["status"] == "no_findings_in_selected_checks"
    assert result["facts"]["declared_fields"] == ["CommandLine"]
    assert result["facts"]["logsource"]["product"] == "linux"
    assert result["compatibility"] == {
        "status": "not_configured",
        "backend": None,
        "pipeline": None,
        "conversion_performed": False,
        "deployment_performed": False,
    }
    assert "diskcache" not in sys.modules


def test_unused_selection_and_wildcard_condition_resolution():
    content = SIGMA.replace(
        "  condition: selection", "  unused:\n    Image: /bin/sh\n  condition: selection"
    )
    result = analyze(content)
    assert result["findings"][0]["code"] == "unused_selection"
    assert result["findings"][0]["selection"] == "unused"
    assert not analyze(content.replace("condition: selection", "condition: 1 of them"))["findings"]


@pytest.mark.parametrize("condition", ["absent", "selection and (", "1 of missing_*"])
def test_unresolved_condition_does_not_report_clean(condition):
    result = analyze(SIGMA.replace("condition: selection", f"condition: {condition}"))
    assert result["status"] == "findings"
    assert {f["code"] for f in result["findings"]} & {"condition_resolution"}


def test_modifiers_and_values_are_checked_without_executing_regex():
    content = SIGMA.replace(
        "CommandLine|contains: aegis-marker", "CommandLine|all: [first, second]"
    )
    assert "all_without_contains" in {f["code"] for f in analyze(content)["findings"]}
    content = SIGMA.replace("aegis-marker", "aegis**marker")
    assert "consecutive_wildcards" in {f["code"] for f in analyze(content)["findings"]}
    content = SIGMA.replace("aegis-marker", '"aegis\\tmarker"')
    assert "control_character" in {f["code"] for f in analyze(content)["findings"]}


def test_nested_and_keyword_selections_are_facts_not_required_telemetry():
    content = SIGMA.replace(
        "  selection:\n    CommandLine|contains: aegis-marker",
        "  selection:\n    - Image: /bin/sh\n    - CommandLine|contains: aegis-marker\n  keywords: [marker, lab]",
    )
    facts = analyze(content)["facts"]
    assert facts["declared_fields"] == ["CommandLine", "Image"]
    assert facts["keyword_selections"] == ["keywords"]


@pytest.mark.parametrize(
    "content",
    [
        "a: &a 1\nb: *a",
        "!!python/object/apply:os.system [id]",
        "a: " + "x" * 65536,
        SIGMA.replace("condition: selection", "condition: " + "selection or " * 200 + "selection"),
    ],
)
def test_analysis_rejects_unsafe_or_over_budget_content(content):
    with pytest.raises((ValueError, yaml.YAMLError)):
        analyze(content)


def test_api_analysis_is_version_specific_and_read_only(admin):
    from aegis.db import session_factory
    from aegis.models import AuditEvent, RuleTestLink
    from sqlalchemy import func, select

    rule = admin.post("/api/v1/rules", json={"content": SIGMA}).json()
    old = admin.get(f"/api/v1/rules/{rule['id']}/versions").json()["items"][0]
    path = f"/api/v1/rules/{rule['id']}/versions/{old['id']}/analysis"
    baseline = admin.get(path).json()
    changed = SIGMA.replace(
        "  condition: selection", "  unused:\n    Image: /bin/sh\n  condition: selection"
    )
    admin.post("/api/v1/rules", json={"content": changed}).raise_for_status()
    versions = admin.get(f"/api/v1/rules/{rule['id']}/versions").json()["items"]
    with session_factory()() as db:
        count = db.scalar(select(func.count()).select_from(AuditEvent))
    result = admin.get(path)
    assert result.status_code == 200, result.text
    assert result.json() == baseline
    new_result = admin.get(
        f"/api/v1/rules/{rule['id']}/versions/{versions[0]['id']}/analysis"
    ).json()
    assert new_result["findings"][0]["code"] == "unused_selection"
    assert new_result["rule_version"] == 2 and new_result["sha256"] == versions[0]["sha256"]
    assert admin.get(f"/api/v1/rules/other/versions/{old['id']}/analysis").status_code == 404
    assert admin.get(f"/api/v1/rules/{rule['id']}/versions/absent/analysis").status_code == 404
    with session_factory()() as db:
        assert db.scalar(select(func.count()).select_from(AuditEvent)) == count
        assert db.scalar(select(func.count()).select_from(RuleTestLink)) == 0


def test_analysis_requires_session_and_allows_viewer_without_csrf(admin):
    rule = admin.post("/api/v1/rules", json={"content": SIGMA}).json()
    saved = admin.get(f"/api/v1/rules/{rule['id']}/versions").json()["items"][0]
    path = f"/api/v1/rules/{rule['id']}/versions/{saved['id']}/analysis"
    admin.post("/api/v1/auth/logout")
    assert admin.get(path).status_code == 401
    admin.post(
        "/api/v1/auth/login",
        json={"username": "viewer", "password": "Test-only-randomized-scope-23!"},
        headers={"x-aegis-request": "browser"},
    ).raise_for_status()
    admin.headers.pop("x-csrf-token", None)
    assert admin.get(path).status_code == 200
    assert admin.post("/api/v1/rules", json={"content": SIGMA}).status_code == 403


def test_analysis_fails_closed_on_corrupt_content_and_legacy_invalid_yaml(admin):
    from aegis.db import session_factory
    from aegis.models import RuleVersion

    rule = admin.post("/api/v1/rules", json={"content": SIGMA}).json()
    saved = admin.get(f"/api/v1/rules/{rule['id']}/versions").json()["items"][0]
    path = f"/api/v1/rules/{rule['id']}/versions/{saved['id']}/analysis"
    with session_factory()() as db:
        stored = db.get(RuleVersion, saved["id"])
        stored.content = "invalid: legacy"
        db.commit()
    assert admin.get(path).status_code == 409
    with session_factory()() as db:
        stored = db.get(RuleVersion, saved["id"])
        stored.sha256 = digest(stored.content)
        db.commit()
    response = admin.get(path)
    assert response.status_code == 422
    assert "Traceback" not in response.text and "legacy" not in response.text


def test_analysis_rate_limit(admin):
    from aegis.db import session_factory
    from aegis.models import User
    from aegis.security import redis_client, token_hash
    from sqlalchemy import select

    rule = admin.post("/api/v1/rules", json={"content": SIGMA}).json()
    saved = admin.get(f"/api/v1/rules/{rule['id']}/versions").json()["items"][0]
    with session_factory()() as db:
        user_id = db.scalar(select(User.id).where(User.username == "administrator"))
    key = "aegis:limit:" + token_hash("sigma-analysis:" + user_id)
    redis_client().set(key, 60, ex=60)
    response = admin.get(f"/api/v1/rules/{rule['id']}/versions/{saved['id']}/analysis")
    assert response.status_code == 429 and response.headers["retry-after"] == "60"


@pytest.mark.parametrize("kind", ["conditions", "selections"])
def test_analysis_limits_condition_and_selection_counts(kind):
    if kind == "conditions":
        content = SIGMA.replace("condition: selection", "condition:\n" + "    - selection\n" * 33)
    else:
        content = SIGMA.replace(
            "  condition: selection",
            "".join(f"  extra_{i}:\n    Image: /bin/sh\n" for i in range(128))
            + "  condition: selection",
        )
    with pytest.raises(ValueError, match="Análise limitada"):
        analyze(content)


@pytest.mark.parametrize("condition", ["not selection", "all of select*"])
def test_selection_references_handle_negation_and_matching_wildcards(condition):
    assert not analyze(SIGMA.replace("condition: selection", f"condition: {condition}"))["findings"]


def test_fresh_analysis_never_imports_cache_connects_or_writes_files():
    import subprocess

    probe = """import os, sys

def guard(event, args):
    if event == 'import' and args[0] == 'diskcache':
        raise AssertionError('DiskCache import prohibited')
    if event in {'socket.connect', 'socket.getaddrinfo', 'os.mkdir'}:
        raise AssertionError('Analysis attempted network or directory creation')
    if event == 'open' and args[2] & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC):
        raise AssertionError('Analysis attempted a file write')

sys.addaudithook(guard)
from aegis.integrations.sigma_analysis import analyze
content = sys.stdin.read()
assert analyze(content)['status'] == 'no_findings_in_selected_checks'
assert analyze(content.replace('condition: selection', 'condition: absent'))['status'] == 'findings'
from aegis.integrations.sigma_readiness import assess
assert not assess(content)['can_convert']
assert 'sigma.backends.opensearch' not in sys.modules
assert 'diskcache' not in sys.modules
"""
    result = subprocess.run(
        [sys.executable, "-B", "-c", probe], input=SIGMA, text=True, capture_output=True, timeout=15
    )
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize(
    "detection",
    [
        {"selection": {"CommandLine" + "|wide" * 80: "x"}, "condition": "selection"},
        {"selection": {"CommandLine" + "|base64" * 80: "x"}, "condition": "selection"},
        {"selection": {"CommandLine|windash": "x" * 3000}, "condition": "selection"},
        {
            "selection": {"Image|contains|all|wide|utf16le|utf16be|utf16|base64": "x"},
            "condition": "selection",
        },
        {"selection": [{"Image|windash": "x"} for _ in range(33)], "condition": "selection"},
        {"selection": [{"Image|windash": "x" * 500} for _ in range(6)], "condition": "selection"},
    ],
)
def test_import_and_analysis_reject_expansion_before_pysigma(detection, monkeypatch):
    from aegis.integrations.yaml_import import parse_sigma
    from sigma.collection import SigmaCollection

    document = yaml.safe_load(SIGMA)
    document["detection"] = detection
    content = yaml.safe_dump(document)

    def forbidden(*args, **kwargs):
        raise AssertionError("pySigma must not receive over-budget content")

    monkeypatch.setattr(SigmaCollection, "from_dicts", forbidden)
    for action in (parse_sigma, analyze):
        with pytest.raises(ValueError, match="Cadeia Sigma|Expansão Sigma"):
            action(content)


def test_regular_encoding_chain_remains_accepted():
    content = SIGMA.replace("CommandLine|contains:", "CommandLine|wide|base64offset|contains:")
    assert analyze(content)["status"] == "no_findings_in_selected_checks"


def test_yaml_depth_rejected_before_constructing_python_tree():
    from aegis.integrations.yaml_import import safe_document

    with pytest.raises(ValueError, match="profundidade"):
        safe_document("a: " + "[" * 40 + "1" + "]" * 40)


@pytest.mark.parametrize(
    "extra",
    [
        {
            "filter": {
                "rules": "any",
                "condition": "selection",
                "selection": {"Image" + "|wide" * 80: "x"},
            }
        },
        {"correlation": {"type": "event_count"}},
        {"action": "global"},
        {"detection": ["selection"]},
        {"detection": None},
    ],
)
def test_non_detection_documents_rejected_before_collection_dispatch(extra, monkeypatch):
    from aegis.integrations.yaml_import import parse_sigma
    from sigma.collection import SigmaCollection

    document = {**yaml.safe_load(SIGMA), **extra}

    def forbidden(*args, **kwargs):
        raise AssertionError("Non-detection document must not reach SigmaCollection")

    monkeypatch.setattr(SigmaCollection, "from_dicts", forbidden)
    for action in (parse_sigma, analyze):
        with pytest.raises(ValueError, match="regra individual"):
            action(yaml.safe_dump(document))
