"""Descriptive cohorts from historical facts; never calls an executor or connector."""

from collections import Counter

from aegis.domain.validation import digest

VALID = {"DETECTED", "OBSERVED_NOT_ALERTED", "NO_TELEMETRY"}
IDENTITIES = {"campaign_id", "laboratory_id", "asset_id"}
REQUIRED = {
    "environment_version",
    "mode",
    "synthetic",
    "logic_version",
    "attack_catalog",
    "attack_techniques",
    "clock_skew_seconds",
    "ingestion_window_seconds",
    "test_definitions",
    "rule_versions",
    "rule_test_links",
}
LIMITATION = (
    "Equivalência limitada aos fatos e configurações registrados, sem atestar igualdade física "
    "dos laboratórios. Diferença de taxa não demonstra melhoria causal ou proteção geral. "
    "Recibo do executor não é telemetria defensiva."
)
DENOMINATOR = (
    "DETECTED + OBSERVED_NOT_ALERTED + NO_TELEMETRY, somente pais e filhos COMPLETED "
    "com origem coerente por lado. Inconclusivos, falhas e pendências excluídos."
)


def context(scope):
    # Ignore only object identities. All other recorded fields, including future
    # fields, participate; local environment version numbers are not attestations.
    return {k: v for k, v in scope.items() if k not in IDENTITIES}


def cohort(runs, synthetic):
    reasons, groups, members = set(), {}, []
    outcomes, eligible, states, manifest = Counter(), Counter(), Counter(), Counter()
    for run in runs:
        scope = run["scope"]
        executions = run["executions"]
        definitions = scope.get("test_definitions", [])
        ids = [t.get("id") for t in definitions]
        actual = [e["test_id"] for e in executions]
        states[run["state"]] += 1
        if digest(scope) != run["scope_hash"]:
            reasons.add("scope_integrity_mismatch")
        if not REQUIRED.issubset(scope) or any(scope.get(k) is None for k in REQUIRED):
            reasons.add("unknown_context")
        catalog = scope.get("attack_catalog") or {}
        if not catalog.get("release_id") or not catalog.get("version"):
            reasons.add("unknown_catalog_context")
        if not definitions or any(not t.get("id") or not t.get("version") for t in definitions):
            reasons.add("unknown_test_context")
        if not synthetic and (not scope.get("runner") or not scope.get("telemetry")):
            reasons.add("unknown_defensive_source_or_runner")
        if run["state"] != "COMPLETED":
            reasons.add("incomplete_runs")
        if Counter(ids) != Counter(actual) or len(set(ids)) != len(ids):
            reasons.add("execution_manifest_mismatch")
        if (
            run["synthetic"] != synthetic
            or scope.get("synthetic") != synthetic
            or scope.get("mode") != ("demo" if synthetic else "linux")
            or scope.get("laboratory_id") != run["laboratory_id"]
        ):
            reasons.add("origin_mismatch")
        key = digest(context(scope))
        group = groups.setdefault(
            key, {"context_sha256": key, "context": context(scope), "run_ids": []}
        )
        group["run_ids"].append(run["id"])
        for e in executions:
            result = e.get("result")
            outcome = result["outcome"] if result else "NOT_TESTED"
            outcomes[outcome] += 1
            if e["state"] != "COMPLETED":
                reasons.add("incomplete_test_executions")
            if not result:
                reasons.add("missing_validation_results")
            origin = (
                e["synthetic"] == synthetic
                and e["asset_id"] == scope.get("asset_id")
                and (not result or result["synthetic"] == synthetic)
                and all(event["synthetic"] == synthetic for event in e.get("events", []))
            )
            if not origin:
                reasons.add("origin_mismatch")
            if result and result["logic_version"] != scope.get("logic_version"):
                reasons.add("validation_logic_mismatch")
            if outcome not in VALID or (result and not result["collection_complete"]):
                reasons.add("partial_or_excluded_results")
            if run["state"] == e["state"] == "COMPLETED" and origin and outcome in VALID:
                eligible[outcome] += 1
                manifest[e["test_id"]] += 1
        members.append(run)
    if len(groups) > 1:
        reasons.add("heterogeneous_contexts")
    valid = sum(eligible.values())
    if not valid:
        reasons.add("empty_denominator")
    # Never publish a rate over a cohort with contradictory synthetic identities.
    if "origin_mismatch" in reasons:
        eligible.clear()
        valid = 0
    return {
        "synthetic": synthetic,
        "total_runs": len(runs),
        "run_states": dict(states),
        "outcomes": dict(outcomes),
        "valid_tests": valid,
        "detected_tests": eligible["DETECTED"],
        "excluded_tests": sum(outcomes.values()) - valid,
        "detected_percentage": round(100 * eligible["DETECTED"] / valid, 1) if valid else None,
        "denominator": DENOMINATOR,
        "eligible_test_manifest": dict(sorted(manifest.items())),
        "reasons": sorted(reasons),
        "cohorts": [groups[k] for k in sorted(groups)],
        "members": members,
    }


def compare_cohorts(before, after):
    reasons = {
        f"{side}:{r}" for side, c in (("before", before), ("after", after)) for r in c["reasons"]
    }
    if before["synthetic"] != after["synthetic"]:
        reasons.add("different_modes")
    if [c["context_sha256"] for c in before["cohorts"]] != [
        c["context_sha256"] for c in after["cohorts"]
    ]:
        reasons.add("different_recorded_contexts")
    if before["eligible_test_manifest"] != after["eligible_test_manifest"]:
        reasons.add("different_test_frequencies")
    comparable = not reasons
    unavailable = (
        before["synthetic"] != after["synthetic"]
        or not before["valid_tests"]
        or not after["valid_tests"]
        or any("origin_mismatch" in r or "integrity_mismatch" in r for r in reasons)
    )
    return {
        "classification": "incomparable"
        if unavailable
        else "equivalent"
        if comparable
        else "descriptive",
        "comparable": comparable,
        "reasons": sorted(reasons),
        "detected_rate_delta_percentage_points": round(
            100
            * (
                after["detected_tests"] / after["valid_tests"]
                - before["detected_tests"] / before["valid_tests"]
            ),
            1,
        )
        if comparable
        else None,
        "limitation": LIMITATION,
    }
