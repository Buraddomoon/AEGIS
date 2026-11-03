"""Single client execution with durable fences and selected cleanup; no CLI/native authorization."""

import copy

import runner_activation_identity_client_driver as driver
import runner_activation_identity_client_gates as gates
import runner_activation_identity_client_inspection as inspection
import runner_activation_identity_client_runtime as runtime
import runner_activation_identity_inspection as parent
import runner_activation_owned_probe as owned
from aegis.domain.validation import digest
from runner_activation_metadata import IMAGES, ActivationError


def run_client(reviews, *, lifecycle=None, cleanup_docker=None):
    """Trusted coordinator only; no retry/resume even if the old role is ABSENT.

    Metadata and wire fixtures in tests do not demonstrate a native TLS assay.
    Completion means the review finished/cleanup passed, not all TLS controls
    were conclusive or PKI/normal operation was authorized.
    """
    if not isinstance(reviews, gates.IdentityClientGates):
        raise ActivationError("identity_client_computed_gates_required")
    c = reviews.confirmation
    original = c._guard()
    if runtime.ROLE in original["resources"]:
        raise ActivationError("identity_client_new_role_required_no_replay")
    spec = runtime.recipe(c.store, c.path, c.plan_sha256, reviews.context_sha256)
    images = {key: c.artifact["metadata"]["images"][key]["id"] for key in IMAGES}
    lifecycle = lifecycle or driver.IdentityClientDocker()
    records, physical = {}, {}

    def gate(phase):
        before = c._guard()
        approved = reviews.review(phase, copy.deepcopy(spec))
        gates.validate(
            approved, phase, spec, before, c.operation, c.artifact["pki"]["manifest_sha256"]
        )
        if c._guard() != before or digest(
            runtime.recipe(c.store, c.path, c.plan_sha256, reviews.context_sha256)
        ) != digest(spec):
            raise ActivationError("identity_client_lifecycle_gate_context_changed")
        records[phase] = {
            "gate": copy.deepcopy(approved),
            "review": copy.deepcopy(reviews._last_review),
        }
        return approved

    def inspect(phase, known):
        c._guard()
        result = inspection.review(
            c.store,
            c.path,
            c.plan_sha256,
            reviews.context_sha256,
            known,
            phase,
            docker=reviews.runtime_docker,
            ownership_docker=reviews.ownership_docker,
        )
        c._guard()
        physical[phase] = result
        return result

    def validate(raw):
        result = gates.request.probe.decode_result(raw, reviews.context, reviews.context_sha256)
        approved = gate("exited")
        if digest(physical["exited"]) != reviews.evidence[-1]["client_runtime_sha256"]:
            raise ActivationError("identity_client_exit_configuration_changed")
        owned.fresh(approved)
        c._guard()
        c.store.append(
            "identity_client_reply_observed",
            {
                "role": runtime.ROLE,
                "result_sha256": digest(result),
                "runtime_evidence_sha256": digest(physical["exited"]),
            },
        )
        c._guard()
        return result

    result = owned.run(
        c.store,
        images,
        runtime.ROLE,
        spec,
        reviews.context_sha256,
        review_image=lambda: parent.review_image(spec["image"], docker=reviews.runtime_docker),
        gate=gate,
        review_runtime=inspect,
        create=lambda: lifecycle.create(reviews),
        start=lambda known: lifecycle.start(reviews, known),
        validate_reply=validate,
        ownership_docker=reviews.ownership_docker,
        cleanup_docker=cleanup_docker,
    )
    result.update(
        {
            "plan_sha256": c.plan_sha256,
            "scope_sha256": c.scope,
            "request_context_sha256": reviews.context_sha256,
            "runner_resource_id": spec["runner_resource_id"],
            "network_resource_id": spec["network_resource_id"],
            "gate_records": records,
            "gate_evidence": copy.deepcopy(reviews.evidence),
            "tls_controls_status": result["result"]["status"]
            if result["result"] is not None
            else None,
            "marker_executed": False,
        }
    )
    if "exited" in records:
        result["gate_sha256"]["exited"] = digest(records["exited"]["gate"])
    return result
