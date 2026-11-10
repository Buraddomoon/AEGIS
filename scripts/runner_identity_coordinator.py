"""One identity-only bridge/server/client cycle; native invocation needs specific authorization."""

import subprocess
from dataclasses import dataclass

import runner_activation_cleanup as closure
import runner_activation_identity_client_lifecycle as client
import runner_activation_identity_lifecycle as server
import runner_activation_identity_request as request
import runner_activation_network_gates as network
import runner_identity_recorded_gates as recorded
from aegis.domain.validation import digest
from runner_activation_metadata import IMAGES, ActivationError
from runner_activation_owned_probe import IDENTITY_ASSAY_FAILURE_CODES as FAILURE_CODES
from runner_activation_owned_probe import IDENTITY_FAILURE_CODES
from runner_identity_artifacts import ROOT, IdentityArtifacts, inventory_failure_code
from runner_identity_budget import IdentityBudget, IdentityNativeAdapters


@dataclass(frozen=True)
class Adapters:
    """Trusted internal provider boundary; no command, target or saved gate inputs."""

    bridge_create: object = None
    bridge_runtime: object = None
    server: object = None
    server_runtime: object = None
    server_network: object = None
    client: object = None
    client_runtime: object = None
    client_network: object = None
    cleanup: object = None


ERRORS = (
    ValueError,
    OSError,
    TypeError,
    KeyError,
    AttributeError,
    RecursionError,
    subprocess.SubprocessError,
)


def execute(context, build_inputs, *, adapters=None, root=ROOT):
    """Requires a fresh specifically authorized scope and same NetworkGates lease.

    This internal function is not invoked by Make/test/API or any native CLI.
    It never starts a DB, worker, Wazuh, test marker or normal runner, never writes
    PKI/bindings, and never retries a role. Native reads/cleanup share begin+300s;
    normal effects stop at most begin+240s. Once the hard budget is exhausted,
    unresolved owned resources remain quarantined; there is no force deletion.
    """
    if not isinstance(context, network.NetworkGates):
        raise ActivationError("identity_assay_network_confirmation_required")
    c = context
    if c._guard()["resources"]:
        raise ActivationError("identity_assay_new_operation_required_no_replay")
    adapters = Adapters() if adapters is None else adapters
    if not isinstance(adapters, Adapters):
        raise ActivationError("identity_assay_trusted_adapters_required")
    budget = IdentityBudget(c)
    native = IdentityNativeAdapters(budget)
    # Native providers are bounded; explicit test providers stay at the trusted
    # integration boundary and are never deserialized from user/API input.
    if c.docker is None:
        c.docker = native.metadata
    if c.ownership_docker is None:
        c.ownership_docker = native.ownership
    if c.subnet_docker is None:
        c.subnet_docker = native.subnet
    if c.routes is None:
        c.routes = native.routes
    images = {key: c.artifact["metadata"]["images"][key]["id"] for key in IMAGES}
    with IdentityArtifacts(c, root=root) as records:
        stages, failed, interrupted, cleanup = {}, None, None, None
        failed_code, inventory_error = None, None
        phase, failure_phase = "network", None
        result = None

        def record(name, report, complete):
            nonlocal failed_code
            stages[name] = report
            records.write(name + "-lifecycle", report)
            if complete is not True:
                code = report.get("failure_code")
                if type(code) is str and code in IDENTITY_FAILURE_CODES:
                    failed_code = code
                raise ActivationError("identity_assay_stage_unconfirmed")
            c._guard()

        try:
            bridge = network.lifecycle.create_network(
                c.store,
                images,
                before_effect=lambda phase, spec: recorded.before_network_create(
                    c, records, phase, spec
                ),
                lifecycle=adapters.bridge_create or native.bridge_create,
                runtime_docker=adapters.bridge_runtime or native.network,
                ownership_docker=c.ownership_docker,
                cleanup_docker=adapters.cleanup or native.cleanup,
            )
            record("network", bridge, bridge["network_retained"])
            phase = "server"
            server_gates = recorded.RecordedServerGates(
                c,
                build_inputs,
                records,
                docker=c.docker,
                ownership_docker=c.ownership_docker,
                runtime_docker=adapters.server_runtime or native.physical,
                network_docker=adapters.server_network or native.network,
            )
            host = server.start_server(
                server_gates,
                lifecycle=adapters.server,
                cleanup_docker=adapters.cleanup or native.cleanup,
            )
            record("server", host, host["server_retained"])
            phase = "client_request"
            payload, expected = request.request(c)
            records.write(
                "client-request",
                {"request": request.probe.decode(payload, expected), "context_sha256": expected},
            )
            c._guard()
            phase = "client"
            client_gates = recorded.RecordedClientGates(
                c,
                build_inputs,
                payload,
                expected,
                records,
                docker=c.docker,
                ownership_docker=c.ownership_docker,
                runtime_docker=adapters.client_runtime or native.physical,
                network_docker=adapters.client_network or native.network,
            )
            probe = client.run_client(
                client_gates,
                lifecycle=adapters.client,
                cleanup_docker=adapters.cleanup or native.cleanup,
            )
            record(
                "client",
                probe,
                probe["probe_result_verified"] is True and probe["probe_removed"] is True,
            )
            result = probe["result"]
            c._guard()
        except ERRORS as error:
            failed, failure_phase = "identity_assay_execution_unconfirmed", phase
            code = error.args[0] if isinstance(error, ActivationError) and error.args else None
            failed_code = failed_code or (
                code if type(code) is str and code in FAILURE_CODES else failed
            )
        except BaseException as error:
            interrupted = error
            failed, failure_phase = "identity_assay_interrupted", phase
            failed_code = failed
        finally:
            # Expired normal admission never blocks owned cleanup. Native drivers
            # still refuse further RPC when the original hard300s budget expires.
            try:
                cleanup = closure.cleanup(
                    c.store,
                    images,
                    docker=adapters.cleanup or native.cleanup,
                    ownership_docker=c.ownership_docker,
                )
            except ERRORS:
                cleanup = None
            except BaseException as error:
                interrupted = interrupted or error
                failed = failed or "identity_assay_cleanup_interrupted"
            try:
                records.write(
                    "cleanup", cleanup or {"status": "identity_assay_cleanup_unconfirmed"}
                )
            except ERRORS:
                failed = failed or "identity_assay_cleanup_record_unconfirmed"

        closed = (
            cleanup is not None
            and cleanup["managed_resources_absence_verified"] is True
            and cleanup["operation_closed"] is True
        )
        try:
            inventory = records.inventory()
        except ERRORS as error:
            inventory = None
            inventory_error = inventory_failure_code(error)
            failed = failed or "identity_assay_artifact_inventory_unconfirmed"
        try:
            budget.remaining()
        except ActivationError:
            failed = failed or "identity_assay_hard_budget_exhausted"
        concluded = failed is None and result is not None and closed
        verified = concluded and result["status"] == "identity_tls_controls_verified"
        receipt = {
            "format": "aegis-identity-assay-receipt/2",
            "operation_id": c.operation,
            "begin_sha256": c.begin_sha256,
            "plan_sha256": c.plan_sha256,
            "scope_sha256": c.scope,
            "plan_use_sha256": records.plan_use_sha256,
            "status": "identity_assay_verified_and_closed"
            if verified
            else "identity_assay_inconclusive_and_closed"
            if concluded
            else "identity_assay_failed_and_closed"
            if closed
            else "identity_assay_cleanup_unconfirmed",
            "error": failed,
            "failure_phase": failure_phase,
            "failure_code": failed_code,
            "artifact_inventory_failure_code": inventory_error,
            "stages": {key: digest(value) for key, value in stages.items()},
            "artifacts": inventory,
            "artifact_inventory_verified": inventory is not None,
            "intent_summary_sha256": digest(c.store.summary()),
            "cleanup": cleanup,
            "tls_controls_status": result["status"] if result is not None else None,
            "tls_controls_verified": verified,
            "managed_resources_absence_verified": closed,
            "effect_expires_at": c.expires.isoformat(),
            "cleanup_expires_at": budget.expires.isoformat(),
            "marker_executed": False,
            "worker_started": False,
            "database_started": False,
            "journal_opened": False,
            "wazuh_started": False,
            "pki_activated": False,
            "binding_changed": False,
            "old_client_rejection_verified": False,
            "volumes_removed": False,
            "normal_operation_permitted": False,
        }
        try:
            records.write("receipt", receipt)
        except ERRORS:
            raise ActivationError("identity_assay_receipt_publication_unconfirmed") from None
        if interrupted is not None:
            raise interrupted
        return receipt
