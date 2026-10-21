"""Manual opt-in controller. Marker command requires a specific confirmation flag."""

import argparse
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

from aegis.domain.contracts import Collection, ExecutionContext
from aegis.domain.validation import LOGIC_VERSION, digest, validate
from aegis.integrations.linux_runner import LinuxMarkerAdapter, LinuxRunnerClient, RunnerConnection
from aegis.lab_runner.protocol import TEST_ID, JobView


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "action", choices=["preflight", "marker", "inspect", "cleanup", "retry-check"]
    )
    parser.add_argument("--confirm-marker-test", action="store_true")
    parser.add_argument("--job-id", type=UUID)
    arguments = parser.parse_args()
    if arguments.action == "marker" and not arguments.confirm_marker_test:
        parser.error(
            "Execução exige --confirm-marker-test e autorização específica do laboratório."
        )
    if arguments.action in ("inspect", "cleanup", "retry-check") and not arguments.job_id:
        parser.error("Informe o UUID do job já registrado.")
    config = RunnerConnection.model_validate_json(
        Path("/run/secrets/controller_connection").read_text()
    )
    client = LinuxRunnerClient(config)
    try:
        identity = client.preflight()
        if arguments.action == "preflight":
            print(identity.model_dump_json(indent=2))
            return
        if arguments.action in ("inspect", "cleanup", "retry-check"):
            view = JobView.model_validate(client.request("GET", f"/v1/jobs/{arguments.job_id}"))
            client.check(view.model_dump(mode="json"), view.spec)
            if arguments.action == "retry-check":
                if view.state != "SUCCEEDED" or view.cleanup_state != "CLEANED":
                    raise RuntimeError("Retry-check exige efeito já concluído e limpo.")
                original = view
                view = client.action(view, "start")
                if view != original:
                    raise RuntimeError("Retry alterou resultado histórico; não repetir operação.")
            if arguments.action == "cleanup":
                if view.state == "RUNNING":
                    raise RuntimeError(
                        "Job ainda ativo; aguarde lease/prazo antes de recuperar cleanup."
                    )
                view = client.action(view, "cleanup")
            print(view.model_dump_json(indent=2))
            return
        instant, execution_id = datetime.now(UTC), uuid4()
        deadline = instant + timedelta(seconds=20)
        context = ExecutionContext(
            str(execution_id),
            str(identity.laboratory_id),
            str(identity.asset_id),
            "aegis-" + str(uuid4()),
            "temporary-marker",
            instant,
            instant,
            False,
            "",
        )
        scope_hash = digest(
            {
                "test_id": TEST_ID,
                "identity": identity.model_dump(mode="json"),
                "execution_id": str(execution_id),
                "deadline": deadline.isoformat(),
            }
        )

        def guard():
            if datetime.now(UTC) >= deadline:
                raise TimeoutError("Prazo do ensaio manual expirou.")

        adapter = LinuxMarkerAdapter(client, deadline, scope_hash, guard)
        # Printed before preparation so unknown outcomes can be inspected by UUID, never replayed.
        print(
            json.dumps({"requested_job_id": str(execution_id), "scope_hash": scope_hash}),
            flush=True,
        )
        try:
            adapter.prepare(context)
            executed = adapter.execute(context)
        finally:
            adapter.cleanup(context)
        view = adapter.jobs[context.execution_id]
        verdict = validate(
            context, Collection((), False, False, False, "SIEM não consultado."), executed
        )
        print(
            json.dumps(
                {
                    "stage": "standalone-linux-runner",
                    "synthetic": False,
                    "platform_campaign_registered": False,
                    "job": view.model_dump(mode="json"),
                    "validation": {
                        "outcome": verdict.outcome,
                        "reason": verdict.reason,
                        "logic_version": LOGIC_VERSION,
                    },
                    "limitation": "Comprovante local do executor; não demonstra observação/detecção por SIEM.",
                },
                ensure_ascii=False,
            )
        )
        if not executed or view.cleanup_state != "CLEANED":
            raise RuntimeError("Ensaio não confirmou execução e cleanup.")
    finally:
        client.close()


if __name__ == "__main__":
    main()
