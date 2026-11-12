"""Read-only preflight of both ADR0034 Wazuh networks. Never creates/reuses a network."""

import json
import subprocess

import runner_activation_subnet_review as subnet
from aegis.lab_runner.wazuh_network_profile import EXECUTION_SUBNET, TELEMETRY_SUBNET


def review(*, docker=None, routes=None):
    # Reuse the bounded local Unix metadata reader, route reader, double-snapshot
    # checks and strict parsers. Never exclude a collision based on ownership labels.
    result = subnet._review((EXECUTION_SUBNET, TELEMETRY_SUBNET), docker=docker, routes=routes)
    result.pop("subnet")
    return {
        **result,
        "format": "aegis-wazuh-network-preflight/1",
        "subnets": [EXECUTION_SUBNET, TELEMETRY_SUBNET],
    }


def main() -> int:
    try:
        print(json.dumps(review(), sort_keys=True, indent=2))
        return 0
    except (OSError, ValueError, subprocess.SubprocessError):
        print(
            json.dumps(
                {
                    "status": "blocked",
                    "error": "Preflight Wazuh recusado: colisão, drift ou metadados indisponíveis. Nenhuma rede alterada.",
                }
            )
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
