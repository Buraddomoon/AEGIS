"""Fixed /state journal probe; future invocation requires a reviewed read-only mount."""

import argparse
import json
import sys
from pathlib import Path

from aegis.lab_runner.continuity import ContinuityError, review
from aegis.lab_runner.persisted_review import expected_proofs

STATE_DIRECTORY = Path("/state")
MAX_INPUT = 4 * 1024 * 1024
FLAGS = {
    "activation_permitted": False,
    "normal_operation_permitted": False,
    "database_volume_binding_verified": False,
    "journal_volume_binding_verified": False,
    "runner_started": False,
    "marker_executed": False,
}


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ContinuityError("proof_bundle_duplicate_field")
        result[key] = value
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-sha256", required=True)
    args = parser.parse_args(argv)
    try:
        payload = sys.stdin.buffer.read(MAX_INPUT + 1)
        if len(payload) > MAX_INPUT:
            raise ContinuityError("proof_bundle_input_limit")
        bundle = json.loads(payload, object_pairs_hook=_unique)
        identity, proofs = expected_proofs(bundle, args.expected_sha256)
        snapshot = review(STATE_DIRECTORY, identity, proofs)
        result = {
            "format": "aegis-runner-journal-probe/1",
            "status": "journal_snapshot_consistent_not_activated",
            "proof_bundle_sha256": args.expected_sha256,
            "old_descriptor_sha256": bundle["old_descriptor_sha256"],
            "snapshot": snapshot,
            **FLAGS,
        }
        print(json.dumps(result, sort_keys=True))
        return 0
    except ContinuityError as error:
        code = str(error)
    except (OSError, ValueError, TypeError, KeyError, AttributeError, RecursionError):
        code = "journal_probe_rejected"
    print(json.dumps({"status": "rejected", "code": code, **FLAGS}, sort_keys=True))
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
