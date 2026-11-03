"""Opt-in identity-only assay entry point; specific human authorization is mandatory."""

import argparse
import json
from datetime import timedelta

import runner_activation as plan
import runner_activation_identity_image as image
import runner_identity_coordinator as coordinator
from aegis.domain.validation import digest
from runner_activation_intents import DEFAULT_ROOT, ActivationIntents, _hash, _identifier
from runner_activation_metadata import ActivationError


def run(
    path, plan_sha256, authorized_scope_sha256, build_inputs, *, confirm_identity_only_assay=False
):
    """A local scope assertion is not a signed or independently obtained approval.

    Never invoke because development was merely resumed. A human must approve
    the concrete identity-only scope first; all earlier Lab approvals are spent.
    No retries, normal runner, DB, journal, worker, Wazuh or binding changes.
    """
    if confirm_identity_only_assay is not True:
        raise ActivationError("identity_assay_explicit_confirmation_required")
    _hash(authorized_scope_sha256)
    artifact = plan.load_plan(path, plan_sha256)
    if authorized_scope_sha256 != artifact["scope_sha256"]:
        raise ActivationError("identity_assay_authorized_scope_mismatch")
    fence = path.parent / "identity-assay-requested.json"
    if fence.exists() or fence.is_symlink():
        raise ActivationError("identity_assay_plan_already_consumed")
    with ActivationIntents(DEFAULT_ROOT) as store:
        if fence.exists() or fence.is_symlink() or store.has_plan_history(plan_sha256):
            raise ActivationError("identity_assay_plan_already_consumed")
        # Read-only preflight precedes the operational300s window. No image pull,
        # build, key generation, original credentials or native startup here.
        plan.recheck(path, plan_sha256)
        image.review(
            build_inputs,
            artifact["metadata"]["images"]["runner"]["id"],
            artifact["tool_commit"],
            repo=plan.ROOT,
        )
        store.begin(artifact["id"], plan_sha256, artifact["scope_sha256"])
        try:
            context = coordinator.network.NetworkGates(
                path,
                plan_sha256,
                store,
                authorized_scope_sha256,
                (plan.pki.clock() + timedelta(seconds=230)).isoformat(),
            )
            return coordinator.execute(context, build_inputs)
        except BaseException:
            if not store.poisoned:
                state = store.review()
                if not state["resources"] and not state["closed"]:
                    # Closing an empty intent cannot invoke a native driver.
                    images = {key: artifact["metadata"]["images"][key]["id"] for key in plan.IMAGES}
                    coordinator.closure.cleanup(store, images)
            raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan-id", required=True)
    parser.add_argument("--expected-sha256", required=True)
    parser.add_argument("--authorized-scope-sha256", required=True)
    parser.add_argument("--build-id", required=True)
    parser.add_argument("--build-plan-sha256", required=True)
    parser.add_argument("--build-receipt-sha256", required=True)
    parser.add_argument("--confirm-identity-only-assay", required=True, action="store_true")
    args = parser.parse_args(argv)
    try:
        path = plan.ROOT / ".local/pki-activation-plans" / _identifier(args.plan_id) / "plan.json"
        result = run(
            path,
            args.expected_sha256,
            args.authorized_scope_sha256,
            {
                "build_id": args.build_id,
                "build_plan_sha256": args.build_plan_sha256,
                "build_receipt_sha256": args.build_receipt_sha256,
            },
            confirm_identity_only_assay=args.confirm_identity_only_assay,
        )
    except coordinator.ERRORS:
        print(
            json.dumps(
                {
                    "status": "rejected",
                    "error": "identity_assay_unconfirmed",
                    "normal_operation_permitted": False,
                }
            )
        )
        return 1
    print(json.dumps({"receipt": result, "receipt_body_sha256": digest(result)}, sort_keys=True))
    return 0 if result["status"] == "identity_assay_verified_and_closed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
