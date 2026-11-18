"""Closed native assay profiles; no commands, targets or external policy input."""

from aegis.lab_runner import atomic_policy, behavior_policy

NAMES = ("atomic80", "linux83-process", "linux83-shell")


def selected(plan: dict) -> dict:
    name = plan.get("profile", "atomic80")
    if name not in NAMES:
        raise ValueError("Unknown reviewed assay profile")
    if name == "atomic80":
        if "profile" in plan and plan.get("format") != "atomic80-one-attempt/1":
            raise ValueError("Dedicated Atomic80 proposal format required")
        return {
            "name": name,
            "issue": 80,
            "database": "atomic_assay",
            "owner": "atomic_owner",
            "prefix": "atomic80_",
            "project_prefix": "aegis-atomic80-",
            "format": "atomic80-one-attempt/1",
            "test_id": atomic_policy.TEST_ID,
            "definition_id": atomic_policy.DEFINITION_ID,
            "review": atomic_policy.review(),
            "review_key": "atomic_review",
            "status": "native_atomic_verified",
        }
    kind = name.removeprefix("linux83-")
    if plan.get("format") != "linux83-one-attempt/1":
        raise ValueError("Dedicated Linux83 proposal format required")
    return {
        "name": name,
        "issue": 83,
        "database": "linux83_assay",
        "owner": "linux83_owner",
        "prefix": "linux83_",
        "project_prefix": "aegis-linux83-",
        "format": "linux83-one-attempt/1",
        "test_id": behavior_policy.TEST_IDS[kind],
        "definition_id": behavior_policy.PROFILES[kind]["definition_id"],
        "review": behavior_policy.review(kind),
        "review_key": "behavior_review",
        "status": "native_linux83_verified",
    }
