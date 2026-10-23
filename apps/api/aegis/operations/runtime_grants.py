"""Reviewed runtime privileges shared by deployment and isolated recovery.

Pure SQL definitions; granting remains a host/deployment administrator action.
No owner credentials are passed to normal API or worker containers.
"""

RUNTIME_PERMISSIONS = (
    "GRANT USAGE ON SCHEMA public TO aegis_app",
    "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO aegis_app",
    "REVOKE ALL ON alembic_version FROM aegis_app",
    "REVOKE UPDATE, DELETE ON audit_events, telemetry_events, detection_evidence, validation_results, rule_versions, schedule_occurrences, lab_verifications, runner_receipts, runner_cleanups, telemetry_collections FROM aegis_app",
    "REVOKE UPDATE, DELETE ON schedules, schedule_authorizations, runner_dispatches FROM aegis_app",
    "GRANT UPDATE (state, reason, next_due_at, occurrences_count) ON schedules TO aegis_app",
    "REVOKE UPDATE, DELETE ON rule_test_links FROM aegis_app",
    "GRANT UPDATE (retired_at, retired_by) ON rule_test_links TO aegis_app",
    "GRANT UPDATE (generation) ON runner_dispatches TO aegis_app",
    "GRANT UPDATE (revoked_at) ON schedule_authorizations TO aegis_app",
)
