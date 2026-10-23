import uuid
from datetime import UTC, datetime

from sqlalchemy import (
    ARRAY,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from aegis.db import Base


def now() -> datetime:
    return datetime.now(UTC)


def uid() -> str:
    return str(uuid.uuid4())


class Entity:
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class User(Entity, Base):
    __tablename__ = "users"
    __table_args__ = (
        CheckConstraint("role in ('administrator','operator','viewer')", name="role"),
    )
    username: Mapped[str] = mapped_column(String(80), unique=True)
    password_hash: Mapped[str] = mapped_column(Text)
    role: Mapped[str] = mapped_column(String(20))
    active: Mapped[bool] = mapped_column(Boolean, default=True)


class LoginSession(Base):
    __tablename__ = "sessions"
    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    csrf_hash: Mapped[str] = mapped_column(String(64))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)


class Laboratory(Entity, Base):
    __tablename__ = "laboratories"
    name: Mapped[str] = mapped_column(String(120), unique=True)
    description: Mapped[str] = mapped_column(Text)
    kind: Mapped[str] = mapped_column(String(20), default="demo")
    authorized: Mapped[bool] = mapped_column(Boolean, default=False)
    owner: Mapped[str] = mapped_column(String(120))
    environment_version: Mapped[int] = mapped_column(Integer, default=1)
    isolation: Mapped[str] = mapped_column(Text)
    active_run_id: Mapped[str | None] = mapped_column(String(36), nullable=True)


class Asset(Entity, Base):
    __tablename__ = "assets"
    laboratory_id: Mapped[str] = mapped_column(ForeignKey("laboratories.id"), index=True)
    name: Mapped[str] = mapped_column(String(120))
    platform: Mapped[str] = mapped_column(String(40))
    external_id: Mapped[str] = mapped_column(String(80), unique=True)
    synthetic: Mapped[bool] = mapped_column(Boolean, default=True)


class AttackTechnique(Base):
    __tablename__ = "attack_techniques"
    id: Mapped[str] = mapped_column(String(20), primary_key=True)
    name: Mapped[str] = mapped_column(String(240))
    description: Mapped[str] = mapped_column(Text)
    tactics: Mapped[list[str]] = mapped_column(ARRAY(String(80)))
    platforms: Mapped[list[str]] = mapped_column(ARRAY(String(80)))
    parent_id: Mapped[str | None] = mapped_column(String(20), nullable=True)
    reference: Mapped[str] = mapped_column(Text)
    dataset_version: Mapped[str] = mapped_column(String(40))
    stix_id: Mapped[str] = mapped_column(String(80), unique=True)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False, server_default=text("false"))
    deprecated: Mapped[bool] = mapped_column(Boolean, default=False, server_default=text("false"))
    present_in_current: Mapped[bool] = mapped_column(
        Boolean, default=True, server_default=text("true")
    )
    source_modified: Mapped[str | None] = mapped_column(String(40))


class AttackCatalogRelease(Base):
    __tablename__ = "attack_catalog_releases"
    __table_args__ = (
        CheckConstraint("provenance in ('bundled','official_commit')", name="catalog_provenance"),
        UniqueConstraint("dataset_version", "source_sha256", "license_sha256", "provenance"),
    )
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    dataset_version: Mapped[str] = mapped_column(String(40))
    provenance: Mapped[str] = mapped_column(String(24))
    source_url: Mapped[str] = mapped_column(Text)
    source_commit: Mapped[str | None] = mapped_column(String(40))
    source_sha256: Mapped[str] = mapped_column(String(64))
    license_sha256: Mapped[str] = mapped_column(String(64))
    # Versioned external document. Domain entities remain relational.
    document: Mapped[dict] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    applied_by: Mapped[str | None] = mapped_column(ForeignKey("users.id"))


class AttackCatalogState(Base):
    __tablename__ = "attack_catalog_state"
    __table_args__ = (CheckConstraint("id = 1", name="catalog_singleton"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1, autoincrement=False)
    release_id: Mapped[str] = mapped_column(ForeignKey("attack_catalog_releases.id"))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class TestDefinition(Base):
    __tablename__ = "test_definitions"
    __table_args__ = (
        CheckConstraint("execution_kind in ('demo','linux_marker')", name="test_execution_kind"),
    )
    id: Mapped[str] = mapped_column(String(60), primary_key=True)
    name: Mapped[str] = mapped_column(String(160))
    description: Mapped[str] = mapped_column(Text)
    technique_id: Mapped[str | None] = mapped_column(ForeignKey("attack_techniques.id"))
    behavior: Mapped[str] = mapped_column(String(80))
    version: Mapped[int] = mapped_column(Integer, default=1)
    platform: Mapped[str] = mapped_column(String(40), default="Synthetic")
    cleanup: Mapped[str] = mapped_column(Text)
    prerequisites: Mapped[str] = mapped_column(Text)
    risk: Mapped[str] = mapped_column(String(20), default="synthetic")
    approved: Mapped[bool] = mapped_column(Boolean, default=True)
    expected_rule: Mapped[str] = mapped_column(String(80))
    demo_outcome: Mapped[str] = mapped_column(String(40))
    execution_kind: Mapped[str] = mapped_column(String(20), default="demo")


class LinuxLabBinding(Base):
    __tablename__ = "linux_lab_bindings"
    laboratory_id: Mapped[str] = mapped_column(ForeignKey("laboratories.id"), primary_key=True)
    runner_id: Mapped[str] = mapped_column(String(36), unique=True)
    configuration_hash: Mapped[str] = mapped_column(String(64))
    reviewed_by: Mapped[str] = mapped_column(ForeignKey("users.id"))
    isolation_review: Mapped[str] = mapped_column(Text)


class LabVerification(Entity, Base):
    __tablename__ = "lab_verifications"
    laboratory_id: Mapped[str] = mapped_column(ForeignKey("laboratories.id"), index=True)
    checked_by: Mapped[str] = mapped_column(ForeignKey("users.id"))
    configuration_hash: Mapped[str] = mapped_column(String(64))
    environment_version: Mapped[int] = mapped_column(Integer)
    success: Mapped[bool] = mapped_column(Boolean)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    reason: Mapped[str] = mapped_column(Text)


class Campaign(Entity, Base):
    __tablename__ = "campaigns"
    name: Mapped[str] = mapped_column(String(160))
    objective: Mapped[str] = mapped_column(Text)
    laboratory_id: Mapped[str] = mapped_column(ForeignKey("laboratories.id"), index=True)
    created_by: Mapped[str] = mapped_column(ForeignKey("users.id"))


class CampaignTest(Base):
    __tablename__ = "campaign_tests"
    campaign_id: Mapped[str] = mapped_column(ForeignKey("campaigns.id"), primary_key=True)
    test_id: Mapped[str] = mapped_column(ForeignKey("test_definitions.id"), primary_key=True)


class CampaignRun(Entity, Base):
    __tablename__ = "campaign_runs"
    __table_args__ = (UniqueConstraint("requested_by", "idempotency_key"),)
    campaign_id: Mapped[str] = mapped_column(ForeignKey("campaigns.id"), index=True)
    laboratory_id: Mapped[str] = mapped_column(ForeignKey("laboratories.id"), index=True)
    requested_by: Mapped[str] = mapped_column(ForeignKey("users.id"))
    schedule_id: Mapped[str | None] = mapped_column(ForeignKey("schedules.id"), index=True)
    idempotency_key: Mapped[str] = mapped_column(String(80))
    state: Mapped[str] = mapped_column(String(30), default="CREATED", index=True)
    scope_hash: Mapped[str] = mapped_column(String(64))
    scope: Mapped[dict] = mapped_column(JSONB)
    synthetic: Mapped[bool] = mapped_column(Boolean, default=True)
    cancel_requested: Mapped[bool] = mapped_column(Boolean, default=False)
    processing_started: Mapped[bool] = mapped_column(Boolean, default=False)
    requested_outcome: Mapped[str | None] = mapped_column(String(30))
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    deadline_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error: Mapped[str | None] = mapped_column(Text)


class Approval(Entity, Base):
    __tablename__ = "approvals"
    run_id: Mapped[str] = mapped_column(ForeignKey("campaign_runs.id"), unique=True)
    approved_by: Mapped[str] = mapped_column(ForeignKey("users.id"))
    schedule_authorization_id: Mapped[str | None] = mapped_column(
        ForeignKey("schedule_authorizations.id"), index=True
    )
    scope_hash: Mapped[str] = mapped_column(String(64))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    max_duration_seconds: Mapped[int] = mapped_column(Integer)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    __table_args__ = (CheckConstraint("max_duration_seconds between 10 and 300", name="duration"),)


class TestExecution(Entity, Base):
    __tablename__ = "test_executions"
    run_id: Mapped[str] = mapped_column(ForeignKey("campaign_runs.id"), index=True)
    test_id: Mapped[str] = mapped_column(ForeignKey("test_definitions.id"))
    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id"))
    state: Mapped[str] = mapped_column(String(30), default="CREATED")
    marker: Mapped[str] = mapped_column(String(100), unique=True)
    synthetic: Mapped[bool] = mapped_column(Boolean, default=True)
    executed: Mapped[bool] = mapped_column(Boolean, default=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    __table_args__ = (UniqueConstraint("run_id", "test_id"),)


class RunnerDispatch(Entity, Base):
    __tablename__ = "runner_dispatches"
    execution_id: Mapped[str] = mapped_column(ForeignKey("test_executions.id"), unique=True)
    spec: Mapped[dict] = mapped_column(JSONB)
    spec_hash: Mapped[str] = mapped_column(String(64))
    generation: Mapped[str | None] = mapped_column(String(36))


class RunnerReceipt(Entity, Base):
    __tablename__ = "runner_receipts"
    execution_id: Mapped[str] = mapped_column(ForeignKey("test_executions.id"), unique=True)
    content: Mapped[dict] = mapped_column(JSONB)
    sha256: Mapped[str] = mapped_column(String(64))


class RunnerCleanup(Entity, Base):
    __tablename__ = "runner_cleanups"
    execution_id: Mapped[str] = mapped_column(ForeignKey("test_executions.id"), unique=True)
    content: Mapped[dict] = mapped_column(JSONB)
    sha256: Mapped[str] = mapped_column(String(64))


class ExecutionStep(Entity, Base):
    __tablename__ = "execution_steps"
    run_id: Mapped[str] = mapped_column(ForeignKey("campaign_runs.id"), index=True)
    execution_id: Mapped[str | None] = mapped_column(ForeignKey("test_executions.id"), index=True)
    state: Mapped[str] = mapped_column(String(30))
    message: Mapped[str] = mapped_column(Text)


class TelemetryEvent(Entity, Base):
    __tablename__ = "telemetry_events"
    execution_id: Mapped[str] = mapped_column(ForeignKey("test_executions.id"), index=True)
    source_id: Mapped[str] = mapped_column(String(180))
    source: Mapped[str] = mapped_column(String(80))
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    kind: Mapped[str] = mapped_column(String(20))
    rule_id: Mapped[str | None] = mapped_column(String(80))
    synthetic: Mapped[bool] = mapped_column(Boolean)
    raw: Mapped[dict] = mapped_column(JSONB)
    sha256: Mapped[str] = mapped_column(String(64))
    __table_args__ = (UniqueConstraint("execution_id", "source", "source_id"),)


class ValidationResult(Entity, Base):
    __tablename__ = "validation_results"
    execution_id: Mapped[str] = mapped_column(ForeignKey("test_executions.id"), unique=True)
    outcome: Mapped[str] = mapped_column(String(40), index=True)
    reason: Mapped[str] = mapped_column(Text)
    logic_version: Mapped[str] = mapped_column(String(60))
    synthetic: Mapped[bool] = mapped_column(Boolean)
    collection_complete: Mapped[bool] = mapped_column(Boolean)
    telemetry_available: Mapped[bool] = mapped_column(Boolean)
    alerts_available: Mapped[bool] = mapped_column(Boolean)


class DetectionEvidence(Entity, Base):
    __tablename__ = "detection_evidence"
    result_id: Mapped[str] = mapped_column(ForeignKey("validation_results.id"), index=True)
    event_id: Mapped[str] = mapped_column(ForeignKey("telemetry_events.id"))
    reason: Mapped[str] = mapped_column(Text)
    __table_args__ = (UniqueConstraint("result_id", "event_id"),)


class DetectionRule(Entity, Base):
    __tablename__ = "detection_rules"
    title: Mapped[str] = mapped_column(String(240))
    sigma_id: Mapped[str] = mapped_column(String(36), unique=True)
    latest_version: Mapped[int] = mapped_column(Integer, default=1)


class RuleVersion(Entity, Base):
    __tablename__ = "rule_versions"
    rule_id: Mapped[str] = mapped_column(ForeignKey("detection_rules.id"), index=True)
    version: Mapped[int] = mapped_column(Integer)
    content: Mapped[str] = mapped_column(Text)
    sha256: Mapped[str] = mapped_column(String(64))
    techniques: Mapped[list[str]] = mapped_column(ARRAY(String(20)))
    created_by: Mapped[str] = mapped_column(ForeignKey("users.id"))
    __table_args__ = (
        UniqueConstraint("rule_id", "version"),
        UniqueConstraint("id", "rule_id", name="uq_rule_versions_id_rule_id"),
    )


class RuleTestLink(Entity, Base):
    __tablename__ = "rule_test_links"
    __table_args__ = (
        ForeignKeyConstraint(
            ["rule_version_id", "rule_id"],
            ["rule_versions.id", "rule_versions.rule_id"],
            name="fk_rule_test_links_version_rule",
        ),
        Index(
            "uq_rule_test_links_active",
            "rule_id",
            "test_id",
            unique=True,
            postgresql_where=text("retired_at IS NULL"),
        ),
        CheckConstraint("test_version > 0", name="link_test_version"),
        CheckConstraint(
            "(retired_at IS NULL) = (retired_by IS NULL)",
            name="link_retirement",
        ),
    )
    rule_id: Mapped[str] = mapped_column(ForeignKey("detection_rules.id"), index=True)
    rule_version_id: Mapped[str] = mapped_column(String(36), index=True)
    test_id: Mapped[str] = mapped_column(ForeignKey("test_definitions.id"), index=True)
    test_version: Mapped[int] = mapped_column(Integer)
    rationale: Mapped[str] = mapped_column(Text)
    created_by: Mapped[str] = mapped_column(ForeignKey("users.id"))
    retired_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    retired_by: Mapped[str | None] = mapped_column(ForeignKey("users.id"))


class AuditEvent(Entity, Base):
    __tablename__ = "audit_events"
    actor_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), index=True)
    action: Mapped[str] = mapped_column(String(80), index=True)
    resource_id: Mapped[str] = mapped_column(String(100))
    details: Mapped[dict] = mapped_column(JSONB, default=dict)


class Schedule(Entity, Base):
    __tablename__ = "schedules"
    __table_args__ = (
        CheckConstraint("interval_seconds between 60 and 2592000", name="schedule_interval"),
        CheckConstraint("max_occurrences between 1 and 100", name="schedule_budget"),
        CheckConstraint("max_duration_seconds between 10 and 300", name="schedule_duration"),
        CheckConstraint("occurrences_count between 0 and max_occurrences", name="schedule_count"),
        CheckConstraint("ends_at > starts_at", name="schedule_window"),
        CheckConstraint(
            "state in ('PENDING_APPROVAL','ACTIVE','PAUSED','REVOKED','EXPIRED','EXHAUSTED','INVALIDATED')",
            name="schedule_state",
        ),
        Index("ix_schedule_due", "state", "next_due_at"),
    )
    campaign_id: Mapped[str] = mapped_column(ForeignKey("campaigns.id"), index=True)
    laboratory_id: Mapped[str] = mapped_column(ForeignKey("laboratories.id"))
    created_by: Mapped[str] = mapped_column(ForeignKey("users.id"))
    state: Mapped[str] = mapped_column(String(30), default="PENDING_APPROVAL")
    scope: Mapped[dict] = mapped_column(JSONB)
    scope_hash: Mapped[str] = mapped_column(String(64))
    plan_hash: Mapped[str] = mapped_column(String(64))
    interval_seconds: Mapped[int] = mapped_column(Integer)
    max_occurrences: Mapped[int] = mapped_column(Integer)
    max_duration_seconds: Mapped[int] = mapped_column(Integer)
    starts_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    ends_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    next_due_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    occurrences_count: Mapped[int] = mapped_column(Integer, default=0)
    reason: Mapped[str | None] = mapped_column(Text)


class ScheduleAuthorization(Entity, Base):
    __tablename__ = "schedule_authorizations"
    schedule_id: Mapped[str] = mapped_column(ForeignKey("schedules.id"), index=True)
    approved_by: Mapped[str] = mapped_column(ForeignKey("users.id"))
    plan_hash: Mapped[str] = mapped_column(String(64))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    __table_args__ = (
        Index(
            "uq_schedule_current_authorization",
            "schedule_id",
            unique=True,
            postgresql_where=revoked_at.is_(None),
        ),
    )


class ScheduleOccurrence(Entity, Base):
    __tablename__ = "schedule_occurrences"
    schedule_id: Mapped[str] = mapped_column(ForeignKey("schedules.id"), index=True)
    authorization_id: Mapped[str] = mapped_column(ForeignKey("schedule_authorizations.id"))
    scheduled_for: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    run_id: Mapped[str | None] = mapped_column(ForeignKey("campaign_runs.id"), unique=True)
    status: Mapped[str] = mapped_column(String(30))
    reason: Mapped[str] = mapped_column(Text)
    __table_args__ = (
        UniqueConstraint("schedule_id", "scheduled_for"),
        CheckConstraint(
            "status in ('QUEUED','SKIPPED_LATE','SKIPPED_BUSY')", name="occurrence_status"
        ),
        CheckConstraint("(status = 'QUEUED') = (run_id IS NOT NULL)", name="occurrence_run"),
    )


Index("ix_runs_state_created", CampaignRun.state, CampaignRun.created_at)


class WazuhBinding(Entity, Base):
    __tablename__ = "wazuh_bindings"
    laboratory_id: Mapped[str] = mapped_column(ForeignKey("laboratories.id"), unique=True)
    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id"), unique=True)
    agent_id: Mapped[str] = mapped_column(String(12), unique=True)
    expected_rule: Mapped[str] = mapped_column(String(16))
    configuration_hash: Mapped[str] = mapped_column(String(64))
    schema_id: Mapped[str] = mapped_column(String(40))
    reviewed_by: Mapped[str] = mapped_column(ForeignKey("users.id"))
    review: Mapped[str] = mapped_column(Text)


class TelemetryCollection(Entity, Base):
    __tablename__ = "telemetry_collections"
    __table_args__ = (CheckConstraint("attempts >= 0", name="collection_attempts"),)
    execution_id: Mapped[str] = mapped_column(ForeignKey("test_executions.id"), unique=True)
    provider: Mapped[str] = mapped_column(String(40))
    configuration_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    schema_id: Mapped[str] = mapped_column(String(40))
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    ended_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    attempts: Mapped[int] = mapped_column(Integer)
    complete: Mapped[bool] = mapped_column(Boolean)
    telemetry_available: Mapped[bool] = mapped_column(Boolean)
    alerts_available: Mapped[bool] = mapped_column(Boolean)
    window_satisfied: Mapped[bool] = mapped_column(Boolean)
    reason: Mapped[str] = mapped_column(Text)
