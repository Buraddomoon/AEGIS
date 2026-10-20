import uuid
from datetime import UTC, datetime

from sqlalchemy import (
    ARRAY,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
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


class TestDefinition(Base):
    __tablename__ = "test_definitions"
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
    __table_args__ = (UniqueConstraint("rule_id", "version"),)


class AuditEvent(Entity, Base):
    __tablename__ = "audit_events"
    actor_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), index=True)
    action: Mapped[str] = mapped_column(String(80), index=True)
    resource_id: Mapped[str] = mapped_column(String(100))
    details: Mapped[dict] = mapped_column(JSONB, default=dict)


Index("ix_runs_state_created", CampaignRun.state, CampaignRun.created_at)
