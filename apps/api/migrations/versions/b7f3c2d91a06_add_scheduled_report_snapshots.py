"""Transactional requests and immutable automatic Demo report snapshots."""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "b7f3c2d91a06"
down_revision = "a0d9c7e21b45"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "scheduled_reports",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("schedule_id", sa.String(36), sa.ForeignKey("schedules.id"), nullable=False),
        sa.Column(
            "authorization_id",
            sa.String(36),
            sa.ForeignKey("schedule_authorizations.id"),
            nullable=False,
        ),
        sa.Column(
            "occurrence_id",
            sa.String(36),
            sa.ForeignKey("schedule_occurrences.id"),
            nullable=False,
            unique=True,
        ),
        sa.Column(
            "run_id", sa.String(36), sa.ForeignKey("campaign_runs.id"), nullable=False, unique=True
        ),
        sa.Column("previous_run_id", sa.String(36), sa.ForeignKey("campaign_runs.id")),
        sa.Column("kind", sa.String(16), nullable=False),
        sa.Column("state", sa.String(16), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("next_attempt_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("error_code", sa.String(32)),
        sa.Column("document", postgresql.JSONB()),
        sa.Column("document_sha256", sa.String(64)),
        sa.Column("generated_at", sa.DateTime(timezone=True)),
        sa.CheckConstraint(
            "state in ('PENDING','READY','FAILED')",
            name=op.f("ck_scheduled_reports_scheduled_report_state"),
        ),
        sa.CheckConstraint(
            "kind in ('BASELINE','COMPARISON')",
            name=op.f("ck_scheduled_reports_scheduled_report_kind"),
        ),
        sa.CheckConstraint(
            "(kind='BASELINE') = (previous_run_id IS NULL)",
            name=op.f("ck_scheduled_reports_scheduled_report_pair"),
        ),
        sa.CheckConstraint(
            "run_id <> previous_run_id",
            name=op.f("ck_scheduled_reports_scheduled_report_distinct_runs"),
        ),
        sa.CheckConstraint(
            "attempts between 0 and 3", name=op.f("ck_scheduled_reports_scheduled_report_attempts")
        ),
        sa.CheckConstraint(
            "error_code IS NULL OR error_code in ('CONTEXT_MISMATCH','SOURCE_LIMIT','GENERATION_FAILED','RECOVERY_RECONCILED')",
            name=op.f("ck_scheduled_reports_scheduled_report_error"),
        ),
        sa.CheckConstraint(
            "state <> 'FAILED' OR error_code IS NOT NULL",
            name=op.f("ck_scheduled_reports_scheduled_report_failure"),
        ),
        sa.CheckConstraint(
            "(state='READY' AND document IS NOT NULL AND document_sha256 ~ '^[a-f0-9]{64}$' AND document_sha256 IS NOT NULL AND generated_at IS NOT NULL AND error_code IS NULL AND attempts>0) OR (state<>'READY' AND document IS NULL AND document_sha256 IS NULL AND generated_at IS NULL)",
            name=op.f("ck_scheduled_reports_scheduled_report_artifact"),
        ),
        sa.CheckConstraint(
            "document IS NULL OR (jsonb_typeof(document)='object' AND octet_length(document::text)<=2097152)",
            name=op.f("ck_scheduled_reports_scheduled_report_size"),
        ),
    )
    op.create_index("ix_scheduled_reports_schedule_id", "scheduled_reports", ["schedule_id"])
    op.create_index(
        "ix_scheduled_report_pending", "scheduled_reports", ["state", "next_attempt_at"]
    )
    op.execute("""CREATE FUNCTION guard_scheduled_report() RETURNS trigger
      LANGUAGE plpgsql AS $$ BEGIN
        IF OLD.state <> 'PENDING' OR
          ROW(NEW.id,NEW.created_at,NEW.schedule_id,NEW.authorization_id,NEW.occurrence_id,
              NEW.run_id,NEW.previous_run_id,NEW.kind) IS DISTINCT FROM
          ROW(OLD.id,OLD.created_at,OLD.schedule_id,OLD.authorization_id,OLD.occurrence_id,
              OLD.run_id,OLD.previous_run_id,OLD.kind) OR
          NEW.attempts < OLD.attempts OR NEW.attempts > OLD.attempts+1 THEN
          RAISE EXCEPTION 'Scheduled report history is immutable' USING ERRCODE='23514';
        END IF;
        RETURN NEW;
      END $$""")
    op.execute("""CREATE TRIGGER scheduled_report_history_guard BEFORE UPDATE ON scheduled_reports
      FOR EACH ROW EXECUTE FUNCTION guard_scheduled_report()""")


def downgrade():
    op.drop_table("scheduled_reports")
    op.execute("DROP FUNCTION guard_scheduled_report()")
