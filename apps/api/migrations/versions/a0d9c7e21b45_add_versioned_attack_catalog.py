"""Versioned ATT&CK releases and lifecycle projection; adoption remains explicit."""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "a0d9c7e21b45"
down_revision = "977fd0c42ae8"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "attack_techniques",
        sa.Column("revoked", sa.Boolean(), server_default=sa.text("false"), nullable=False),
    )
    op.add_column(
        "attack_techniques",
        sa.Column("deprecated", sa.Boolean(), server_default=sa.text("false"), nullable=False),
    )
    op.add_column(
        "attack_techniques",
        sa.Column(
            "present_in_current", sa.Boolean(), server_default=sa.text("true"), nullable=False
        ),
    )
    op.add_column("attack_techniques", sa.Column("source_modified", sa.String(40), nullable=True))
    op.create_table(
        "attack_catalog_releases",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("dataset_version", sa.String(40), nullable=False),
        sa.Column("provenance", sa.String(24), nullable=False),
        sa.Column("source_url", sa.Text(), nullable=False),
        sa.Column("source_commit", sa.String(40)),
        sa.Column("source_sha256", sa.String(64), nullable=False),
        sa.Column("license_sha256", sa.String(64), nullable=False),
        sa.Column("document", postgresql.JSONB(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("applied_by", sa.String(36), sa.ForeignKey("users.id")),
        sa.CheckConstraint(
            "provenance in ('bundled','official_commit')",
            name=op.f("ck_attack_catalog_releases_catalog_provenance"),
        ),
        sa.UniqueConstraint("dataset_version", "source_sha256", "license_sha256", "provenance"),
    )
    op.create_table(
        "attack_catalog_state",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=False),
        sa.Column(
            "release_id", sa.String(64), sa.ForeignKey("attack_catalog_releases.id"), nullable=False
        ),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("id=1", name=op.f("ck_attack_catalog_state_catalog_singleton")),
    )
    op.execute("""CREATE FUNCTION guard_attack_catalog_release() RETURNS trigger
      LANGUAGE plpgsql AS $$ BEGIN
        RAISE EXCEPTION 'ATT&CK release history is immutable' USING ERRCODE='23514';
      END $$""")
    op.execute("""CREATE TRIGGER attack_catalog_history_guard BEFORE UPDATE OR DELETE
      ON attack_catalog_releases FOR EACH ROW EXECUTE FUNCTION guard_attack_catalog_release()""")


def downgrade():
    op.execute("DROP TRIGGER attack_catalog_history_guard ON attack_catalog_releases")
    op.execute("DROP FUNCTION guard_attack_catalog_release()")
    op.drop_table("attack_catalog_state")
    op.drop_table("attack_catalog_releases")
    for column in ("source_modified", "present_in_current", "deprecated", "revoked"):
        op.drop_column("attack_techniques", column)
