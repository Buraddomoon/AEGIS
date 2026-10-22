"""add versioned rule test review links"""

import sqlalchemy as sa
from alembic import op

revision = "ec3020ae8711"
down_revision = "4b72c7bb8548"
branch_labels = None
depends_on = None


def upgrade():
    op.create_unique_constraint("uq_rule_versions_id_rule_id", "rule_versions", ["id", "rule_id"])
    op.create_table(
        "rule_test_links",
        sa.Column("rule_id", sa.String(length=36), nullable=False),
        sa.Column("rule_version_id", sa.String(length=36), nullable=False),
        sa.Column("test_id", sa.String(length=60), nullable=False),
        sa.Column("test_version", sa.Integer(), nullable=False),
        sa.Column("rationale", sa.Text(), nullable=False),
        sa.Column("created_by", sa.String(length=36), nullable=False),
        sa.Column("retired_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("retired_by", sa.String(length=36), nullable=True),
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "(retired_at IS NULL) = (retired_by IS NULL)",
            name=op.f("ck_rule_test_links_link_retirement"),
        ),
        sa.CheckConstraint("test_version > 0", name=op.f("ck_rule_test_links_link_test_version")),
        sa.ForeignKeyConstraint(
            ["created_by"], ["users.id"], name=op.f("fk_rule_test_links_created_by_users")
        ),
        sa.ForeignKeyConstraint(
            ["retired_by"], ["users.id"], name=op.f("fk_rule_test_links_retired_by_users")
        ),
        sa.ForeignKeyConstraint(
            ["rule_id"],
            ["detection_rules.id"],
            name=op.f("fk_rule_test_links_rule_id_detection_rules"),
        ),
        sa.ForeignKeyConstraint(
            ["rule_version_id", "rule_id"],
            ["rule_versions.id", "rule_versions.rule_id"],
            name="fk_rule_test_links_version_rule",
        ),
        sa.ForeignKeyConstraint(
            ["test_id"],
            ["test_definitions.id"],
            name=op.f("fk_rule_test_links_test_id_test_definitions"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_rule_test_links")),
    )
    op.create_index(
        op.f("ix_rule_test_links_rule_id"), "rule_test_links", ["rule_id"], unique=False
    )
    op.create_index(
        op.f("ix_rule_test_links_rule_version_id"),
        "rule_test_links",
        ["rule_version_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_rule_test_links_test_id"), "rule_test_links", ["test_id"], unique=False
    )
    op.create_index(
        "uq_rule_test_links_active",
        "rule_test_links",
        ["rule_id", "test_id"],
        unique=True,
        postgresql_where=sa.text("retired_at IS NULL"),
    )


def downgrade():
    op.drop_index(
        "uq_rule_test_links_active",
        table_name="rule_test_links",
        postgresql_where=sa.text("retired_at IS NULL"),
    )
    op.drop_index(op.f("ix_rule_test_links_test_id"), table_name="rule_test_links")
    op.drop_index(op.f("ix_rule_test_links_rule_version_id"), table_name="rule_test_links")
    op.drop_index(op.f("ix_rule_test_links_rule_id"), table_name="rule_test_links")
    op.drop_table("rule_test_links")
    op.drop_constraint("uq_rule_versions_id_rule_id", "rule_versions", type_="unique")
