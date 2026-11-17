"""Immutable Atomic metadata versions and append-only metadata reviews."""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "c8e4a6d21f90"
down_revision = "b7f3c2d91a06"
branch_labels = None
depends_on = None


def entity():
    return [
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    ]


def upgrade():
    op.create_table(
        "atomic_documents",
        *entity(),
        sa.Column("source_commit", sa.String(40), nullable=False),
        sa.Column("source_sha256", sa.String(64), nullable=False),
        sa.Column("technique_id", sa.String(20), nullable=False),
        sa.Column("imported_by", sa.String(36), sa.ForeignKey("users.id"), nullable=False),
        sa.UniqueConstraint("source_commit", "technique_id"),
        sa.CheckConstraint("source_commit ~ '^[a-f0-9]{40}$'", name="atomic_commit"),
        sa.CheckConstraint("source_sha256 ~ '^[a-f0-9]{64}$'", name="atomic_hash"),
        sa.CheckConstraint("technique_id ~ '^T[0-9]{4}(\\.[0-9]{3})?$'", name="atomic_technique"),
    )
    op.create_table(
        "atomic_entries",
        *entity(),
        sa.Column(
            "document_id", sa.String(36), sa.ForeignKey("atomic_documents.id"), nullable=False
        ),
        sa.Column("guid", sa.String(36), nullable=False),
        sa.Column("name", sa.String(240), nullable=False),
        sa.Column("platforms", postgresql.ARRAY(sa.String(40)), nullable=False),
        sa.Column("metadata_projection", postgresql.JSONB(), nullable=False),
        sa.UniqueConstraint("document_id", "guid"),
    )
    op.create_index("ix_atomic_entries_document_id", "atomic_entries", ["document_id"])
    op.create_table(
        "atomic_reviews",
        *entity(),
        sa.Column("entry_id", sa.String(36), sa.ForeignKey("atomic_entries.id"), nullable=False),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("decision", sa.String(16), nullable=False),
        sa.Column("note", sa.Text(), nullable=False),
        sa.Column("reviewed_by", sa.String(36), sa.ForeignKey("users.id"), nullable=False),
        sa.UniqueConstraint("entry_id", "sequence"),
        sa.CheckConstraint("sequence > 0", name="atomic_review_sequence"),
        sa.CheckConstraint("decision in ('reviewed','rejected')", name="atomic_review_decision"),
        sa.CheckConstraint("length(note) BETWEEN 1 AND 2000", name="atomic_review_note"),
    )
    op.create_index("ix_atomic_reviews_entry_id", "atomic_reviews", ["entry_id"])
    op.execute("""CREATE FUNCTION guard_atomic_history() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN RAISE EXCEPTION 'Atomic metadata history is immutable' USING ERRCODE='23514'; END $$""")
    for table in ("atomic_documents", "atomic_entries", "atomic_reviews"):
        op.execute(
            f"CREATE TRIGGER atomic_history_guard BEFORE UPDATE OR DELETE ON {table} FOR EACH ROW EXECUTE FUNCTION guard_atomic_history()"
        )


def downgrade():
    for table in ("atomic_reviews", "atomic_entries", "atomic_documents"):
        op.drop_table(table)
    op.execute("DROP FUNCTION guard_atomic_history()")
