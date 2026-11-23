"""Allow immutable context profile extensions of the same catalog source."""

import sqlalchemy as sa
from alembic import op

revision = "e2a71c9d064b"
down_revision = "c8e4a6d21f90"
branch_labels = None
depends_on = None


def upgrade():
    # Server default preserves existing rows without rewriting their documents/IDs.
    op.add_column(
        "attack_catalog_releases",
        sa.Column(
            "document_format",
            sa.String(40),
            nullable=False,
            server_default="aegis-enterprise-catalog/1",
        ),
    )
    op.drop_constraint(
        "uq_attack_catalog_releases_dataset_version", "attack_catalog_releases", type_="unique"
    )
    op.create_unique_constraint(
        "uq_attack_catalog_releases_dataset_version",
        "attack_catalog_releases",
        ["dataset_version", "source_sha256", "license_sha256", "provenance", "document_format"],
    )
    op.create_check_constraint(
        "catalog_document_format",
        "attack_catalog_releases",
        "document_format in ('aegis-enterprise-catalog/1','aegis-enterprise-catalog/2') "
        "AND document_format = coalesce(document->>'format', 'aegis-enterprise-catalog/1')",
    )


def downgrade():
    if op.get_bind().scalar(
        sa.text(
            "SELECT EXISTS(SELECT 1 FROM attack_catalog_releases "
            "WHERE document_format <> 'aegis-enterprise-catalog/1')"
        )
    ):
        raise RuntimeError("Context release history exists; downgrade refused")
    op.drop_constraint("catalog_document_format", "attack_catalog_releases", type_="check")
    op.drop_constraint(
        "uq_attack_catalog_releases_dataset_version", "attack_catalog_releases", type_="unique"
    )
    op.create_unique_constraint(
        "uq_attack_catalog_releases_dataset_version",
        "attack_catalog_releases",
        ["dataset_version", "source_sha256", "license_sha256", "provenance"],
    )
    op.drop_column("attack_catalog_releases", "document_format")
