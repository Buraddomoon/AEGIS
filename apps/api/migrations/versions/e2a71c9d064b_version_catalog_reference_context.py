"""Allow immutable context profile extensions of the same catalog source."""

import sqlalchemy as sa
from alembic import op

revision = "e2a71c9d064b"
down_revision = "c8e4a6d21f90"
branch_labels = None
depends_on = None


def upgrade():
    # Read the existing versioned JSON: no new column or historical row rewrite.
    op.drop_constraint(
        "uq_attack_catalog_releases_dataset_version", "attack_catalog_releases", type_="unique"
    )
    op.create_index(
        "uq_attack_catalog_releases_source_profile",
        "attack_catalog_releases",
        [
            "dataset_version",
            "source_sha256",
            "license_sha256",
            "provenance",
            sa.text("coalesce(document->>'format', 'aegis-enterprise-catalog/1')"),
        ],
        unique=True,
    )
    op.create_check_constraint(
        "catalog_document_format",
        "attack_catalog_releases",
        "coalesce(document->>'format', 'aegis-enterprise-catalog/1') "
        "in ('aegis-enterprise-catalog/1','aegis-enterprise-catalog/2')",
    )


def downgrade():
    if op.get_bind().scalar(
        sa.text(
            "SELECT EXISTS(SELECT 1 FROM attack_catalog_releases "
            "WHERE document->>'format' <> 'aegis-enterprise-catalog/1')"
        )
    ):
        raise RuntimeError("Context release history exists; downgrade refused")
    op.drop_constraint("catalog_document_format", "attack_catalog_releases", type_="check")
    op.drop_index("uq_attack_catalog_releases_source_profile", table_name="attack_catalog_releases")
    op.create_unique_constraint(
        "uq_attack_catalog_releases_dataset_version",
        "attack_catalog_releases",
        ["dataset_version", "source_sha256", "license_sha256", "provenance"],
    )
