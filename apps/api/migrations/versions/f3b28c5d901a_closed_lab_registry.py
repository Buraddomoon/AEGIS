"""Closed registry selection and exact campaign asset, without rewriting history."""

import sqlalchemy as sa
from alembic import op

revision = "f3b28c5d901a"
down_revision = "e2a71c9d064b"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("linux_lab_bindings", sa.Column("registry_id", sa.String(64), nullable=True))
    op.create_unique_constraint(
        "uq_linux_lab_bindings_registry_id", "linux_lab_bindings", ["registry_id"]
    )
    op.create_unique_constraint("uq_assets_id_laboratory_id", "assets", ["id", "laboratory_id"])
    op.add_column("campaigns", sa.Column("asset_id", sa.String(36), nullable=True))
    op.create_foreign_key(
        "fk_campaigns_asset_laboratory",
        "campaigns",
        "assets",
        ["asset_id", "laboratory_id"],
        ["id", "laboratory_id"],
    )


def downgrade():
    if op.get_bind().scalar(
        sa.text(
            "SELECT EXISTS(SELECT 1 FROM campaigns WHERE asset_id IS NOT NULL) OR EXISTS(SELECT 1 FROM linux_lab_bindings WHERE registry_id IS NOT NULL)"
        )
    ):
        raise RuntimeError("Registry/asset selections exist; downgrade refused")
    op.drop_constraint("fk_campaigns_asset_laboratory", "campaigns", type_="foreignkey")
    op.drop_column("campaigns", "asset_id")
    op.drop_constraint("uq_assets_id_laboratory_id", "assets", type_="unique")
    op.drop_constraint("uq_linux_lab_bindings_registry_id", "linux_lab_bindings", type_="unique")
    op.drop_column("linux_lab_bindings", "registry_id")
