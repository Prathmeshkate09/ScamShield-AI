"""add analysis user ownership

Revision ID: 0002_add_analysis_user_ownership
Revises: 0001_create_analyses
Create Date: 2026-08-15
"""

from alembic import op


revision = "0002_add_analysis_user_ownership"
down_revision = "0001_create_analyses"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("CREATE SCHEMA IF NOT EXISTS auth")
    op.execute("CREATE TABLE IF NOT EXISTS auth.users (id UUID PRIMARY KEY)")
    op.create_foreign_key(
        "fk_analyses_user_id_auth_users",
        "analyses",
        "users",
        ["user_id"],
        ["id"],
        source_schema="public",
        referent_schema="auth",
        ondelete="SET NULL",
    )
    op.create_index("ix_analyses_user_id_created_at", "analyses", ["user_id", "created_at"])


def downgrade() -> None:
    op.drop_index("ix_analyses_user_id_created_at", table_name="analyses")
    op.drop_constraint("fk_analyses_user_id_auth_users", "analyses", schema="public", type_="foreignkey")
