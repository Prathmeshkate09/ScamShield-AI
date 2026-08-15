"""create analyses table

Revision ID: 0001_create_analyses
Revises:
Create Date: 2026-08-15
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0001_create_analyses"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "analyses",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("input_type", sa.String(length=20), nullable=False),
        sa.Column("input_text", sa.Text(), nullable=True),
        sa.Column("file_path", sa.Text(), nullable=True),
        sa.Column("risk_score", sa.Integer(), nullable=False),
        sa.Column("risk_level", sa.String(length=20), nullable=False),
        sa.Column("scam_type", sa.String(length=100), nullable=False),
        sa.Column("confidence", sa.Numeric(precision=4, scale=3), nullable=False),
        sa.Column("red_flags", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("explanation", sa.Text(), nullable=False),
        sa.Column("recommendation", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("timezone('utc', now())"), nullable=False),
        sa.CheckConstraint("risk_score >= 0 AND risk_score <= 100", name="ck_analyses_risk_score"),
        sa.CheckConstraint("confidence >= 0 AND confidence <= 1", name="ck_analyses_confidence"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_analyses_created_at", "analyses", ["created_at"])
    op.create_index("ix_analyses_risk_level", "analyses", ["risk_level"])
    op.create_index("ix_analyses_scam_type", "analyses", ["scam_type"])
    op.create_index("ix_analyses_user_id", "analyses", ["user_id"])
    op.execute("ALTER TABLE public.analyses ENABLE ROW LEVEL SECURITY")


def downgrade() -> None:
    op.drop_index("ix_analyses_user_id", table_name="analyses")
    op.drop_index("ix_analyses_scam_type", table_name="analyses")
    op.drop_index("ix_analyses_risk_level", table_name="analyses")
    op.drop_index("ix_analyses_created_at", table_name="analyses")
    op.drop_table("analyses")
