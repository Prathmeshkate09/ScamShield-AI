"""add structured threat report fields

Revision ID: 0003_add_threat_report_fields
Revises: 0002_add_analysis_user_ownership
Create Date: 2026-09-04
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0003_add_threat_report_fields"
down_revision = "0002_add_analysis_user_ownership"
branch_labels = None
depends_on = None


def upgrade() -> None:
    empty_list = sa.text("'[]'::jsonb")
    empty_chain = sa.text("'{\"nodes\":[],\"edges\":[]}'::jsonb")
    op.add_column("analyses", sa.Column("signals", postgresql.JSONB(), server_default=empty_list, nullable=False))
    op.add_column("analyses", sa.Column("evidence", postgresql.JSONB(), server_default=empty_list, nullable=False))
    op.add_column("analyses", sa.Column("extracted_urls", postgresql.JSONB(), server_default=empty_list, nullable=False))
    op.add_column("analyses", sa.Column("url_intelligence", postgresql.JSONB(), server_default=empty_list, nullable=False))
    op.add_column("analyses", sa.Column("attack_chain", postgresql.JSONB(), server_default=empty_chain, nullable=False))
    op.add_column("analyses", sa.Column("incident_response", postgresql.JSONB(), server_default=empty_list, nullable=False))
    op.add_column("analyses", sa.Column("analysis_duration_ms", sa.Integer(), nullable=True))
    op.add_column("analyses", sa.Column("ai_provider", sa.String(length=40), nullable=True))
    op.add_column("analyses", sa.Column("model_name", sa.String(length=120), nullable=True))
    op.add_column("analyses", sa.Column("scoring_version", sa.String(length=30), server_default="v1", nullable=False))
    op.create_check_constraint(
        "ck_analyses_analysis_duration_ms",
        "analyses",
        "analysis_duration_ms IS NULL OR analysis_duration_ms >= 0",
    )


def downgrade() -> None:
    op.drop_constraint("ck_analyses_analysis_duration_ms", "analyses", type_="check")
    op.drop_column("analyses", "scoring_version")
    op.drop_column("analyses", "model_name")
    op.drop_column("analyses", "ai_provider")
    op.drop_column("analyses", "analysis_duration_ms")
    op.drop_column("analyses", "incident_response")
    op.drop_column("analyses", "attack_chain")
    op.drop_column("analyses", "url_intelligence")
    op.drop_column("analyses", "extracted_urls")
    op.drop_column("analyses", "evidence")
    op.drop_column("analyses", "signals")
