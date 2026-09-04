from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass

from sqlalchemy import func, select, text
from sqlalchemy.exc import DisconnectionError, InterfaceError, OperationalError, SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.errors import DatabaseUnavailableError
from app.models.analysis import Analysis
from app.schemas.analysis import AnalysisResponse, DashboardStats, ScamAssessment

logger = logging.getLogger(__name__)

DATABASE_CONNECTION_ERRORS = (DisconnectionError, InterfaceError, OperationalError, OSError)


@dataclass(frozen=True)
class PaginatedAnalyses:
    items: list[AnalysisResponse]
    total: int
    database_latency_ms: int


class AnalysisRepository:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession], provision_local_auth_users: bool = False) -> None:
        self.session_factory = session_factory
        self.provision_local_auth_users = provision_local_auth_users

    async def save(
        self,
        analysis_id: uuid.UUID,
        user_id: uuid.UUID,
        assessment: ScamAssessment,
        input_type: str,
        input_text: str | None = None,
        file_path: str | None = None,
    ) -> tuple[AnalysisResponse, int]:
        started_at = time.perf_counter()
        record = Analysis(
            id=analysis_id,
            user_id=user_id,
            input_type=input_type,
            input_text=input_text,
            file_path=file_path,
            risk_score=assessment.risk_score,
            risk_level=assessment.risk_level.value,
            scam_type=assessment.scam_type,
            confidence=assessment.confidence,
            red_flags=assessment.red_flags,
            explanation=assessment.explanation,
            recommendation=assessment.recommendation,
            signals=[],
            evidence=[],
            extracted_urls=[],
            url_intelligence=[],
            attack_chain={"nodes": [], "edges": []},
            incident_response=[],
            scoring_version="v1",
        )
        async with self.session_factory() as session:
            try:
                if self.provision_local_auth_users:
                    await session.execute(
                        text("INSERT INTO auth.users (id) VALUES (:user_id) ON CONFLICT (id) DO NOTHING"),
                        {"user_id": user_id},
                    )
                session.add(record)
                await session.commit()
                await session.refresh(record)
            except DATABASE_CONNECTION_ERRORS as error:
                await self._raise_database_unavailable(session, "save", error)
        return self._to_response(record), round((time.perf_counter() - started_at) * 1000)

    async def list(self, user_id: uuid.UUID, page: int, page_size: int) -> PaginatedAnalyses:
        started_at = time.perf_counter()
        statement = (
            select(Analysis)
            .where(Analysis.user_id == user_id)
            .order_by(Analysis.created_at.desc())
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
        async with self.session_factory() as session:
            try:
                result = await session.execute(statement)
                records = list(result.scalars())
                total = await session.scalar(select(func.count(Analysis.id)).where(Analysis.user_id == user_id))
            except DATABASE_CONNECTION_ERRORS as error:
                await self._raise_database_unavailable(session, "list", error)
        return PaginatedAnalyses(
            items=[self._to_response(record) for record in records],
            total=total or 0,
            database_latency_ms=round((time.perf_counter() - started_at) * 1000),
        )
    async def get(self, analysis_id: uuid.UUID, user_id: uuid.UUID) -> AnalysisResponse | None:
        async with self.session_factory() as session:
            try:
                record = await session.scalar(select(Analysis).where(Analysis.id == analysis_id, Analysis.user_id == user_id))
            except DATABASE_CONNECTION_ERRORS as error:
                await self._raise_database_unavailable(session, "get", error)
        return self._to_response(record) if record else None

    async def stats(self, user_id: uuid.UUID) -> DashboardStats:
        async with self.session_factory() as session:
            try:
                total = await session.scalar(select(func.count(Analysis.id)).where(Analysis.user_id == user_id))
                high_risk = await session.scalar(
                    select(func.count(Analysis.id)).where(Analysis.user_id == user_id, Analysis.risk_level.in_(["HIGH", "CRITICAL"]))
                )
                critical = await session.scalar(select(func.count(Analysis.id)).where(Analysis.user_id == user_id, Analysis.risk_level == "CRITICAL"))
                common_type = await session.scalar(
                    select(Analysis.scam_type)
                    .where(Analysis.user_id == user_id)
                    .group_by(Analysis.scam_type)
                    .order_by(func.count(Analysis.id).desc(), Analysis.scam_type.asc())
                    .limit(1)
                )
            except DATABASE_CONNECTION_ERRORS as error:
                await self._raise_database_unavailable(session, "stats", error)
        return DashboardStats(
            total_analyses=total or 0,
            high_risk_detected=high_risk or 0,
            critical_scams=critical or 0,
            most_common_scam_type=common_type,
        )

    @staticmethod
    def _to_response(record: Analysis) -> AnalysisResponse:
        return AnalysisResponse(
            id=record.id,
            input_type=record.input_type,
            risk_score=record.risk_score,
            risk_level=record.risk_level,
            scam_type=record.scam_type,
            confidence=float(record.confidence),
            red_flags=record.red_flags,
            explanation=record.explanation,
            recommendation=record.recommendation,
            signals=record.signals,
            evidence=record.evidence,
            extracted_urls=record.extracted_urls,
            url_intelligence=record.url_intelligence,
            attack_chain=record.attack_chain,
            incident_response=record.incident_response,
            analysis_duration_ms=record.analysis_duration_ms,
            ai_provider=record.ai_provider,
            model_name=record.model_name,
            scoring_version=record.scoring_version,
            created_at=record.created_at,
        )

    @staticmethod
    async def _raise_database_unavailable(session: AsyncSession, operation: str, error: Exception) -> None:
        try:
            await session.rollback()
        except SQLAlchemyError as rollback_error:
            logger.error(
                "database.rollback_failed",
                extra={"operation": operation, "error_type": type(rollback_error).__name__},
            )
        logger.error("database.connection_failed", extra={"operation": operation, "error_type": type(error).__name__})
        raise DatabaseUnavailableError() from error
