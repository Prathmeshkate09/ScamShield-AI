from __future__ import annotations

import logging

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine

logger = logging.getLogger(__name__)


class Database:
    def __init__(self, database_url: str | None) -> None:
        self._engine: AsyncEngine | None = None
        self.session_factory: async_sessionmaker[AsyncSession] | None = None
        if database_url:
            self._engine = create_async_engine(database_url, pool_pre_ping=True, pool_size=5, max_overflow=5)
            self.session_factory = async_sessionmaker(self._engine, expire_on_commit=False)

    @property
    def configured(self) -> bool:
        return self.session_factory is not None

    async def health_state(self) -> str:
        if self._engine is None:
            return "not_configured"

        try:
            async with self._engine.connect() as connection:
                await connection.execute(text("SELECT 1"))
        except Exception as error:
            logger.error("database.health_check_failed", extra={"error_type": type(error).__name__})
            return "unavailable"
        return "ready"

    async def dispose(self) -> None:
        if self._engine is not None:
            await self._engine.dispose()
