from __future__ import annotations

from fastapi import Request

from app.config import Settings
from app.core.errors import PersistenceUnavailableError
from app.database import Database
from app.repositories.analysis_repository import AnalysisRepository
from app.services.ai_service import select_provider
from app.services.scam_analyzer import ScamAnalyzer
from app.services.storage_service import StorageService


def get_settings(request: Request) -> Settings:
    return request.app.state.settings


def get_analyzer(request: Request) -> ScamAnalyzer:
    return ScamAnalyzer(select_provider(request.app.state.settings))


def get_storage_service(request: Request) -> StorageService:
    return StorageService(request.app.state.settings)


def get_repository(request: Request) -> AnalysisRepository:
    database: Database = request.app.state.database
    if database.session_factory is None:
        raise PersistenceUnavailableError()
    return AnalysisRepository(database.session_factory)
