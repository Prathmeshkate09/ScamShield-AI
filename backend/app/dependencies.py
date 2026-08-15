from __future__ import annotations

from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.config import Settings
from app.core.errors import AuthenticationRequiredError, PersistenceUnavailableError
from app.database import Database
from app.repositories.analysis_repository import AnalysisRepository
from app.services.ai_service import select_provider
from app.services.auth_service import AuthenticatedUser, SupabaseAuthService
from app.services.rate_limiter import RateLimitService
from app.services.scam_analyzer import ScamAnalyzer
from app.services.storage_service import StorageService

bearer_scheme = HTTPBearer(auto_error=False)


def get_settings(request: Request) -> Settings:
    return request.app.state.settings


def get_database(request: Request) -> Database:
    return request.app.state.database


def get_analyzer(request: Request) -> ScamAnalyzer:
    return ScamAnalyzer(select_provider(request.app.state.settings))


def get_storage_service(request: Request) -> StorageService:
    return StorageService(request.app.state.settings)


def get_auth_service(request: Request) -> SupabaseAuthService:
    return request.app.state.auth_service


def get_rate_limiter(request: Request) -> RateLimitService:
    return request.app.state.rate_limiter


async def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    auth_service: SupabaseAuthService = Depends(get_auth_service),
) -> AuthenticatedUser:
    if credentials is None or credentials.scheme.lower() != "bearer" or not credentials.credentials:
        raise AuthenticationRequiredError()
    return await auth_service.get_user(credentials.credentials)


async def require_standard_rate_limit(
    user: AuthenticatedUser = Depends(get_current_user),
    rate_limiter: RateLimitService = Depends(get_rate_limiter),
) -> AuthenticatedUser:
    await rate_limiter.enforce_user(user.id)
    return user


async def require_text_scan_rate_limit(
    user: AuthenticatedUser = Depends(require_standard_rate_limit),
    rate_limiter: RateLimitService = Depends(get_rate_limiter),
) -> AuthenticatedUser:
    await rate_limiter.enforce_scan(user.id, "text")
    return user


async def require_url_scan_rate_limit(
    user: AuthenticatedUser = Depends(require_standard_rate_limit),
    rate_limiter: RateLimitService = Depends(get_rate_limiter),
) -> AuthenticatedUser:
    await rate_limiter.enforce_scan(user.id, "url")
    return user


async def require_voice_scan_rate_limit(
    user: AuthenticatedUser = Depends(require_standard_rate_limit),
    rate_limiter: RateLimitService = Depends(get_rate_limiter),
) -> AuthenticatedUser:
    await rate_limiter.enforce_scan(user.id, "voice")
    return user


async def require_image_scan_rate_limit(
    user: AuthenticatedUser = Depends(require_standard_rate_limit),
    rate_limiter: RateLimitService = Depends(get_rate_limiter),
) -> AuthenticatedUser:
    await rate_limiter.enforce_scan(user.id, "image")
    return user


def get_repository(request: Request) -> AnalysisRepository:
    database: Database = request.app.state.database
    if database.session_factory is None:
        raise PersistenceUnavailableError()
    return AnalysisRepository(database.session_factory, request.app.state.settings.local_auth_schema_enabled)
