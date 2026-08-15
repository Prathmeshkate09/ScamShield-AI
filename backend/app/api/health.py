from __future__ import annotations

from fastapi import APIRouter, Depends

from app.config import Settings
from app.database import Database
from app.dependencies import get_database, get_rate_limiter, get_settings
from app.schemas.common import ResponseMeta, SuccessResponse
from app.services.ai_service import select_provider
from app.services.rate_limiter import RateLimitService

router = APIRouter(tags=["health"])


@router.get("/health", response_model=SuccessResponse)
async def health(
    settings: Settings = Depends(get_settings),
    database: Database = Depends(get_database),
    rate_limiter: RateLimitService = Depends(get_rate_limiter),
) -> SuccessResponse:
    provider = select_provider(settings)
    database_state = await database.health_state()
    is_degraded = database_state != "ready" or rate_limiter.state == "degraded"
    return SuccessResponse(
        data={
            "status": "degraded" if is_degraded else "ok",
            "service": "scamshield-api",
            "database_configured": settings.database_configured,
            "database": database_state,
            "storage_configured": settings.storage_configured,
            "authentication_configured": settings.auth_configured,
            "rate_limiter": rate_limiter.state,
        },
        meta=ResponseMeta(request_id="health", provider=provider.name, mode=provider.mode),
    )
