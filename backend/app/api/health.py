from __future__ import annotations

from fastapi import APIRouter, Depends

from app.config import Settings
from app.dependencies import get_settings
from app.schemas.common import ResponseMeta, SuccessResponse
from app.services.ai_service import select_provider

router = APIRouter(tags=["health"])


@router.get("/health", response_model=SuccessResponse)
async def health(settings: Settings = Depends(get_settings)) -> SuccessResponse:
    provider = select_provider(settings)
    return SuccessResponse(
        data={
            "status": "ok",
            "service": "scamshield-api",
            "database_configured": settings.database_configured,
            "storage_configured": settings.storage_configured,
        },
        meta=ResponseMeta(request_id="health", provider=provider.name, mode=provider.mode),
    )
