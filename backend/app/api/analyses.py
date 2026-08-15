from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, Query

from app.core.errors import AppError
from app.dependencies import get_repository
from app.repositories.analysis_repository import AnalysisRepository
from app.schemas.analysis import AnalysisListResponse
from app.schemas.common import ResponseMeta, SuccessResponse

router = APIRouter(prefix="/analyses", tags=["analyses"])


@router.get("", response_model=SuccessResponse)
async def list_analyses(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    repository: AnalysisRepository = Depends(get_repository),
) -> SuccessResponse:
    result = await repository.list(page, page_size)
    return SuccessResponse(
        data=AnalysisListResponse(items=result.items, page=page, page_size=page_size, total=result.total),
        meta=ResponseMeta(request_id="history"),
    )


@router.get("/stats", response_model=SuccessResponse)
async def analysis_stats(repository: AnalysisRepository = Depends(get_repository)) -> SuccessResponse:
    return SuccessResponse(data=await repository.stats(), meta=ResponseMeta(request_id="stats"))


@router.get("/{analysis_id}", response_model=SuccessResponse)
async def get_analysis(analysis_id: UUID, repository: AnalysisRepository = Depends(get_repository)) -> SuccessResponse:
    result = await repository.get(analysis_id)
    if result is None:
        raise AppError("Analysis not found.", 404, "analysis_not_found")
    return SuccessResponse(data=result, meta=ResponseMeta(request_id="analysis-detail"))
