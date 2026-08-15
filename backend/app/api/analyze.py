from __future__ import annotations

import logging
import time
import uuid

from fastapi import APIRouter, Depends, File, Request, UploadFile

from app.dependencies import (
    get_analyzer,
    get_repository,
    get_storage_service,
    require_image_scan_rate_limit,
    require_text_scan_rate_limit,
    require_url_scan_rate_limit,
    require_voice_scan_rate_limit,
)
from app.repositories.analysis_repository import AnalysisRepository
from app.schemas.analysis import ScamAssessment, TextAnalysisRequest, UrlAnalysisRequest, VoiceAnalysisRequest
from app.schemas.common import ResponseMeta, SuccessResponse
from app.services.image_service import validate_image
from app.services.auth_service import AuthenticatedUser
from app.services.scam_analyzer import ScamAnalyzer
from app.services.storage_service import StorageService

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/analyze", tags=["analysis"])


async def complete_analysis(
    request: Request,
    analyzer: ScamAnalyzer,
    repository: AnalysisRepository,
    user: AuthenticatedUser,
    assessment: ScamAssessment,
    ai_latency_ms: int,
    input_type: str,
    input_text: str | None = None,
    file_path: str | None = None,
) -> SuccessResponse:
    analysis_id = uuid.uuid4()
    request_id = request.state.request_id
    database_latency_ms: int | None = None
    response, database_latency_ms = await repository.save(analysis_id, user.id, assessment, input_type, input_text, file_path)
    persisted = True
    logger.info(
        "analysis.completed",
        extra={
            "request_id": request_id,
            "analysis_id": str(analysis_id),
            "input_type": input_type,
            "provider": analyzer.provider.name,
            "latency_ms": ai_latency_ms,
            "database_latency_ms": database_latency_ms,
        },
    )
    return SuccessResponse(
        data=response,
        meta=ResponseMeta(request_id=request_id, provider=analyzer.provider.name, mode=analyzer.provider.mode, persisted=persisted),
    )


@router.post("/text", response_model=SuccessResponse)
async def analyze_text(
    payload: TextAnalysisRequest,
    request: Request,
    user: AuthenticatedUser = Depends(require_text_scan_rate_limit),
    analyzer: ScamAnalyzer = Depends(get_analyzer),
    repository: AnalysisRepository = Depends(get_repository),
) -> SuccessResponse:
    started_at = time.perf_counter()
    logger.info("analysis.started", extra={"request_id": request.state.request_id, "input_type": "text", "provider": analyzer.provider.name})
    assessment, ai_latency_ms = await analyzer.analyze_text(payload.text)
    response = await complete_analysis(request, analyzer, repository, user, assessment, ai_latency_ms, "text", input_text=payload.text)
    logger.info(
        "analysis.request_succeeded",
        extra={"request_id": request.state.request_id, "input_type": "text", "latency_ms": round((time.perf_counter() - started_at) * 1000)},
    )
    return response


@router.post("/url", response_model=SuccessResponse)
async def analyze_url(
    payload: UrlAnalysisRequest,
    request: Request,
    user: AuthenticatedUser = Depends(require_url_scan_rate_limit),
    analyzer: ScamAnalyzer = Depends(get_analyzer),
    repository: AnalysisRepository = Depends(get_repository),
) -> SuccessResponse:
    logger.info("analysis.started", extra={"request_id": request.state.request_id, "input_type": "url", "provider": analyzer.provider.name})
    assessment, ai_latency_ms = await analyzer.analyze_url(payload.url)
    return await complete_analysis(request, analyzer, repository, user, assessment, ai_latency_ms, "url", input_text=payload.url)


@router.post("/voice", response_model=SuccessResponse)
async def analyze_voice(
    payload: VoiceAnalysisRequest,
    request: Request,
    user: AuthenticatedUser = Depends(require_voice_scan_rate_limit),
    analyzer: ScamAnalyzer = Depends(get_analyzer),
    repository: AnalysisRepository = Depends(get_repository),
) -> SuccessResponse:
    logger.info("analysis.started", extra={"request_id": request.state.request_id, "input_type": "voice", "provider": analyzer.provider.name})
    assessment, ai_latency_ms = await analyzer.analyze_text(payload.transcript, input_type="voice")
    return await complete_analysis(request, analyzer, repository, user, assessment, ai_latency_ms, "voice", input_text=payload.transcript)


@router.post("/image", response_model=SuccessResponse)
async def analyze_image(
    request: Request,
    file: UploadFile = File(...),
    user: AuthenticatedUser = Depends(require_image_scan_rate_limit),
    analyzer: ScamAnalyzer = Depends(get_analyzer),
    storage: StorageService = Depends(get_storage_service),
    repository: AnalysisRepository = Depends(get_repository),
) -> SuccessResponse:
    logger.info("analysis.started", extra={"request_id": request.state.request_id, "input_type": "image", "provider": analyzer.provider.name})
    content = await file.read()
    content_type, extension = validate_image(content, file.content_type, file.filename, request.app.state.settings.max_upload_bytes)
    file_path = await storage.upload_image(content, content_type, extension, user.id)
    assessment, ai_latency_ms = await analyzer.analyze_image(content, content_type)
    return await complete_analysis(request, analyzer, repository, user, assessment, ai_latency_ms, "image", file_path=file_path)
