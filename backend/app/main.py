from __future__ import annotations

import logging
import uuid
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api import analyses, analyze, health
from app.config import Settings
from app.core.errors import AppError
from app.core.logging import configure_logging
from app.database import Database
from app.schemas.common import ErrorResponse
from app.services.auth_service import SupabaseAuthService
from app.services.rate_limiter import RateLimitService

logger = logging.getLogger(__name__)


def create_app(settings: Settings | None = None) -> FastAPI:
    configure_logging()
    app_settings = settings or Settings()

    @asynccontextmanager
    async def lifespan(application: FastAPI):
        application.state.settings = app_settings
        application.state.database = Database(app_settings.database_url)
        application.state.auth_http_client = httpx.AsyncClient(timeout=httpx.Timeout(5.0))
        application.state.auth_service = SupabaseAuthService(app_settings, application.state.auth_http_client)
        application.state.rate_limiter = RateLimitService(app_settings)
        await application.state.rate_limiter.initialize()
        try:
            yield
        finally:
            await application.state.auth_http_client.aclose()
            await application.state.database.dispose()

    application = FastAPI(title=app_settings.app_name, version="0.1.0", lifespan=lifespan)
    application.add_middleware(
        CORSMiddleware,
        allow_origins=app_settings.cors_origin_list,
        allow_credentials=False,
        allow_methods=["GET", "POST"],
        allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
    )

    @application.middleware("http")
    async def request_context(request: Request, call_next):
        request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        request.state.request_id = request_id
        if request.method != "OPTIONS" and request.url.path == "/health":
            client_ip = request.client.host if request.client else "unknown"
            try:
                await request.app.state.rate_limiter.enforce_health(client_ip)
            except AppError as error:
                return await app_error_handler(request, error)
        content_length = request.headers.get("content-length")
        if content_length and int(content_length) > app_settings.max_upload_bytes + 16_384:
            return JSONResponse(
                status_code=413,
                content={
                    "success": False,
                    "error": {"code": "request_too_large", "message": "Request body is too large.", "request_id": request_id},
                },
            )
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        return response

    @application.exception_handler(AppError)
    async def app_error_handler(request: Request, error: AppError) -> JSONResponse:
        request_id = getattr(request.state, "request_id", "unknown")
        logger.warning("request.failed", extra={"request_id": request_id, "error_code": error.code})
        payload = ErrorResponse(error={"code": error.code, "message": error.message, "request_id": request_id})
        response = JSONResponse(status_code=error.status_code, content=payload.model_dump())
        for header, value in error.headers.items():
            response.headers[header] = value
        response.headers["X-Request-ID"] = request_id
        return response

    @application.exception_handler(RequestValidationError)
    async def validation_error_handler(request: Request, error: RequestValidationError) -> JSONResponse:
        request_id = getattr(request.state, "request_id", "unknown")
        payload = ErrorResponse(error={"code": "validation_error", "message": "Request validation failed.", "request_id": request_id})
        return JSONResponse(status_code=422, content=payload.model_dump())

    @application.exception_handler(Exception)
    async def unhandled_error_handler(request: Request, error: Exception) -> JSONResponse:
        request_id = getattr(request.state, "request_id", "unknown")
        logger.exception("request.unhandled_error", extra={"request_id": request_id})
        payload = ErrorResponse(error={"code": "internal_error", "message": "An unexpected error occurred.", "request_id": request_id})
        return JSONResponse(status_code=500, content=payload.model_dump())

    application.include_router(health.router)
    application.include_router(analyze.router, prefix=app_settings.api_prefix)
    application.include_router(analyses.router, prefix=app_settings.api_prefix)
    return application


app = create_app()
