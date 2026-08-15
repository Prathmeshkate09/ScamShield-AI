from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class ResponseMeta(BaseModel):
    request_id: str
    provider: str | None = None
    mode: str | None = None
    persisted: bool | None = None


class SuccessResponse(BaseModel):
    success: bool = True
    data: Any
    meta: ResponseMeta


class ErrorBody(BaseModel):
    code: str
    message: str
    request_id: str


class ErrorResponse(BaseModel):
    success: bool = False
    error: ErrorBody
