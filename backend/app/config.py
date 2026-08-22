from __future__ import annotations

from functools import cached_property
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    app_name: str = "ScamShield AI"
    app_env: Literal["development", "test", "production"] = "development"
    api_prefix: str = "/api/v1"
    cors_origins: str = "http://localhost:3000"
    database_url: str | None = None
    supabase_url: str | None = None
    supabase_publishable_key: str | None = None
    supabase_anon_key: str | None = None
    supabase_service_role_key: str | None = None
    supabase_storage_bucket: str = "scam-assets"
    upstash_redis_rest_url: str | None = None
    upstash_redis_rest_token: str | None = None
    rate_limit_enabled: bool = False
    rate_limit_window_seconds: int = Field(default=60, ge=1, le=3_600)
    rate_limit_health_per_window: int = Field(default=30, ge=1, le=10_000)
    rate_limit_user_per_window: int = Field(default=60, ge=1, le=10_000)
    rate_limit_scan_per_window: int = Field(default=10, ge=1, le=10_000)
    rate_limit_image_per_window: int = Field(default=4, ge=1, le=10_000)
    auth_strict_session_validation: bool | None = None
    local_auth_schema_enabled: bool = False
    ai_provider: Literal["auto", "openai", "gemini", "demo"] = "auto"
    openai_api_key: str | None = None
    openai_model: str = "gpt-4.1-mini"
    gemini_api_key: str | None = None
    gemini_model: str = "gemini-3.6-flash"
    max_upload_bytes: int = Field(default=10 * 1024 * 1024, ge=1_024, le=25 * 1024 * 1024)

    @field_validator("database_url")
    @classmethod
    def normalize_database_url(cls, value: str | None) -> str | None:
        if not value:
            return None
        if value.startswith("postgres://"):
            value = value.replace("postgres://", "postgresql+asyncpg://", 1)
        elif value.startswith("postgresql://"):
            value = value.replace("postgresql://", "postgresql+asyncpg://", 1)
        return value

    @cached_property
    def cors_origin_list(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]

    @property
    def database_configured(self) -> bool:
        return bool(self.database_url)

    @property
    def storage_configured(self) -> bool:
        return bool(self.supabase_url and self.supabase_service_role_key)

    @property
    def supabase_public_key(self) -> str | None:
        return self.supabase_publishable_key or self.supabase_anon_key

    @property
    def auth_configured(self) -> bool:
        return bool(self.supabase_url and self.supabase_public_key)

    @property
    def require_active_auth_session(self) -> bool:
        if self.auth_strict_session_validation is not None:
            return self.auth_strict_session_validation
        return self.app_env == "production"

    @property
    def rate_limiter_configured(self) -> bool:
        return bool(self.upstash_redis_rest_url and self.upstash_redis_rest_token)
