import base64
import json
from uuid import UUID

import httpx
import pytest
from fastapi.security import HTTPAuthorizationCredentials

from app.config import Settings
from app.core.errors import (
    AccountUnavailableError,
    AuthenticationRequiredError,
    EmailVerificationRequiredError,
)
from app.dependencies import get_current_user
from app.services.auth_service import AuthenticatedUser, SupabaseAuthService

USER_ID = UUID("00000000-0000-4000-8000-000000000001")
SESSION_ID = UUID("00000000-0000-4000-8000-000000000010")


def access_token() -> str:
    def encode(value: dict[str, str]) -> str:
        return base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip("=")

    return f"{encode({'alg': 'none'})}.{encode({'sub': str(USER_ID), 'session_id': str(SESSION_ID)})}.signature"


def auth_service(handler) -> tuple[SupabaseAuthService, httpx.AsyncClient]:
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    settings = Settings(
        app_env="test",
        supabase_url="https://project.supabase.co",
        supabase_publishable_key="sb_publishable_test",
    )
    return SupabaseAuthService(settings, client), client


@pytest.mark.asyncio
async def test_verified_user_is_normalized_and_accepted() -> None:
    token = access_token()

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["authorization"] == f"Bearer {token}"
        return httpx.Response(
            200,
            json={
                "id": "00000000-0000-4000-8000-000000000001",
                "email": "  User@Example.COM ",
                "email_confirmed_at": "2026-08-21T00:00:00Z",
                "is_anonymous": False,
            },
        )

    service, client = auth_service(handler)
    try:
        user = await service.get_user(token)
    finally:
        await client.aclose()

    assert user.id == USER_ID
    assert user.email == "user@example.com"
    assert user.session_id == SESSION_ID


@pytest.mark.asyncio
async def test_unverified_user_is_rejected() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "id": "00000000-0000-4000-8000-000000000001",
                "email": "user@example.com",
                "email_confirmed_at": None,
            },
        )

    service, client = auth_service(handler)
    try:
        with pytest.raises(EmailVerificationRequiredError):
            await service.get_user("unverified-token")
    finally:
        await client.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize("status_code,error_type", [(401, AuthenticationRequiredError), (403, AccountUnavailableError)])
async def test_invalid_or_disabled_sessions_are_rejected(status_code: int, error_type: type[Exception]) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status_code, json={"message": "not authorized"})

    service, client = auth_service(handler)
    try:
        with pytest.raises(error_type):
            await service.get_user("unusable-token")
    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_anonymous_user_is_not_treated_as_a_full_account() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "id": "00000000-0000-4000-8000-000000000001",
                "email": None,
                "email_confirmed_at": None,
                "is_anonymous": True,
            },
        )

    service, client = auth_service(handler)
    try:
        with pytest.raises(AccountUnavailableError):
            await service.get_user("anonymous-token")
    finally:
        await client.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize("active", [True, False])
async def test_production_api_requires_an_active_supabase_session(active: bool) -> None:
    user = AuthenticatedUser(id=USER_ID, email="user@example.com", session_id=SESSION_ID)

    class VerifiedAuthService:
        async def get_user(self, token: str) -> AuthenticatedUser:
            return user

    class SessionDatabase:
        async def auth_session_is_active(self, user_id: UUID, session_id: UUID) -> bool:
            assert user_id == USER_ID
            assert session_id == SESSION_ID
            return active

    credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials=access_token())
    if active:
        result = await get_current_user(
            credentials=credentials,
            auth_service=VerifiedAuthService(),  # type: ignore[arg-type]
            database=SessionDatabase(),  # type: ignore[arg-type]
            settings=Settings(app_env="production", auth_strict_session_validation=True),
        )
        assert result == user
    else:
        with pytest.raises(AuthenticationRequiredError):
            await get_current_user(
                credentials=credentials,
                auth_service=VerifiedAuthService(),  # type: ignore[arg-type]
                database=SessionDatabase(),  # type: ignore[arg-type]
                settings=Settings(app_env="production", auth_strict_session_validation=True),
            )


def test_strict_session_validation_defaults_by_environment() -> None:
    assert Settings(app_env="production", auth_strict_session_validation=None).require_active_auth_session is True
    assert Settings(app_env="development", auth_strict_session_validation=None).require_active_auth_session is False
