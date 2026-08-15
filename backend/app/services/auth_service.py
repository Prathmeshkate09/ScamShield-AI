from __future__ import annotations

import uuid
from dataclasses import dataclass

import httpx

from app.config import Settings
from app.core.errors import AuthenticationRequiredError, AuthenticationUnavailableError


@dataclass(frozen=True)
class AuthenticatedUser:
    id: uuid.UUID
    email: str | None


class SupabaseAuthService:
    def __init__(self, settings: Settings, client: httpx.AsyncClient) -> None:
        self.settings = settings
        self.client = client

    async def get_user(self, access_token: str) -> AuthenticatedUser:
        if not self.settings.auth_configured:
            raise AuthenticationUnavailableError()

        try:
            response = await self.client.get(
                f"{self.settings.supabase_url}/auth/v1/user",
                headers={
                    "apikey": self.settings.supabase_public_key or "",
                    "Authorization": f"Bearer {access_token}",
                },
            )
        except httpx.HTTPError as error:
            raise AuthenticationUnavailableError() from error

        if response.status_code in {401, 403}:
            raise AuthenticationRequiredError()
        if response.is_error:
            raise AuthenticationUnavailableError()

        try:
            payload = response.json()
            user_id = uuid.UUID(str(payload["id"]))
        except (KeyError, TypeError, ValueError) as error:
            raise AuthenticationRequiredError() from error

        email = payload.get("email")
        return AuthenticatedUser(id=user_id, email=email if isinstance(email, str) else None)
