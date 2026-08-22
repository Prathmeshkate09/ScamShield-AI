from __future__ import annotations

import base64
import binascii
import json
import uuid
from dataclasses import dataclass

import httpx

from app.config import Settings
from app.core.errors import (
    AccountUnavailableError,
    AuthenticationRequiredError,
    AuthenticationUnavailableError,
    EmailVerificationRequiredError,
)


@dataclass(frozen=True)
class AuthenticatedUser:
    id: uuid.UUID
    email: str | None
    session_id: uuid.UUID | None = None


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

        if response.status_code == 401:
            raise AuthenticationRequiredError()
        if response.status_code == 403:
            raise AccountUnavailableError()
        if response.is_error:
            raise AuthenticationUnavailableError()

        try:
            payload = response.json()
            user_id = uuid.UUID(str(payload["id"]))
        except (KeyError, TypeError, ValueError) as error:
            raise AuthenticationRequiredError() from error

        if payload.get("is_anonymous") is True or payload.get("banned_until"):
            raise AccountUnavailableError()

        email = payload.get("email")
        if not isinstance(email, str) or not email.strip() or not payload.get("email_confirmed_at"):
            raise EmailVerificationRequiredError()
        normalized_email = email.strip().lower()
        return AuthenticatedUser(id=user_id, email=normalized_email, session_id=self._session_id(access_token, user_id))

    @staticmethod
    def _session_id(access_token: str, user_id: uuid.UUID) -> uuid.UUID | None:
        try:
            encoded_payload = access_token.split(".")[1]
            padding = "=" * (-len(encoded_payload) % 4)
            claims = json.loads(base64.urlsafe_b64decode(encoded_payload + padding))
            if claims.get("sub") != str(user_id):
                return None
            return uuid.UUID(str(claims["session_id"]))
        except (IndexError, KeyError, TypeError, ValueError, binascii.Error, json.JSONDecodeError):
            return None
