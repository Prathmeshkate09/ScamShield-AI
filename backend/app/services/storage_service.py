from __future__ import annotations

import asyncio
import uuid
from uuid import UUID

from app.config import Settings
from app.core.errors import AppError


class StorageService:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    async def upload_image(self, content: bytes, content_type: str, extension: str, user_id: UUID) -> str:
        if not self.settings.storage_configured:
            raise AppError("Screenshot uploads require SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY.", 503, "storage_not_configured")
        path = f"users/{user_id}/screenshots/{uuid.uuid4()}.{extension}"

        def upload() -> None:
            from supabase import create_client

            client = create_client(self.settings.supabase_url or "", self.settings.supabase_service_role_key or "")
            try:
                client.storage.get_bucket(self.settings.supabase_storage_bucket)
            except Exception:
                client.storage.create_bucket(self.settings.supabase_storage_bucket, options={"public": False})
            client.storage.from_(self.settings.supabase_storage_bucket).upload(
                path=path,
                file=content,
                file_options={"content-type": content_type, "upsert": "false"},
            )

        try:
            await asyncio.to_thread(upload)
        except Exception as error:
            raise AppError("The screenshot could not be stored securely.", 502, "storage_upload_failed") from error
        return path
