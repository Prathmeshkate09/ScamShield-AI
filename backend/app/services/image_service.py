from __future__ import annotations

from io import BytesIO

from PIL import Image, UnidentifiedImageError

from app.core.errors import AppError


ALLOWED_IMAGE_TYPES = {
    "image/png": "PNG",
    "image/jpeg": "JPEG",
    "image/webp": "WEBP",
}


def validate_image(content: bytes, content_type: str | None, filename: str | None, max_bytes: int) -> tuple[str, str]:
    if not content:
        raise AppError("Upload an image file to analyze.", 400, "empty_file")
    if len(content) > max_bytes:
        raise AppError(f"Images must be {max_bytes // (1024 * 1024)} MB or smaller.", 413, "file_too_large")
    if content_type not in ALLOWED_IMAGE_TYPES:
        raise AppError("Only PNG, JPG, JPEG, and WEBP images are supported.", 415, "unsupported_file_type")
    extension = (filename or "").rsplit(".", 1)[-1].lower()
    if extension not in {"png", "jpg", "jpeg", "webp"}:
        raise AppError("The file extension must be PNG, JPG, JPEG, or WEBP.", 415, "invalid_file_extension")
    try:
        with Image.open(BytesIO(content)) as image:
            actual_format = image.format
            image.verify()
    except (SyntaxError, UnidentifiedImageError, OSError, ValueError) as error:
        raise AppError("The upload is not a valid image.", 415, "invalid_image") from error
    if actual_format != ALLOWED_IMAGE_TYPES[content_type]:
        raise AppError("The image content does not match its declared type.", 415, "image_type_mismatch")
    return content_type, extension
