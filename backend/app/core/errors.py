from __future__ import annotations


class AppError(Exception):
    def __init__(self, message: str, status_code: int, code: str, headers: dict[str, str] | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.code = code
        self.headers = headers or {}


class ProviderResponseError(AppError):
    def __init__(self) -> None:
        super().__init__("The AI provider returned an invalid analysis response.", 502, "invalid_provider_response")


class ProviderUnavailableError(AppError):
    def __init__(self) -> None:
        super().__init__(
            "The AI provider is temporarily unavailable. Please try again in a moment.",
            503,
            "provider_unavailable",
            {"Retry-After": "15"},
        )


class PersistenceUnavailableError(AppError):
    def __init__(self) -> None:
        super().__init__("Analysis history is unavailable until DATABASE_URL is configured.", 503, "persistence_unavailable")


class AuthenticationRequiredError(AppError):
    def __init__(self) -> None:
        super().__init__("A valid sign-in session is required.", 401, "authentication_required", {"WWW-Authenticate": "Bearer"})


class AuthenticationUnavailableError(AppError):
    def __init__(self) -> None:
        super().__init__("Authentication verification is temporarily unavailable.", 503, "authentication_unavailable")


class RateLimitExceededError(AppError):
    def __init__(self, retry_after: int) -> None:
        super().__init__("Too many requests. Please try again shortly.", 429, "rate_limit_exceeded", {"Retry-After": str(max(retry_after, 1))})


class RateLimiterUnavailableError(AppError):
    def __init__(self) -> None:
        super().__init__("Request protection is temporarily unavailable. Please try again shortly.", 503, "rate_limiter_unavailable")
