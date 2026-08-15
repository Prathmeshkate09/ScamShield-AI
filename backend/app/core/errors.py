from __future__ import annotations


class AppError(Exception):
    def __init__(self, message: str, status_code: int, code: str) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.code = code


class ProviderResponseError(AppError):
    def __init__(self) -> None:
        super().__init__("The AI provider returned an invalid analysis response.", 502, "invalid_provider_response")


class PersistenceUnavailableError(AppError):
    def __init__(self) -> None:
        super().__init__("Analysis history is unavailable until DATABASE_URL is configured.", 503, "persistence_unavailable")
