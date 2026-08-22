import asyncio
from datetime import UTC, datetime
from io import BytesIO
from uuid import UUID

import pytest
from fastapi.testclient import TestClient
from PIL import Image
from sqlalchemy.exc import OperationalError

from app.config import Settings
from app.core.errors import (
    AccountUnavailableError,
    AuthenticationRequiredError,
    DatabaseUnavailableError,
    EmailVerificationRequiredError,
    RateLimiterUnavailableError,
    RateLimitExceededError,
)
from app.dependencies import get_analyzer, get_auth_service, get_current_user, get_repository, get_storage_service
from app.main import create_app
from app.repositories.analysis_repository import AnalysisRepository
from app.schemas.analysis import AnalysisResponse, ScamAssessment
from app.services.ai_service import GeminiProvider, ProviderResult
from app.services.auth_service import AuthenticatedUser
from app.services.rate_limiter import RateLimitService
from app.services.scam_analyzer import ScamAnalyzer

TEST_USER = AuthenticatedUser(id=UUID("00000000-0000-4000-8000-000000000001"), email="tester@example.com")
OTHER_USER = AuthenticatedUser(id=UUID("00000000-0000-4000-8000-000000000002"), email="other@example.com")


class FakeRepository:
    def __init__(self) -> None:
        self.saved: list[tuple[UUID, AnalysisResponse]] = []

    async def save(self, analysis_id, user_id, assessment, input_type, input_text=None, file_path=None):
        response = AnalysisResponse(
            id=analysis_id,
            input_type=input_type,
            created_at=datetime.now(UTC),
            **assessment.model_dump(),
        )
        self.saved.append((user_id, response))
        return response, 1

    async def list(self, user_id, page, page_size):
        records = [record for owner, record in self.saved if owner == user_id]
        return type("Page", (), {"items": records, "total": len(records)})()

    async def get(self, analysis_id, user_id):
        return next((record for owner, record in self.saved if owner == user_id and record.id == analysis_id), None)

    async def stats(self, user_id):
        records = [record for owner, record in self.saved if owner == user_id]
        return type(
            "Stats",
            (),
            {
                "total_analyses": len(records),
                "high_risk_detected": sum(record.risk_level in {"HIGH", "CRITICAL"} for record in records),
                "critical_scams": sum(record.risk_level == "CRITICAL" for record in records),
                "most_common_scam_type": records[0].scam_type if records else None,
            },
        )()


def create_test_client(repository: FakeRepository | None = None, user: AuthenticatedUser | None = TEST_USER) -> TestClient:
    application = create_app(Settings(app_env="test", ai_provider="demo", database_url=None, rate_limit_enabled=False))
    if user is not None:
        application.dependency_overrides[get_current_user] = lambda: user
    if repository is not None:
        application.dependency_overrides[get_repository] = lambda: repository
    return TestClient(application)


def test_health_reports_demo_mode() -> None:
    with create_test_client() as client:
        response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["meta"]["mode"] == "demo"
    assert response.json()["data"]["database"] == "not_configured"
    assert response.json()["data"]["status"] == "degraded"


def test_database_connection_failure_returns_controlled_error() -> None:
    class UnavailableRepository(FakeRepository):
        async def save(self, analysis_id, user_id, assessment, input_type, input_text=None, file_path=None):
            raise DatabaseUnavailableError()

    with create_test_client(UnavailableRepository()) as client:
        response = client.post("/api/v1/analyze/text", json={"text": "Please confirm the delivery time tomorrow."})

    assert response.status_code == 503
    assert response.headers["Retry-After"] == "15"
    assert response.json()["error"]["code"] == "database_unavailable"


def test_repository_maps_connection_refusal_to_controlled_error() -> None:
    assessment = ScamAssessment(
        risk_score=10,
        risk_level="SAFE",
        scam_type="No Clear Scam Pattern",
        confidence=0.8,
        red_flags=[],
        explanation="No clear scam pattern was detected.",
        recommendation=["Verify unexpected requests through an official channel."],
    )

    class FailingSession:
        rolled_back = False

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc_value, traceback):
            return False

        def add(self, record):
            return None

        async def commit(self):
            raise OperationalError("COMMIT", {}, ConnectionRefusedError("refused"))

        async def rollback(self):
            self.rolled_back = True

    failing_session = FailingSession()
    repository = AnalysisRepository(lambda: failing_session)  # type: ignore[arg-type]

    with pytest.raises(DatabaseUnavailableError):
        asyncio.run(repository.save(UUID("00000000-0000-4000-8000-000000000003"), TEST_USER.id, assessment, "text"))

    assert failing_session.rolled_back is True


def test_text_analysis_returns_structured_result() -> None:
    payload = {"text": "Your bank account will be blocked in 30 minutes. Complete KYC using this link and enter your OTP."}
    with create_test_client(FakeRepository()) as client:
        response = client.post("/api/v1/analyze/text", json=payload)
    body = response.json()
    assert response.status_code == 200
    assert body["data"]["risk_score"] >= 80
    assert body["data"]["risk_level"] == "CRITICAL"
    assert body["meta"]["mode"] == "demo"


def test_empty_text_is_rejected() -> None:
    with create_test_client(FakeRepository()) as client:
        response = client.post("/api/v1/analyze/text", json={"text": "   "})
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_error"


def test_invalid_url_is_rejected() -> None:
    with create_test_client(FakeRepository()) as client:
        response = client.post("/api/v1/analyze/url", json={"url": "file:///etc/passwd"})
    assert response.status_code == 422


def test_url_analysis_combines_structural_signals() -> None:
    with create_test_client(FakeRepository()) as client:
        response = client.post("/api/v1/analyze/url", json={"url": "http://198.51.100.1/login?otp=123456"})
    body = response.json()
    assert response.status_code == 200
    assert body["data"]["risk_score"] >= 60
    assert "Uses an IP address instead of a recognizable domain" in body["data"]["red_flags"]


def test_image_rejects_executable_content() -> None:
    with create_test_client(FakeRepository()) as client:
        response = client.post("/api/v1/analyze/image", files={"file": ("payload.exe", b"not an image", "application/octet-stream")})
    assert response.status_code == 415


def test_malformed_provider_response_is_controlled() -> None:
    class MalformedProvider:
        name = "test"
        mode = "live"

        async def analyze_text(self, content: str, input_type: str, context: str | None = None) -> ProviderResult:
            return ProviderResult(raw_json="not-json", latency_ms=1)

        async def analyze_image(self, content: bytes, content_type: str) -> ProviderResult:
            return ProviderResult(raw_json="not-json", latency_ms=1)

    analyzer = ScamAnalyzer(MalformedProvider())
    with create_test_client(FakeRepository()) as client:
        client.app.dependency_overrides[get_analyzer] = lambda: analyzer
        response = client.post("/api/v1/analyze/text", json={"text": "hello"})
    assert response.status_code == 502
    assert response.json()["error"]["code"] == "invalid_provider_response"


def test_provider_exception_is_controlled() -> None:
    class FailingProvider:
        name = "test"
        mode = "live"

        async def analyze_text(self, content: str, input_type: str, context: str | None = None) -> ProviderResult:
            raise RuntimeError("provider failed")

        async def analyze_image(self, content: bytes, content_type: str) -> ProviderResult:
            raise RuntimeError("provider failed")

    analyzer = ScamAnalyzer(FailingProvider())
    with create_test_client(FakeRepository()) as client:
        client.app.dependency_overrides[get_analyzer] = lambda: analyzer
        response = client.post("/api/v1/analyze/text", json={"text": "hello"})
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "provider_unavailable"


def test_gemini_uses_supported_structured_output_configuration() -> None:
    config = GeminiProvider._json_config()
    assert config == {"response_mime_type": "application/json", "response_schema": ScamAssessment}


def test_gemini_retries_a_transient_provider_error(monkeypatch) -> None:
    class TransientError(Exception):
        code = 503

    assessment = ScamAssessment(
        risk_score=8,
        risk_level="SAFE",
        scam_type="No Clear Scam Pattern",
        confidence=0.72,
        red_flags=[],
        explanation="No clear scam pattern.",
        recommendation=["Verify unexpected requests through a trusted channel."],
    )

    class FakeModels:
        def __init__(self) -> None:
            self.calls = 0

        async def generate_content(self, **kwargs):
            self.calls += 1
            if self.calls == 1:
                raise TransientError()
            return type("Response", (), {"text": assessment.model_dump_json()})()

    models = FakeModels()
    provider = GeminiProvider.__new__(GeminiProvider)
    provider.client = type("Client", (), {"aio": type("AsyncClient", (), {"models": models})()})()
    provider.model = "test-model"
    monkeypatch.setattr(GeminiProvider, "_RETRY_DELAY_SECONDS", 0)

    result = asyncio.run(provider.analyze_text("Check this message", "text"))

    assert models.calls == 2
    assert result.raw_json == assessment.model_dump_json()


def test_analysis_is_persisted_when_repository_is_available() -> None:
    repository = FakeRepository()
    with create_test_client(repository) as client:
        response = client.post("/api/v1/analyze/text", json={"text": "Please confirm the delivery time tomorrow."})
    body = response.json()
    assert response.status_code == 200
    assert body["meta"]["persisted"] is True
    assert len(repository.saved) == 1
    assert repository.saved[0][0] == TEST_USER.id
    assert isinstance(repository.saved[0][1].id, UUID)


def test_history_requires_configured_database() -> None:
    with create_test_client(user=TEST_USER) as client:
        response = client.get("/api/v1/analyses")
    assert response.status_code == 503


def test_missing_token_is_rejected() -> None:
    with create_test_client(FakeRepository(), user=None) as client:
        response = client.post("/api/v1/analyze/text", json={"text": "Check this message"})
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "authentication_required"


def test_invalid_token_is_rejected() -> None:
    class InvalidAuthService:
        async def get_user(self, access_token):
            raise AuthenticationRequiredError()

    application = create_app(Settings(app_env="test", ai_provider="demo", database_url=None))
    application.dependency_overrides[get_auth_service] = lambda: InvalidAuthService()
    application.dependency_overrides[get_repository] = lambda: FakeRepository()
    with TestClient(application) as client:
        response = client.post("/api/v1/analyze/text", headers={"Authorization": "Bearer invalid"}, json={"text": "Check this message"})
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "authentication_required"


@pytest.mark.parametrize(
    "auth_error,expected_code",
    [
        (EmailVerificationRequiredError(), "email_verification_required"),
        (AccountUnavailableError(), "account_unavailable"),
    ],
)
def test_unverified_or_disabled_accounts_receive_controlled_errors(auth_error, expected_code: str) -> None:
    class RestrictedAuthService:
        async def get_user(self, access_token):
            raise auth_error

    application = create_app(Settings(app_env="test", ai_provider="demo", database_url=None))
    application.dependency_overrides[get_auth_service] = lambda: RestrictedAuthService()
    application.dependency_overrides[get_repository] = lambda: FakeRepository()
    with TestClient(application) as client:
        response = client.post(
            "/api/v1/analyze/text",
            headers={"Authorization": "Bearer restricted"},
            json={"text": "Check this message"},
        )

    assert response.status_code == 403
    assert response.json()["error"]["code"] == expected_code


def test_user_history_and_detail_are_isolated() -> None:
    repository = FakeRepository()
    with create_test_client(repository, TEST_USER) as client:
        created = client.post("/api/v1/analyze/text", json={"text": "Confirm the delivery time tomorrow."}).json()["data"]
        client.app.dependency_overrides[get_current_user] = lambda: OTHER_USER
        history = client.get("/api/v1/analyses")
        detail = client.get(f"/api/v1/analyses/{created['id']}")
    assert history.status_code == 200
    assert history.json()["data"]["total"] == 0
    assert detail.status_code == 404


def test_image_storage_receives_user_scoped_owner() -> None:
    class CapturingStorage:
        def __init__(self) -> None:
            self.user_id: UUID | None = None

        async def upload_image(self, content, content_type, extension, user_id):
            self.user_id = user_id
            return f"users/{user_id}/screenshots/example.{extension}"

    storage = CapturingStorage()
    image_buffer = BytesIO()
    Image.new("RGB", (1, 1), "black").save(image_buffer, format="PNG")
    png = image_buffer.getvalue()
    with create_test_client(FakeRepository()) as client:
        client.app.dependency_overrides[get_storage_service] = lambda: storage
        response = client.post("/api/v1/analyze/image", files={"file": ("message.png", png, "image/png")})
    assert response.status_code == 503
    assert storage.user_id == TEST_USER.id


class FakeCounterStore:
    def __init__(self, fail: bool = False) -> None:
        self.fail = fail
        self.counts: dict[str, int] = {}

    async def ping(self):
        if self.fail:
            raise RuntimeError("unavailable")
        return "PONG"

    async def eval(self, script, keys, args):
        if self.fail:
            raise RuntimeError("unavailable")
        key = keys[0]
        self.counts[key] = self.counts.get(key, 0) + 1
        return [self.counts[key], int(args[0])]


@pytest.mark.asyncio
async def test_rate_limit_rejects_after_threshold_and_isolates_users() -> None:
    settings = Settings(
        app_env="test",
        rate_limit_enabled=True,
        upstash_redis_rest_url="https://example.upstash.io",
        upstash_redis_rest_token="token",
        rate_limit_user_per_window=2,
    )
    limiter = RateLimitService(settings, FakeCounterStore())
    await limiter.initialize()
    await limiter.enforce_user(TEST_USER.id)
    await limiter.enforce_user(TEST_USER.id)
    await limiter.enforce_user(OTHER_USER.id)
    with pytest.raises(RateLimitExceededError) as error:
        await limiter.enforce_user(TEST_USER.id)
    assert error.value.headers["Retry-After"] == "60"


@pytest.mark.asyncio
async def test_limiter_outage_fails_closed() -> None:
    settings = Settings(
        app_env="test",
        rate_limit_enabled=True,
        upstash_redis_rest_url="https://example.upstash.io",
        upstash_redis_rest_token="token",
    )
    limiter = RateLimitService(settings, FakeCounterStore(fail=True))
    await limiter.initialize()
    assert limiter.state == "degraded"
    with pytest.raises(RateLimiterUnavailableError):
        await limiter.enforce_user(TEST_USER.id)


def test_api_rate_limit_returns_retry_after() -> None:
    settings = Settings(
        app_env="test",
        ai_provider="demo",
        rate_limit_enabled=True,
        rate_limit_user_per_window=20,
        rate_limit_scan_per_window=1,
    )
    repository = FakeRepository()
    limiter = RateLimitService(settings, FakeCounterStore())
    asyncio.run(limiter.initialize())
    application = create_app(settings)
    application.dependency_overrides[get_current_user] = lambda: TEST_USER
    application.dependency_overrides[get_repository] = lambda: repository
    with TestClient(application) as client:
        client.app.state.rate_limiter = limiter
        first = client.post("/api/v1/analyze/text", json={"text": "Please confirm the delivery time tomorrow."})
        second = client.post("/api/v1/analyze/text", json={"text": "Please confirm the delivery time tomorrow."})
    assert first.status_code == 200
    assert second.status_code == 429
    assert second.headers["Retry-After"] == "60"
    assert second.json()["error"]["code"] == "rate_limit_exceeded"


def test_protected_api_fails_closed_when_limiter_is_unavailable() -> None:
    settings = Settings(app_env="test", ai_provider="demo", rate_limit_enabled=True)
    repository = FakeRepository()
    limiter = RateLimitService(settings, FakeCounterStore(fail=True))
    asyncio.run(limiter.initialize())
    application = create_app(settings)
    application.dependency_overrides[get_current_user] = lambda: TEST_USER
    application.dependency_overrides[get_repository] = lambda: repository
    with TestClient(application) as client:
        client.app.state.rate_limiter = limiter
        response = client.post("/api/v1/analyze/text", json={"text": "Please confirm the delivery time tomorrow."})
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "rate_limiter_unavailable"
