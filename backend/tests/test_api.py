from datetime import UTC, datetime
from uuid import UUID

from fastapi.testclient import TestClient

from app.api.analyze import optional_repository
from app.config import Settings
from app.dependencies import get_analyzer
from app.main import create_app
from app.schemas.analysis import AnalysisResponse
from app.services.ai_service import ProviderResult
from app.services.scam_analyzer import ScamAnalyzer


def create_test_client() -> TestClient:
    application = create_app(Settings(app_env="test", ai_provider="demo"))
    return TestClient(application)


def test_health_reports_demo_mode() -> None:
    with create_test_client() as client:
        response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["meta"]["mode"] == "demo"


def test_text_analysis_returns_structured_result() -> None:
    payload = {"text": "Your bank account will be blocked in 30 minutes. Complete KYC using this link and enter your OTP."}
    with create_test_client() as client:
        response = client.post("/api/v1/analyze/text", json=payload)
    body = response.json()
    assert response.status_code == 200
    assert body["data"]["risk_score"] >= 80
    assert body["data"]["risk_level"] == "CRITICAL"
    assert body["meta"]["mode"] == "demo"


def test_empty_text_is_rejected() -> None:
    with create_test_client() as client:
        response = client.post("/api/v1/analyze/text", json={"text": "   "})
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_error"


def test_invalid_url_is_rejected() -> None:
    with create_test_client() as client:
        response = client.post("/api/v1/analyze/url", json={"url": "file:///etc/passwd"})
    assert response.status_code == 422


def test_url_analysis_combines_structural_signals() -> None:
    with create_test_client() as client:
        response = client.post("/api/v1/analyze/url", json={"url": "http://198.51.100.1/login?otp=123456"})
    body = response.json()
    assert response.status_code == 200
    assert body["data"]["risk_score"] >= 60
    assert "Uses an IP address instead of a recognizable domain" in body["data"]["red_flags"]


def test_image_rejects_executable_content() -> None:
    with create_test_client() as client:
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
    with create_test_client() as client:
        client.app.dependency_overrides[get_analyzer] = lambda: analyzer
        response = client.post("/api/v1/analyze/text", json={"text": "hello"})
    assert response.status_code == 502
    assert response.json()["error"]["code"] == "invalid_provider_response"


def test_analysis_is_persisted_when_repository_is_available() -> None:
    class FakeRepository:
        def __init__(self) -> None:
            self.saved: list[AnalysisResponse] = []

        async def save(self, analysis_id, assessment, input_type, input_text=None, file_path=None):
            response = AnalysisResponse(
                id=analysis_id,
                input_type=input_type,
                created_at=datetime.now(UTC),
                **assessment.model_dump(),
            )
            self.saved.append(response)
            return response, 1

    repository = FakeRepository()
    with create_test_client() as client:
        client.app.dependency_overrides[optional_repository] = lambda: repository
        response = client.post("/api/v1/analyze/text", json={"text": "Please confirm the delivery time tomorrow."})
    body = response.json()
    assert response.status_code == 200
    assert body["meta"]["persisted"] is True
    assert len(repository.saved) == 1
    assert isinstance(repository.saved[0].id, UUID)


def test_history_requires_configured_database() -> None:
    with create_test_client() as client:
        response = client.get("/api/v1/analyses")
    assert response.status_code == 503
