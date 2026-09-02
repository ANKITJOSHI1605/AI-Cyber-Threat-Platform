from fastapi.testclient import TestClient

from backend.app.main import app


client = TestClient(app)


def test_health_endpoint() -> None:
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_analyze_url_endpoint() -> None:
    response = client.post("/api/v1/analyze-url", json={"url": "https://example.com"})
    assert response.status_code == 200
    assert response.json()["verdict"] == "low_risk"


def test_invalid_url_returns_validation_error() -> None:
    response = client.post("/api/v1/analyze-url", json={"url": "http://"})
    assert response.status_code == 422
