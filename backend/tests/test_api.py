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
    assert response.json()["id"] > 0


def test_scan_history_and_summary_endpoints() -> None:
    client.post("/api/v1/analyze-url", json={"url": "http://192.168.1.10/login"})
    history = client.get("/api/v1/scans?limit=2")
    summary = client.get("/api/v1/summary")

    assert history.status_code == 200
    assert len(history.json()) <= 2
    assert summary.status_code == 200
    assert summary.json()["scanned"] >= 1
    assert summary.json()["threats"] >= 1


def test_invalid_url_returns_validation_error() -> None:
    response = client.post("/api/v1/analyze-url", json={"url": "http://"})
    assert response.status_code == 422


def test_threat_intelligence_has_safe_unconfigured_fallback(monkeypatch) -> None:
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
    response = client.post("/api/v1/threat-intelligence", json={"url": "https://example.com"})
    assert response.status_code == 200
    assert response.json()["status"] == "not_configured"
