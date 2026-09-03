from fastapi.testclient import TestClient
from uuid import uuid4

from backend.app.auth import create_access_token, hash_password
from backend.app.database import create_user
from backend.app.main import app


client = TestClient(app)


def analyst_headers() -> dict[str, str]:
    user = create_user(f"analyst-{uuid4()}@example.com", "Test Analyst", hash_password("strong-test-password"), "analyst")
    return {"Authorization": f"Bearer {create_access_token(user)}"}


def test_phishing_email_analysis() -> None:
    response = client.post("/api/v1/analyze-email", json={
        "sender": "security-team@gmail.com",
        "text": "Urgent: your account is suspended. Verify your password immediately at https://example.com/login",
    })
    assert response.status_code == 200
    assert response.json()["verdict"] in {"suspicious", "malicious"}
    assert response.json()["risk_score"] >= 30


def test_network_anomaly_analysis() -> None:
    response = client.post("/api/v1/analyze-network", json={
        "failed_login_count": 12,
        "requests_per_minute": 300,
        "bytes_out": 70_000_000,
        "hour": 2,
        "is_new_country": True,
        "privileged_action": True,
    })
    assert response.status_code == 200
    assert response.json()["verdict"] == "malicious"


def test_incident_workflow() -> None:
    headers = analyst_headers()
    created = client.post("/api/v1/incidents", headers=headers, json={
        "title": "Repeated administrator login failures",
        "description": "Twelve failed logins from a new country.",
        "severity": "high",
        "source": "network-analyzer",
    })
    assert created.status_code == 201
    incident_id = created.json()["id"]

    updated = client.patch(f"/api/v1/incidents/{incident_id}", headers=headers, json={"status": "investigating"})
    assert updated.status_code == 200
    assert updated.json()["status"] == "investigating"
    assert any(item["id"] == incident_id for item in client.get("/api/v1/incidents").json())


def test_analytics_and_csv_report() -> None:
    analytics = client.get("/api/v1/analytics")
    report = client.get("/api/v1/reports/incidents.csv", headers=analyst_headers())

    assert analytics.status_code == 200
    assert {"url_verdicts", "event_verdicts", "incidents"} <= analytics.json().keys()
    assert report.status_code == 200
    assert report.headers["content-type"].startswith("text/csv")
    assert "severity,status,source" in report.text


def test_registration_login_and_viewer_permissions() -> None:
    email = f"viewer-{uuid4()}@example.com"
    registered = client.post("/api/v1/auth/register", json={"email": email, "name": "Demo Viewer", "password": "secure-demo-password"})
    assert registered.status_code == 201
    assert registered.json()["user"]["role"] == "viewer"
    token = registered.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    assert client.get("/api/v1/auth/me", headers=headers).status_code == 200
    denied = client.post("/api/v1/incidents", headers=headers, json={"title": "Viewer cannot create", "description": "This operation must be forbidden.", "severity": "low", "source": "test"})
    assert denied.status_code == 403
    assert client.post("/api/v1/auth/login", json={"email": email, "password": "secure-demo-password"}).status_code == 200


def test_protected_endpoint_requires_authentication() -> None:
    assert client.get("/api/v1/reports/incidents.csv").status_code == 401
