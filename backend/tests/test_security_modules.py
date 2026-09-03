from fastapi.testclient import TestClient

from backend.app.main import app


client = TestClient(app)


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
    created = client.post("/api/v1/incidents", json={
        "title": "Repeated administrator login failures",
        "description": "Twelve failed logins from a new country.",
        "severity": "high",
        "source": "network-analyzer",
    })
    assert created.status_code == 201
    incident_id = created.json()["id"]

    updated = client.patch(f"/api/v1/incidents/{incident_id}", json={"status": "investigating"})
    assert updated.status_code == 200
    assert updated.json()["status"] == "investigating"
    assert any(item["id"] == incident_id for item in client.get("/api/v1/incidents").json())
