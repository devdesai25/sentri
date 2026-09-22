from fastapi.testclient import TestClient
from app.main import app

def test_health_check():
    client = TestClient(app)
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}

def test_root_endpoint():
    client = TestClient(app)
    response = client.get("/api/v1/")
    assert response.status_code == 200
    data = response.json()
    assert "message" in data and "Sentri" in data["message"]
    assert data["status"] == "operational"

def test_list_events():
    client = TestClient(app)
    response = client.get("/api/v1/ssh/events")
    assert response.status_code == 200
    assert isinstance(response.json(), list)

def test_post_events_validation():
    client = TestClient(app)
    response = client.post("/api/v1/ssh/events", json={})
    assert response.status_code == 422  # Unprocessable Entity due to missing required fields

def test_commands_risk_assessment():
    client = TestClient(app)
    payload = {
        "command": "ls",
        "arguments": "-l",
        "username": "testuser",
        "working_directory": "/home/testuser"
    }
    response = client.post("/api/v1/commands/risk-assessment", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert "risk_level" in data
    assert "reason" in data

def test_commands_telegram_test():
    client = TestClient(app)
    response = client.post("/api/v1/commands/telegram-test")
    assert response.status_code == 200
    data = response.json()
    assert "status" in data
    assert "results" in data or "message" in data

def test_commands_risk_assessment_missing_fields():
    client = TestClient(app)
    # Missing required 'command' and 'username'
    payload = {
        "arguments": "-l"
    }
    response = client.post("/api/v1/commands/risk-assessment", json=payload)
    assert response.status_code == 422

def test_commands_risk_assessment_high_risk():
    client = TestClient(app)
    payload = {
        "command": "rm",
        "arguments": "-rf /",
        "username": "root",
        "working_directory": "/"
    }
    response = client.post("/api/v1/commands/risk-assessment", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert "risk_level" in data
    assert data["risk_level"] in ["critical", "high", "medium", "low", "minimal"]
    assert "reason" in data

def test_commands_explain():
    client = TestClient(app)
    payload = {
        "command": "ls",
        "arguments": "-l",
        "username": "testuser",
        "working_directory": "/home/testuser"
    }
    response = client.post("/api/v1/commands/explain", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert "command" in data
    assert "summary" in data
    assert "sections" in data
    assert "risk_level" in data