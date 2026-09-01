"""
CyberFlux — Backend Tests
"""

import pytest
from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


# ─── Health ───────────────────────────────────────────────────────────

def test_health():
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert "security_posture" in data
    posture = data["security_posture"]
    assert posture["monitoring_mode"] == "READ-ONLY"
    assert posture["return_path"] == "BLOCKED"
    assert posture["payload_decryption"] == "DISABLED"


def test_security_posture():
    response = client.get("/api/security-posture")
    assert response.status_code == 200
    data = response.json()
    assert data["traffic_direction"] == "UNIDIRECTIONAL"
    assert data["active_probing"] == "DISABLED"


# ─── Metrics ──────────────────────────────────────────────────────────

def test_metrics():
    response = client.get("/api/metrics")
    assert response.status_code == 200
    data = response.json()
    assert "events_per_sec" in data
    assert "detection_latency_ms" in data
    assert "system_health" in data


# ─── Flows ────────────────────────────────────────────────────────────

def test_flows():
    response = client.get("/api/flows?limit=10")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)


def test_flow_not_found():
    response = client.get("/api/flows/nonexistent")
    assert response.status_code == 404


# ─── Alerts ───────────────────────────────────────────────────────────

def test_alerts():
    response = client.get("/api/alerts?limit=10")
    assert response.status_code == 200
    assert isinstance(response.json(), list)


def test_alert_summary():
    response = client.get("/api/alerts/summary")
    assert response.status_code == 200
    data = response.json()
    assert "total_alerts" in data
    assert "critical_count" in data


# ─── Threats ──────────────────────────────────────────────────────────

def test_threats():
    response = client.get("/api/threats")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)


# ─── Simulation ──────────────────────────────────────────────────────

def test_simulation_status():
    response = client.get("/api/simulation/status")
    assert response.status_code == 200
    data = response.json()
    assert "state" in data


# ─── Detection Info ──────────────────────────────────────────────────

def test_detection_info():
    response = client.get("/api/detection/info")
    assert response.status_code == 200
    data = response.json()
    assert "detector_name" in data
    assert "RULE_BASED" in data["detector_type"]
