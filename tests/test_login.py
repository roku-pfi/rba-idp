"""IdP-2: password verify against seeded user + application (no PDP / session)."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from rba_contracts import LoginOutcome

from rba_idp.config import Settings
from rba_idp.main import create_app

LOGIN = {
    "email": "demo@example.com",
    "password": "demo-password",
    "application_id": "demo-banking-app",
    "ip_address": "203.0.113.10",
    "asn": "13335",
    "country": "AR",
    "device_type": "mobile",
    "os": "Android",
    "browser": "Chrome",
}


@pytest.fixture
def client() -> TestClient:
    settings = Settings(use_memory_db=True)
    app = create_app(settings)
    with TestClient(app) as test_client:
        yield test_client


def test_healthz(client: TestClient) -> None:
    assert client.get("/healthz").json() == {"status": "ok"}


def test_valid_credentials_authenticate_without_session_or_risk(client: TestClient) -> None:
    resp = client.post("/login", json=LOGIN)
    assert resp.status_code == 200
    body = resp.json()
    assert body["outcome"] == LoginOutcome.AUTHENTICATED.value
    assert body["user_id"] == "usr_demo"
    assert "session" not in body
    assert "action" not in body
    assert "risk_score" not in body
    assert "event_id" not in body
    assert "challenge_id" not in body


def test_email_is_case_insensitive(client: TestClient) -> None:
    payload = {**LOGIN, "email": "Demo@Example.COM"}
    resp = client.post("/login", json=payload)
    assert resp.status_code == 200
    assert resp.json()["outcome"] == LoginOutcome.AUTHENTICATED.value


def test_wrong_password_is_invalid_credentials(client: TestClient) -> None:
    payload = {**LOGIN, "password": "wrong-password"}
    resp = client.post("/login", json=payload)
    assert resp.status_code == 200
    body = resp.json()
    assert body == {"outcome": LoginOutcome.INVALID_CREDENTIALS.value}


def test_unknown_user_is_invalid_credentials(client: TestClient) -> None:
    payload = {**LOGIN, "email": "nobody@example.com"}
    resp = client.post("/login", json=payload)
    assert resp.status_code == 200
    body = resp.json()
    assert body == {"outcome": LoginOutcome.INVALID_CREDENTIALS.value}
    assert "user_id" not in body


def test_unknown_application_is_400(client: TestClient) -> None:
    payload = {**LOGIN, "application_id": "not-a-registered-app"}
    resp = client.post("/login", json=payload)
    assert resp.status_code == 400
    assert resp.json()["detail"] == "unknown application"


def test_mfa_and_session_are_not_implemented_yet(client: TestClient) -> None:
    assert client.post("/mfa/verify", json={"challenge_id": "7c2e1b3d-4a6f-9c8e-2d1b-3a6f9c8e4f9a", "code": "000000"}).status_code == 404
    assert client.get("/session").status_code == 404
    assert client.post("/logout").status_code == 404
