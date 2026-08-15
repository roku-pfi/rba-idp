"""IdP-3: password verify then PDP enforce (no session / MFA challenge)."""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

import pytest
from fastapi.testclient import TestClient
from rba_contracts import (
    Action,
    LoginOutcome,
    Reason,
    RiskEvaluateRequest,
    RiskEvaluateResponse,
    RiskLevel,
)

from rba_idp.config import Settings
from rba_idp.main import create_app
from rba_idp.pdp import PdpUnavailable

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

REASON = Reason(
    code="signal_novel",
    signal="device_type",
    contribution=1.8,
    detail="device_type not previously seen for this user",
)


class StubPdp:
    def __init__(
        self,
        *,
        action: Action = Action.ALLOW,
        risk_score: float = 0.12,
        risk_level: RiskLevel = RiskLevel.LOW,
        reasons: list[Reason] | None = None,
    ) -> None:
        self.action = action
        self.risk_score = risk_score
        self.risk_level = risk_level
        self.reasons = reasons if reasons is not None else [REASON]
        self.calls: list[RiskEvaluateRequest] = []

    def evaluate(self, request: RiskEvaluateRequest) -> RiskEvaluateResponse:
        self.calls.append(request)
        return RiskEvaluateResponse(
            event_id=request.event_id,
            risk_score=self.risk_score,
            risk_level=self.risk_level,
            action=self.action,
            reasons=self.reasons,
            model_version="freeman-0.1.0",
            policy_version="1.0.0",
            feature_schema_version="1.0.0",
            fallback=False,
            scored_at=datetime.now(timezone.utc),
        )


class FailingPdp:
    def evaluate(self, request: RiskEvaluateRequest) -> RiskEvaluateResponse:
        raise PdpUnavailable("connection refused")


@pytest.fixture
def pdp() -> StubPdp:
    return StubPdp()


@pytest.fixture
def client(pdp: StubPdp) -> TestClient:
    settings = Settings(use_memory_db=True)
    app = create_app(settings, pdp_client=pdp)
    with TestClient(app) as test_client:
        yield test_client


def _client_for(pdp_client) -> TestClient:
    settings = Settings(use_memory_db=True)
    return TestClient(create_app(settings, pdp_client=pdp_client))


def test_healthz(client: TestClient) -> None:
    assert client.get("/healthz").json() == {"status": "ok"}


def test_valid_credentials_return_pdp_decision(client: TestClient, pdp: StubPdp) -> None:
    resp = client.post("/login", json=LOGIN)
    assert resp.status_code == 200
    body = resp.json()
    assert body["outcome"] == LoginOutcome.AUTHENTICATED.value
    assert body["user_id"] == "usr_demo"
    assert body["action"] == Action.ALLOW.value
    assert body["risk_score"] == 0.12
    assert body["risk_level"] == RiskLevel.LOW.value
    assert body["reasons"] == [REASON.model_dump(mode="json")]
    UUID(body["event_id"])
    assert "session" not in body
    assert "challenge_id" not in body
    assert len(pdp.calls) == 1
    call = pdp.calls[0]
    assert call.user_id == "usr_demo"
    assert call.application_id == "demo-banking-app"
    assert call.ip_address == "203.0.113.10"
    assert call.asn == "13335"
    assert call.country == "AR"
    assert call.device_type == "mobile"
    assert call.os == "Android"
    assert call.browser == "Chrome"
    assert call.login_successful is True
    assert call.timestamp.tzinfo is not None


def test_email_is_case_insensitive(client: TestClient, pdp: StubPdp) -> None:
    payload = {**LOGIN, "email": "Demo@Example.COM"}
    resp = client.post("/login", json=payload)
    assert resp.status_code == 200
    assert resp.json()["outcome"] == LoginOutcome.AUTHENTICATED.value
    assert len(pdp.calls) == 1


@pytest.mark.parametrize(
    ("action", "outcome", "level", "score"),
    [
        (Action.ALLOW, LoginOutcome.AUTHENTICATED, RiskLevel.LOW, 0.12),
        (Action.REQUIRE_MFA, LoginOutcome.MFA_REQUIRED, RiskLevel.MEDIUM, 0.61),
        (Action.REAUTHENTICATE, LoginOutcome.REAUTH_REQUIRED, RiskLevel.HIGH, 0.82),
        (Action.BLOCK, LoginOutcome.BLOCKED, RiskLevel.CRITICAL, 0.97),
    ],
)
def test_pdp_action_maps_to_login_outcome(
    action: Action,
    outcome: LoginOutcome,
    level: RiskLevel,
    score: float,
) -> None:
    pdp = StubPdp(action=action, risk_score=score, risk_level=level)
    with _client_for(pdp) as client:
        resp = client.post("/login", json=LOGIN)
    assert resp.status_code == 200
    body = resp.json()
    assert body["outcome"] == outcome.value
    assert body["action"] == action.value
    assert body["risk_score"] == score
    assert body["risk_level"] == level.value
    assert body["user_id"] == "usr_demo"
    assert "session" not in body
    assert "challenge_id" not in body


def test_wrong_password_is_invalid_credentials_without_pdp(
    client: TestClient, pdp: StubPdp
) -> None:
    payload = {**LOGIN, "password": "wrong-password"}
    resp = client.post("/login", json=payload)
    assert resp.status_code == 200
    assert resp.json() == {"outcome": LoginOutcome.INVALID_CREDENTIALS.value}
    assert pdp.calls == []


def test_unknown_user_is_invalid_credentials_without_pdp(
    client: TestClient, pdp: StubPdp
) -> None:
    payload = {**LOGIN, "email": "nobody@example.com"}
    resp = client.post("/login", json=payload)
    assert resp.status_code == 200
    body = resp.json()
    assert body == {"outcome": LoginOutcome.INVALID_CREDENTIALS.value}
    assert "user_id" not in body
    assert pdp.calls == []


def test_unknown_application_is_400_without_pdp(client: TestClient, pdp: StubPdp) -> None:
    payload = {**LOGIN, "application_id": "not-a-registered-app"}
    resp = client.post("/login", json=payload)
    assert resp.status_code == 400
    assert resp.json()["detail"] == "unknown application"
    assert pdp.calls == []


def test_pdp_unavailable_is_503() -> None:
    with _client_for(FailingPdp()) as client:
        resp = client.post("/login", json=LOGIN)
    assert resp.status_code == 503
    assert resp.json()["detail"] == "PDP unavailable"


def test_password_never_reaches_the_pdp(client: TestClient, pdp: StubPdp) -> None:
    client.post("/login", json=LOGIN)
    dumped = pdp.calls[0].model_dump()
    assert "password" not in dumped
    assert "email" not in dumped


def test_mfa_and_session_are_not_implemented_yet(client: TestClient) -> None:
    assert client.post(
        "/mfa/verify",
        json={"challenge_id": "7c2e1b3d-4a6f-9c8e-2d1b-3a6f9c8e4f9a", "code": "000000"},
    ).status_code == 404
    assert client.get("/session").status_code == 404
    assert client.post("/logout").status_code == 404
