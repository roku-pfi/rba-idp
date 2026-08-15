"""Shared IdP test helpers (not pytest fixtures)."""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi.testclient import TestClient
from rba_contracts import (
    Action,
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

MOCK_OTP = "000000"


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


def client_for(pdp_client) -> TestClient:
    settings = Settings(use_memory_db=True)
    return TestClient(create_app(settings, pdp_client=pdp_client))
