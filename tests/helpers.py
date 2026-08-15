"""Shared IdP test helpers (not pytest fixtures)."""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi.testclient import TestClient
from rba_contracts import (
    Action,
    DecisionListResponse,
    DecisionRecord,
    PolicyConfig,
    Reason,
    RiskEvaluateRequest,
    RiskEvaluateResponse,
    RiskLevel,
)
from rba_contracts.policy import LevelToAction, PolicyBundle, ScoreBand

from rba_idp.config import Settings
from rba_idp.main import create_app
from rba_idp.pdp import PdpUnavailable
from rba_idp.clients import AuditNotFound, ControlPlaneUnavailable

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

ADMIN_LOGIN = {
    **LOGIN,
    "email": "admin@example.com",
    "password": "admin-password",
    "application_id": "idp-admin-console",
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


STUB_POLICY = PolicyConfig(
    policy_version="1.0.0",
    defaults=PolicyBundle(
        score_to_level=[
            ScoreBand(max=0.30, level=RiskLevel.LOW),
            ScoreBand(max=0.60, level=RiskLevel.MEDIUM),
            ScoreBand(max=0.80, level=RiskLevel.HIGH),
            ScoreBand(max=1.00, level=RiskLevel.CRITICAL),
        ],
        level_to_action=LevelToAction(
            LOW=Action.ALLOW,
            MEDIUM=Action.REQUIRE_MFA,
            HIGH=Action.REAUTHENTICATE,
            CRITICAL=Action.BLOCK,
        ),
        fallback_action=Action.REQUIRE_MFA,
    ),
)


class StubPolicy:
    def __init__(self, config: PolicyConfig | None = None) -> None:
        self.config = config or STUB_POLICY.model_copy(deep=True)

    def get_policy(self) -> PolicyConfig:
        return self.config

    def put_policy(self, config: PolicyConfig) -> PolicyConfig:
        self.config = config
        return config


class StubAudit:
    def __init__(self, items: list[DecisionRecord] | None = None) -> None:
        self.items = list(items or [])

    def list_decisions(
        self,
        *,
        user_id: str | None = None,
        application_id: str | None = None,
        action: Action | None = None,
        limit: int = 50,
    ) -> DecisionListResponse:
        rows = self.items
        if user_id:
            rows = [row for row in rows if row.user_id == user_id]
        if application_id:
            rows = [row for row in rows if row.application_id == application_id]
        if action is not None:
            rows = [row for row in rows if row.action == action]
        sliced = rows[:limit]
        return DecisionListResponse(items=sliced, count=len(sliced))

    def get_decision(self, event_id):
        for row in self.items:
            if row.event_id == event_id:
                return row
        raise AuditNotFound(str(event_id))


class FailingAudit:
    def list_decisions(self, **_kwargs):
        raise ControlPlaneUnavailable("connection refused")

    def get_decision(self, event_id):
        raise ControlPlaneUnavailable("connection refused")


def client_for(
    pdp_client,
    *,
    policy_client=None,
    audit_client=None,
) -> TestClient:
    settings = Settings(use_memory_db=True)
    return TestClient(
        create_app(
            settings,
            pdp_client=pdp_client,
            policy_client=policy_client or StubPolicy(),
            audit_client=audit_client or StubAudit(),
        )
    )
