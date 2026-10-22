"""Shared IdP test helpers (not pytest fixtures)."""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi.testclient import TestClient
from rba_contracts import (
    Action,
    BasePolicy,
    DecisionListResponse,
    DecisionRecord,
    EngineMode,
    Reason,
    RiskEvaluateRequest,
    RiskEvaluateResponse,
    RiskLevel,
    TenantPolicy,
)

from rba_idp.config import Settings
from rba_idp.main import create_app
from rba_idp.pdp import PdpUnavailable
from rba_idp.clients import AuditNotFound, ControlPlaneUnavailable, PolicyNotFound
from rba_idp.services.admin import TENANT_HEADER, starter_policy

BANK = "roku-bank"
KAZE = "kaze-labs"
PLATFORM = "rokusec"

# Martín, a Roku Bank customer, logging into the bank.
LOGIN = {
    "email": "martin@correo.example",
    "password": "martin-demo",
    "application_id": "roku-bank-web",
    "ip_address": "203.0.113.10",
    "asn": "13335",
    "country": "AR",
    "device_type": "mobile",
    "os": "Android",
    "browser": "Chrome",
}

SIGNALS = {
    "ip_address": LOGIN["ip_address"],
    "asn": LOGIN["asn"],
    "country": LOGIN["country"],
    "device_type": LOGIN["device_type"],
    "os": LOGIN["os"],
    "browser": LOGIN["browser"],
}

# Console logins (ADR-0033): no application_id; the domain picks the tenant.
DIEGO = {"email": "diego@rokubank.example", "password": "diego-demo", **SIGNALS}
ANA = {"email": "ana@rokubank.example", "password": "ana-demo", **SIGNALS}
LUCAS = {"email": "lucas@kazelabs.example", "password": "lucas-demo", **SIGNALS}
JUAN = {"email": "juan@rokusec.example", "password": "juan-demo", **SIGNALS}
# Kept for older tests: the bank's tenant admin.
ADMIN_LOGIN = DIEGO

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
        # What the PDP says to enforce; defaults to the verdict (ACTIVE).
        self.enforced: Action | None = None
        self.engine_mode = EngineMode.ACTIVE
        self.fallback = False

    def evaluate(self, request: RiskEvaluateRequest) -> RiskEvaluateResponse:
        self.calls.append(request)
        return RiskEvaluateResponse(
            event_id=request.event_id,
            risk_score=self.risk_score,
            risk_level=self.risk_level,
            action=self.action,
            enforced_action=self.enforced or self.action,
            engine_mode=self.engine_mode,
            reasons=self.reasons,
            model_version="freeman-0.1.0",
            policy_version="1.0.0",
            feature_schema_version="1.0.0",
            fallback=self.fallback,
            scored_at=datetime.now(timezone.utc),
        )


class FailingPdp:
    def evaluate(self, request: RiskEvaluateRequest) -> RiskEvaluateResponse:
        raise PdpUnavailable("connection refused")


def stub_policy(tenant_id: str, **update) -> TenantPolicy:
    """ACTIVE + PASSWORD_ONLY with the default ladder, unless overridden."""
    policy = starter_policy(tenant_id).model_copy(
        update={"engine_mode": EngineMode.ACTIVE, "base_policy": BasePolicy.PASSWORD_ONLY}
    )
    return policy.model_copy(update=update)


class StubPolicy:
    """The PDP's policy store: one policy per tenant."""

    def __init__(self, policies: dict[str, TenantPolicy] | None = None) -> None:
        self.policies = policies if policies is not None else {
            tid: stub_policy(tid) for tid in (BANK, KAZE, PLATFORM)
        }
        self.reads: list[str] = []

    def get_policy(self, tenant_id: str) -> TenantPolicy:
        self.reads.append(tenant_id)
        if tenant_id not in self.policies:
            raise PolicyNotFound(tenant_id)
        return self.policies[tenant_id]

    def put_policy(self, policy: TenantPolicy) -> TenantPolicy:
        self.policies[policy.tenant_id] = policy
        return policy


class StubAudit:
    """The decision store. Filters by tenant like the real one."""

    def __init__(self, items: list[DecisionRecord] | None = None) -> None:
        self.items = list(items or [])
        self.tenants_asked: list[str] = []

    def list_decisions(
        self,
        *,
        tenant_id: str,
        user_id: str | None = None,
        application_id: str | None = None,
        action: Action | None = None,
        limit: int = 50,
    ) -> DecisionListResponse:
        self.tenants_asked.append(tenant_id)
        rows = [row for row in self.items if row.tenant_id == tenant_id]
        if user_id:
            rows = [row for row in rows if row.user_id == user_id]
        if application_id:
            rows = [row for row in rows if row.application_id == application_id]
        if action is not None:
            rows = [row for row in rows if row.action == action]
        sliced = rows[:limit]
        return DecisionListResponse(items=sliced, count=len(sliced))

    def get_decision(self, tenant_id: str, event_id):
        for row in self.items:
            if row.event_id == event_id and row.tenant_id == tenant_id:
                return row
        raise AuditNotFound(str(event_id))


class FailingAudit:
    def list_decisions(self, **_kwargs):
        raise ControlPlaneUnavailable("connection refused")

    def get_decision(self, tenant_id, event_id):
        raise ControlPlaneUnavailable("connection refused")


def test_settings(**overrides) -> Settings:
    values = {
        "use_memory_db": True,
        "webauthn_rp_id": "testserver",
        "webauthn_origin": "http://testserver",
        "mock_otp_enabled": True,
    }
    values.update(overrides)
    return Settings(**values)


def client_for(
    pdp_client,
    *,
    policy_client=None,
    audit_client=None,
    settings: Settings | None = None,
) -> TestClient:
    settings = settings or test_settings()
    return TestClient(
        create_app(
            settings,
            pdp_client=pdp_client,
            policy_client=policy_client or StubPolicy(),
            audit_client=audit_client or StubAudit(),
        )
    )


def console_token(client: TestClient, who: dict) -> str:
    """Sign an operator into their console; the stub PDP must ALLOW."""
    body = client.post("/console/login", json=who).json()
    assert body["outcome"] == "AUTHENTICATED", body
    return body["session"]["token"]


def bearer(token: str, tenant: str | None = None) -> dict[str, str]:
    headers = {"Authorization": f"Bearer {token}"}
    if tenant is not None:
        headers[TENANT_HEADER] = tenant
    return headers
