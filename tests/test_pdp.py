"""HttpPdpClient posts the evaluate contract and maps transport failures."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from uuid import uuid4

import httpx
from rba_contracts import Action, Reason, RiskEvaluateRequest, RiskLevel

from rba_idp.pdp import HttpPdpClient, PdpUnavailable


def _request() -> RiskEvaluateRequest:
    return RiskEvaluateRequest(
        event_id=uuid4(),
        application_id="demo-banking-app",
        user_id="usr_demo",
        timestamp=datetime(2026, 8, 15, 12, 0, tzinfo=timezone.utc),
        ip_address="203.0.113.10",
        login_successful=True,
    )


def _ok_body(event_id: str) -> dict:
    return {
        "event_id": event_id,
        "risk_score": 0.61,
        "risk_level": RiskLevel.MEDIUM.value,
        "action": Action.REQUIRE_MFA.value,
        "reasons": [
            Reason(
                code="signal_novel",
                signal="ip_address",
                contribution=1.2,
                detail="ip_address not previously seen for this user",
            ).model_dump(mode="json")
        ],
        "model_version": "freeman-0.1.0",
        "policy_version": "1.0.0",
        "feature_schema_version": "1.0.0",
        "fallback": False,
        "scored_at": "2026-08-15T12:00:00.042Z",
    }


def test_posts_json_to_risk_evaluate() -> None:
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["body"] = json.loads(request.content)
        event_id = captured["body"]["event_id"]
        return httpx.Response(200, json=_ok_body(event_id))

    transport = httpx.MockTransport(handler)
    http = httpx.Client(base_url="http://pdp.test", transport=transport)
    client = HttpPdpClient("http://pdp.test", client=http)
    req = _request()
    decision = client.evaluate(req)
    assert captured["url"] == "http://pdp.test/risk/evaluate"
    assert captured["body"]["user_id"] == "usr_demo"
    assert captured["body"]["login_successful"] is True
    assert "password" not in captured["body"]
    assert decision.action == Action.REQUIRE_MFA
    assert decision.event_id == req.event_id


def test_http_error_becomes_pdp_unavailable() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, json={"detail": "boom"})

    http = httpx.Client(
        base_url="http://pdp.test",
        transport=httpx.MockTransport(handler),
    )
    client = HttpPdpClient("http://pdp.test", client=http)
    try:
        client.evaluate(_request())
        raise AssertionError("expected PdpUnavailable")
    except PdpUnavailable:
        pass


def test_invalid_body_becomes_pdp_unavailable() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"not": "a decision"})

    http = httpx.Client(
        base_url="http://pdp.test",
        transport=httpx.MockTransport(handler),
    )
    client = HttpPdpClient("http://pdp.test", client=http)
    try:
        client.evaluate(_request())
        raise AssertionError("expected PdpUnavailable")
    except PdpUnavailable:
        pass
