"""Demo-2 thin callback: one-time code → session token (not OIDC)."""

from __future__ import annotations

from urllib.parse import parse_qs, urlparse

from fastapi.testclient import TestClient
from rba_contracts import Action, LoginOutcome

from rba_idp.db.models import AuthCode
from sqlalchemy import select
from tests.helpers import DIEGO, LOGIN, StubPdp, client_for


def _bearer(token: str) -> dict[str, str]:
    return {"authorization": f"Bearer {token}"}


def _code_from(redirect_to: str) -> str:
    parsed = urlparse(redirect_to)
    codes = parse_qs(parsed.query).get("code", [])
    assert len(codes) == 1, redirect_to
    return codes[0]


def test_allow_issues_callback_for_seeded_banking_app(client: TestClient) -> None:
    body = client.post("/login", json=LOGIN).json()
    assert body["outcome"] == LoginOutcome.AUTHENTICATED.value
    assert body["redirect_to"].startswith("http://localhost:8002/callback?")
    code = _code_from(body["redirect_to"])
    exchanged = client.post("/callback/token", json={"code": code})
    assert exchanged.status_code == 200
    payload = exchanged.json()
    assert payload["user"]["email"] == "martin@correo.example"
    assert payload["user"]["is_admin"] is False
    # Redeeming rotates the token: only the app's copy is valid.
    app_token = payload["session"]["token"]
    assert app_token != body["session"]["token"]
    assert client.get("/session", headers=_bearer(app_token)).status_code == 200
    stale = client.get("/session", headers=_bearer(body["session"]["token"]))
    assert stale.status_code == 401


def test_auth_codes_hold_no_raw_token(client: TestClient) -> None:
    body = client.post("/login", json=LOGIN).json()
    raw = body["session"]["token"]
    factory = client.app.state.session_factory
    with factory() as session:
        rows = session.scalars(select(AuthCode)).all()
    assert rows
    for row in rows:
        assert raw not in {getattr(row, c.name) for c in AuthCode.__table__.columns}


def test_callback_code_is_one_time(client: TestClient) -> None:
    body = client.post("/login", json=LOGIN).json()
    code = _code_from(body["redirect_to"])
    assert client.post("/callback/token", json={"code": code}).status_code == 200
    again = client.post("/callback/token", json={"code": code})
    assert again.status_code == 400
    assert again.json()["detail"] == "unknown or expired code"


def test_unknown_callback_code_is_400(client: TestClient) -> None:
    resp = client.post("/callback/token", json={"code": "not-a-real-code"})
    assert resp.status_code == 400


def test_mismatched_redirect_uri_does_not_leave_the_idp(client: TestClient) -> None:
    payload = {**LOGIN, "redirect_uri": "http://evil.example/callback"}
    body = client.post("/login", json=payload).json()
    assert body["outcome"] == LoginOutcome.AUTHENTICATED.value
    assert "redirect_to" not in body


def test_admin_console_has_no_callback() -> None:
    with client_for(StubPdp()) as client:
        body = client.post("/console/login", json=DIEGO).json()
        assert body["outcome"] == LoginOutcome.AUTHENTICATED.value
        assert "redirect_to" not in body


def test_mfa_success_issues_callback() -> None:
    pdp = StubPdp(action=Action.REQUIRE_MFA, risk_score=0.61)
    with client_for(pdp) as client:
        challenge = client.post("/login", json=LOGIN).json()
        assert challenge["outcome"] == LoginOutcome.MFA_REQUIRED.value
        verified = client.post(
            "/mfa/verify",
            json={
                "challenge_id": challenge["challenge_id"],
                "code": "000000",
                "redirect_uri": "http://localhost:8002/callback",
            },
        ).json()
        assert verified["outcome"] == LoginOutcome.AUTHENTICATED.value
        assert verified["redirect_to"].startswith("http://localhost:8002/callback?")
        code = _code_from(verified["redirect_to"])
        assert client.post("/callback/token", json={"code": code}).status_code == 200
