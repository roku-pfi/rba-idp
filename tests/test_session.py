"""IdP-4: GET /session, POST /logout, POST /mfa/verify (mock OTP)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import UUID

from fastapi.testclient import TestClient
from rba_contracts import Action, LoginOutcome, RiskLevel

from rba_idp.db.models import IdpSession, MfaChallenge
from rba_idp.tokens import hash_session_token
from tests.helpers import LOGIN, MOCK_OTP, REASON, StubPdp, client_for


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_get_session_returns_user(client: TestClient) -> None:
    login = client.post("/login", json=LOGIN).json()
    token = login["session"]["token"]
    resp = client.get("/session", headers=_auth(token))
    assert resp.status_code == 200
    body = resp.json()
    assert body["user"]["user_id"] == "usr_demo"
    assert body["user"]["email"] == "demo@example.com"
    assert body["user"]["created_at"]
    assert body["expires_at"] == login["session"]["expires_at"]


def test_get_session_without_token_is_401(client: TestClient) -> None:
    resp = client.get("/session")
    assert resp.status_code == 401
    assert resp.json()["detail"] == "missing or expired session"


def test_get_session_with_bogus_token_is_401(client: TestClient) -> None:
    resp = client.get("/session", headers=_auth("not-a-real-token"))
    assert resp.status_code == 401


def test_logout_drops_session_and_is_idempotent(client: TestClient) -> None:
    token = client.post("/login", json=LOGIN).json()["session"]["token"]
    first = client.post("/logout", headers=_auth(token))
    assert first.status_code == 204
    assert client.get("/session", headers=_auth(token)).status_code == 401
    second = client.post("/logout", headers=_auth(token))
    assert second.status_code == 204
    assert client.post("/logout").status_code == 204


def test_expired_session_is_401(client: TestClient) -> None:
    token = client.post("/login", json=LOGIN).json()["session"]["token"]
    with client.app.state.session_factory() as session:
        row = session.get(IdpSession, hash_session_token(token))
        assert row is not None
        row.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        session.commit()
    resp = client.get("/session", headers=_auth(token))
    assert resp.status_code == 401


def test_mfa_verify_issues_session() -> None:
    pdp = StubPdp(
        action=Action.REQUIRE_MFA, risk_score=0.61, risk_level=RiskLevel.MEDIUM
    )
    with client_for(pdp) as client:
        login = client.post("/login", json=LOGIN).json()
        assert login["outcome"] == LoginOutcome.MFA_REQUIRED.value
        challenge_id = login["challenge_id"]
        UUID(challenge_id)
        assert "session" not in login
        assert len(pdp.calls) == 1

        resp = client.post(
            "/mfa/verify",
            json={"challenge_id": challenge_id, "code": MOCK_OTP},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["outcome"] == LoginOutcome.AUTHENTICATED.value
        assert body["user_id"] == "usr_demo"
        assert body["action"] == Action.REQUIRE_MFA.value
        assert body["risk_score"] == 0.61
        assert body["reasons"] == [REASON.model_dump(mode="json")]
        token = body["session"]["token"]
        assert client.get("/session", headers=_auth(token)).status_code == 200
        assert len(pdp.calls) == 1


def test_reauth_verify_issues_session() -> None:
    pdp = StubPdp(
        action=Action.REAUTHENTICATE, risk_score=0.82, risk_level=RiskLevel.HIGH
    )
    with client_for(pdp) as client:
        login = client.post("/login", json=LOGIN).json()
        assert login["outcome"] == LoginOutcome.REAUTH_REQUIRED.value
        resp = client.post(
            "/mfa/verify",
            json={"challenge_id": login["challenge_id"], "code": MOCK_OTP},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["outcome"] == LoginOutcome.AUTHENTICATED.value
        assert body["action"] == Action.REAUTHENTICATE.value
        assert body["session"]["token"]


def test_wrong_otp_is_invalid_credentials_and_challenge_stays_open() -> None:
    pdp = StubPdp(action=Action.REQUIRE_MFA, risk_score=0.61, risk_level=RiskLevel.MEDIUM)
    with client_for(pdp) as client:
        challenge_id = client.post("/login", json=LOGIN).json()["challenge_id"]
        wrong = client.post(
            "/mfa/verify",
            json={"challenge_id": challenge_id, "code": "111111"},
        )
        assert wrong.status_code == 200
        assert wrong.json() == {"outcome": LoginOutcome.INVALID_CREDENTIALS.value}
        retry = client.post(
            "/mfa/verify",
            json={"challenge_id": challenge_id, "code": MOCK_OTP},
        )
        assert retry.status_code == 200
        assert retry.json()["outcome"] == LoginOutcome.AUTHENTICATED.value


def test_consumed_challenge_cannot_be_reused() -> None:
    pdp = StubPdp(action=Action.REQUIRE_MFA, risk_score=0.61, risk_level=RiskLevel.MEDIUM)
    with client_for(pdp) as client:
        challenge_id = client.post("/login", json=LOGIN).json()["challenge_id"]
        first = client.post(
            "/mfa/verify",
            json={"challenge_id": challenge_id, "code": MOCK_OTP},
        )
        assert first.status_code == 200
        second = client.post(
            "/mfa/verify",
            json={"challenge_id": challenge_id, "code": MOCK_OTP},
        )
        assert second.status_code == 400
        assert second.json()["detail"] == "unknown or expired challenge"


def test_unknown_challenge_is_400(client: TestClient) -> None:
    resp = client.post(
        "/mfa/verify",
        json={
            "challenge_id": "7c2e1b3d-4a6f-9c8e-2d1b-3a6f9c8e4f9a",
            "code": MOCK_OTP,
        },
    )
    assert resp.status_code == 400
    assert resp.json()["detail"] == "unknown or expired challenge"


def test_expired_challenge_cannot_verify() -> None:
    pdp = StubPdp(action=Action.REQUIRE_MFA, risk_score=0.61, risk_level=RiskLevel.MEDIUM)
    with client_for(pdp) as client:
        challenge_id = client.post("/login", json=LOGIN).json()["challenge_id"]
        with client.app.state.session_factory() as session:
            row = session.get(MfaChallenge, challenge_id)
            assert row is not None
            row.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
            session.commit()
        resp = client.post(
            "/mfa/verify",
            json={"challenge_id": challenge_id, "code": MOCK_OTP},
        )
        assert resp.status_code == 400


def test_block_has_no_session_or_challenge() -> None:
    pdp = StubPdp(action=Action.BLOCK, risk_score=0.97, risk_level=RiskLevel.CRITICAL)
    with client_for(pdp) as client:
        body = client.post("/login", json=LOGIN).json()
        assert body["outcome"] == LoginOutcome.BLOCKED.value
        assert "session" not in body
        assert "challenge_id" not in body
        assert client.get("/session").status_code == 401
