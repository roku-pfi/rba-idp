"""IdP-4: password verify then PDP enforce; session / challenge per action."""

from __future__ import annotations

from uuid import UUID

import pytest
from fastapi.testclient import TestClient
from rba_contracts import Action, LoginOutcome, RiskLevel

from rba_idp.db.models import IdpSession
from rba_idp.tokens import hash_session_token
from tests.helpers import LOGIN, MOCK_OTP, REASON, StubPdp, client_for
from tests.helpers import test_settings as make_settings


def test_healthz(client: TestClient) -> None:
    assert client.get("/healthz").json() == {"status": "ok"}


def test_allow_issues_session_and_calls_pdp(client: TestClient, pdp: StubPdp) -> None:
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
    assert body["session"]["token"]
    assert body["session"]["expires_at"]
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


def test_login_fills_country_from_ip_when_omitted(
    client: TestClient, pdp: StubPdp
) -> None:
    payload = {k: v for k, v in LOGIN.items() if k not in ("country", "asn")}
    resp = client.post("/login", json=payload)
    assert resp.status_code == 200
    call = pdp.calls[0]
    assert call.country == "AR"
    assert call.asn == "7303"


def test_session_token_is_stored_hashed(client: TestClient) -> None:
    body = client.post("/login", json=LOGIN).json()
    token = body["session"]["token"]
    with client.app.state.session_factory() as session:
        row = session.get(IdpSession, hash_session_token(token))
        assert row is not None
        assert row.token_hash != token
        assert row.user_id == "usr_demo"


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
    with client_for(pdp) as client:
        resp = client.post("/login", json=LOGIN)
    assert resp.status_code == 200
    body = resp.json()
    assert body["outcome"] == outcome.value
    assert body["action"] == action.value
    assert body["risk_score"] == score
    assert body["risk_level"] == level.value
    assert body["user_id"] == "usr_demo"
    if action == Action.ALLOW:
        assert body["session"]["token"]
        assert "challenge_id" not in body
    elif action in (Action.REQUIRE_MFA, Action.REAUTHENTICATE):
        UUID(body["challenge_id"])
        assert "session" not in body
    else:
        assert "session" not in body
        assert "challenge_id" not in body


def test_wrong_password_is_reported_to_the_pdp_but_not_enforced(
    client: TestClient, pdp: StubPdp
) -> None:
    """ADR-0027: the attempt is recorded; the answer is byte-for-byte unchanged.

    Reporting is what makes `failed_logins_last_24h` real. It must not leak the
    user's existence, issue a session, or let the PDP's decision touch the
    response — a failed password is not an authentication to enforce.
    """
    payload = {**LOGIN, "password": "wrong-password"}
    resp = client.post("/login", json=payload)
    assert resp.status_code == 200
    assert resp.json() == {"outcome": LoginOutcome.INVALID_CREDENTIALS.value}

    assert len(pdp.calls) == 1
    call = pdp.calls[0]
    assert call.login_successful is False
    assert call.user_id == "usr_demo"
    assert call.application_id == "demo-banking-app"
    assert call.country == "AR"


def test_failed_login_report_can_be_disabled(pdp: StubPdp) -> None:
    settings = make_settings(report_failed_logins=False)
    with client_for(pdp, settings=settings) as client:
        resp = client.post("/login", json={**LOGIN, "password": "wrong-password"})
        assert resp.json() == {"outcome": LoginOutcome.INVALID_CREDENTIALS.value}
        assert pdp.calls == []


def test_wrong_password_survives_a_pdp_outage() -> None:
    """Telemetry must never turn a wrong password into a 503 (enforcement still does)."""
    from tests.helpers import FailingPdp

    with client_for(FailingPdp()) as client:
        resp = client.post("/login", json={**LOGIN, "password": "wrong-password"})
        assert resp.status_code == 200
        assert resp.json() == {"outcome": LoginOutcome.INVALID_CREDENTIALS.value}


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


def test_pdp_unavailable_degrades_to_mfa() -> None:
    """RF-10 / RNF-03: an outage must not become open access or a mass lockout.

    A 503 here would lock out every legitimate user for the length of the
    outage. The password was already verified, so the only safe answer left is
    to ask for a second factor.
    """
    from tests.helpers import FailingPdp

    with client_for(FailingPdp()) as client:
        resp = client.post("/login", json=LOGIN)

    assert resp.status_code == 200
    body = resp.json()
    assert body["outcome"] == LoginOutcome.MFA_REQUIRED.value
    assert body["action"] == Action.REQUIRE_MFA.value
    UUID(body["challenge_id"])
    assert "session" not in body

    # There is no score to report, and the reason says exactly that.
    assert body["risk_score"] == 0.0
    assert [r["code"] for r in body["reasons"]] == ["pdp_unavailable"]


def test_pdp_unavailable_never_issues_a_session() -> None:
    """The negative half: degrading must not hand out access."""
    from tests.helpers import FailingPdp

    with client_for(FailingPdp()) as client:
        resp = client.post("/login", json=LOGIN)
        body = resp.json()
        assert "session" not in body
        assert "redirect_to" not in body

        # And the challenge is a real one — completing it is what grants access.
        verify = client.post(
            "/mfa/verify",
            json={"challenge_id": body["challenge_id"], "code": MOCK_OTP},
        )
    assert verify.status_code == 200
    assert verify.json()["outcome"] == LoginOutcome.AUTHENTICATED.value


def test_pdp_unavailable_action_is_configurable_but_cannot_open_access() -> None:
    """The type is the guarantee: ALLOW and BLOCK are not expressible."""
    import pydantic
    import pytest

    from rba_idp.config import Settings

    assert Settings().pdp_unavailable_action == "REQUIRE_MFA"
    assert Settings(pdp_unavailable_action="REAUTHENTICATE").pdp_unavailable_action == (
        "REAUTHENTICATE"
    )
    for forbidden in ("ALLOW", "BLOCK"):
        with pytest.raises(pydantic.ValidationError):
            Settings(pdp_unavailable_action=forbidden)


def test_pdp_unavailable_still_rejects_a_wrong_password() -> None:
    """Degrading is for *authenticated* users. A wrong password is still a 401-shaped no."""
    from tests.helpers import FailingPdp

    with client_for(FailingPdp()) as client:
        resp = client.post("/login", json={**LOGIN, "password": "not-the-password"})

    assert resp.status_code == 200
    assert resp.json() == {"outcome": LoginOutcome.INVALID_CREDENTIALS.value}


def test_password_never_reaches_the_pdp(client: TestClient, pdp: StubPdp) -> None:
    client.post("/login", json=LOGIN)
    dumped = pdp.calls[0].model_dump()
    assert "password" not in dumped
    assert "email" not in dumped


def test_no_group_grant_is_access_denied_without_pdp(
    client: TestClient, pdp: StubPdp
) -> None:
    payload = {**LOGIN, "application_id": "idp-admin-console"}
    resp = client.post("/login", json=payload)
    assert resp.status_code == 200
    body = resp.json()
    assert body["outcome"] == LoginOutcome.ACCESS_DENIED.value
    assert body["user_id"] == "usr_demo"
    assert "session" not in body
    assert pdp.calls == []


def test_ungrouped_user_cannot_log_in(client: TestClient, pdp: StubPdp) -> None:
    token = client.post(
        "/login",
        json={
            **LOGIN,
            "email": "admin@example.com",
            "password": "admin-password",
            "application_id": "idp-admin-console",
        },
    ).json()["session"]["token"]
    created = client.post(
        "/admin/api/users",
        headers={"Authorization": f"Bearer {token}"},
        json={"email": "orphan@example.com", "password": "orphan-password"},
    )
    assert created.status_code == 201
    before = len(pdp.calls)
    resp = client.post(
        "/login",
        json={**LOGIN, "email": "orphan@example.com", "password": "orphan-password"},
    )
    assert resp.json()["outcome"] == LoginOutcome.ACCESS_DENIED.value
    assert len(pdp.calls) == before
