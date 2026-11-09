"""Someone got the password right and was stopped: the owner hears of it on
their next sign-in, once, and can change the password (contracts 0.22.0)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from rba_contracts import Action, LoginOutcome, Reason, RiskLevel

from rba_idp.db.models import MfaChallenge
from tests.helpers import LOGIN, MOCK_OTP, StubPdp, client_for

TOKYO = {**LOGIN, "country": "JP"}


def _expire_challenges(client) -> None:
    with client.app.state.session_factory() as session:
        for row in session.query(MfaChallenge).all():
            row.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        session.commit()


def _sign_in(client, pdp) -> dict:
    pdp.action, pdp.reasons, pdp.enforced = Action.ALLOW, [], None
    body = client.post("/login", json=LOGIN).json()
    assert body["outcome"] == LoginOutcome.AUTHENTICATED.value
    return body


def test_an_abandoned_step_up_is_told_once_on_the_next_sign_in() -> None:
    pdp = StubPdp(action=Action.REAUTHENTICATE, risk_level=RiskLevel.CRITICAL, risk_score=0.9)
    with client_for(pdp) as client:
        assert client.post("/login", json=TOKYO).json()["outcome"] == LoginOutcome.REAUTH_REQUIRED.value
        _expire_challenges(client)
        first = _sign_in(client, pdp)
        again = _sign_in(client, pdp)
    [attempt] = first["attempts"]
    assert attempt["stopped_by"] == "passkey" and attempt["country"] == "JP"
    assert again.get("attempts", []) == []


def test_a_step_up_still_open_is_not_told_yet() -> None:
    pdp = StubPdp(action=Action.REQUIRE_MFA, risk_level=RiskLevel.MEDIUM)
    with client_for(pdp) as client:
        client.post("/login", json=TOKYO)
        assert _sign_in(client, pdp).get("attempts", []) == []


def test_a_passed_step_up_was_the_owner() -> None:
    pdp = StubPdp(action=Action.REQUIRE_MFA, risk_level=RiskLevel.MEDIUM)
    with client_for(pdp) as client:
        body = client.post("/login", json=TOKYO).json()
        done = client.post("/mfa/verify", json={"challenge_id": body["challenge_id"], "code": MOCK_OTP}).json()
        assert done["outcome"] == LoginOutcome.AUTHENTICATED.value
        assert done.get("attempts", []) == []
        _expire_challenges(client)
        assert _sign_in(client, pdp).get("attempts", []) == []


def test_passkey_always_is_not_an_attempt() -> None:
    """The engine let it in; the tenant asks every login for the passkey."""
    pdp = StubPdp(action=Action.ALLOW)
    pdp.enforced = Action.REQUIRE_MFA
    with client_for(pdp) as client:
        client.post("/login", json=LOGIN)
        _expire_challenges(client)
        assert _sign_in(client, pdp).get("attempts", []) == []


def test_a_right_password_from_a_blocked_ip_is_told() -> None:
    blocked = Reason(code="source_blocked", signal="ip_address", detail="blocked")
    pdp = StubPdp(action=Action.BLOCK, risk_level=RiskLevel.CRITICAL, risk_score=0.9, reasons=[blocked])
    with client_for(pdp) as client:
        assert client.post("/login", json=TOKYO).json()["outcome"] == LoginOutcome.BLOCKED.value
        [attempt] = _sign_in(client, pdp)["attempts"]
    assert attempt["stopped_by"] == "blocked"


def test_the_owners_own_pause_is_not_an_attempt() -> None:
    paused = Reason(code="account_cooldown", signal="failed_logins_own", detail="paused")
    pdp = StubPdp(action=Action.BLOCK, risk_level=RiskLevel.CRITICAL, risk_score=0.9, reasons=[paused])
    with client_for(pdp) as client:
        client.post("/login", json=LOGIN)
        assert _sign_in(client, pdp).get("attempts", []) == []


def test_the_owner_changes_the_password_and_other_sessions_end() -> None:
    pdp = StubPdp()
    with client_for(pdp) as client:
        other = _sign_in(client, pdp)["session"]["token"]
        mine = _sign_in(client, pdp)["session"]["token"]
        auth = {"Authorization": f"Bearer {mine}"}

        wrong = client.post("/account/password", headers=auth,
                            json={"current_password": "nope", "new_password": "otra-clave-123"})
        assert wrong.status_code == 403
        assert client.post("/account/password", json={"current_password": LOGIN["password"],
                                                        "new_password": "otra-clave-123"}).status_code == 401
        ok = client.post("/account/password", headers=auth,
                         json={"current_password": LOGIN["password"], "new_password": "otra-clave-123"})
        assert ok.status_code == 204

        assert client.get("/session", headers={"Authorization": f"Bearer {other}"}).status_code == 401
        assert client.get("/session", headers=auth).status_code == 200
        assert client.post("/login", json=LOGIN).json()["outcome"] == LoginOutcome.INVALID_CREDENTIALS.value
        renewed = client.post("/login", json={**LOGIN, "password": "otra-clave-123"}).json()
        assert renewed["outcome"] == LoginOutcome.AUTHENTICATED.value


def test_no_passkey_yet_is_not_an_attempt() -> None:
    """A first sign-in that needs a passkey the user does not have: the owner."""
    from tests.helpers import test_settings

    pdp = StubPdp(action=Action.REQUIRE_MFA, risk_level=RiskLevel.MEDIUM)
    with client_for(pdp, settings=test_settings(mock_otp_enabled=False)) as client:
        assert client.post("/login", json=TOKYO).json()["outcome"] == LoginOutcome.SECOND_FACTOR_MISSING.value
        assert _sign_in(client, pdp).get("attempts", []) == []


def _age_attempts(client, seconds: int) -> None:
    from rba_idp.db.models import StoppedAttemptRow

    with client.app.state.session_factory() as session:
        for row in session.query(StoppedAttemptRow).all():
            row.occurred_at = datetime.now(timezone.utc) - timedelta(seconds=seconds)
        session.commit()


def test_a_signed_in_app_sees_attempts_while_the_user_is_in() -> None:
    """The owner is in the bank; someone tries from Tokyo. The bank's banner
    shows it after the grace minute, until the owner dismisses it."""
    pdp = StubPdp()
    with client_for(pdp) as client:
        auth = {"Authorization": f"Bearer {_sign_in(client, pdp)['session']['token']}"}
        pdp.action, pdp.risk_level = Action.REAUTHENTICATE, RiskLevel.CRITICAL
        client.post("/login", json=TOKYO)
        assert client.get("/session/attempts", headers=auth).json() == []  # may still be the owner
        _age_attempts(client, 61)
        [attempt] = client.get("/session/attempts", headers=auth).json()
        assert attempt["country"] == "JP"
        assert client.get("/session/attempts", headers=auth).json() == [attempt]  # stays until dismissed
        seen = client.post("/session/attempts/seen", headers=auth, params={"up_to": attempt["occurred_at"]})
        assert seen.status_code == 204
        assert client.get("/session/attempts", headers=auth).json() == []
        assert client.get("/session/attempts").status_code == 401


def test_a_refusal_shows_at_once_and_a_password_change_clears_it() -> None:
    blocked = Reason(code="source_blocked", signal="ip_address", detail="blocked")
    pdp = StubPdp()
    with client_for(pdp) as client:
        auth = {"Authorization": f"Bearer {_sign_in(client, pdp)['session']['token']}"}
        pdp.action, pdp.reasons = Action.BLOCK, [blocked]
        client.post("/login", json=TOKYO)
        assert len(client.get("/session/attempts", headers=auth).json()) == 1
        client.post("/account/password", headers=auth,
                    json={"current_password": LOGIN["password"], "new_password": "otra-clave-123"})
        assert client.get("/session/attempts", headers=auth).json() == []
