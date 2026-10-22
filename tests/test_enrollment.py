"""A passkey is enrolled only from a trusted context (ADR-0037).

The attack being closed: someone holding Martín's password triggers the first
step-up and registers *their* authenticator. So these tests run with the mock
OTP **off**, the way a deployment runs, and check every door: the step-up is
not one, a usual-context login is (once, briefly), an activation code is (with
the password), and nothing else is.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from rba_contracts import Action, EngineMode, LoginOutcome, RiskLevel

from rba_idp import activation
from rba_idp.db.models import MfaChallenge
from tests.helpers import (
    ANA,
    DIEGO,
    LOGIN,
    StubPdp,
    StubPolicy,
    bearer,
    client_for,
    console_token,
    stub_policy,
)
from tests.helpers import test_settings as make_settings
from tests.test_webauthn import SoftPasskey

ACTIVATE = "/activate"


def _deployed(pdp: StubPdp, policy_client=None, **overrides) -> TestClient:
    """An IdP configured like a deployment: no mock OTP."""
    return client_for(
        pdp,
        policy_client=policy_client,
        settings=make_settings(mock_otp_enabled=False, **overrides),
    )


def _step_up_pdp() -> StubPdp:
    return StubPdp(action=Action.REQUIRE_MFA, risk_score=0.61, risk_level=RiskLevel.MEDIUM)


def _usual_pdp() -> StubPdp:
    return StubPdp(action=Action.ALLOW, risk_score=0.1, risk_level=RiskLevel.LOW)


def _operator(client: TestClient, who: dict = DIEGO) -> str:
    """Sign an operator in under a usual-context verdict, whatever the test's
    PDP says for Martín — operators have no passkey either."""
    pdp = client.app.state.pdp_client
    saved = (pdp.action, pdp.risk_level, pdp.risk_score)
    pdp.action, pdp.risk_level, pdp.risk_score = Action.ALLOW, RiskLevel.LOW, 0.1
    try:
        return console_token(client, who)
    finally:
        pdp.action, pdp.risk_level, pdp.risk_score = saved


def _issue_code(client: TestClient, user_id: str = "usr_rb_martin") -> str:
    diego = _operator(client)
    resp = client.post(f"/admin/api/users/{user_id}/activation-code", headers=bearer(diego))
    assert resp.status_code == 201, resp.text
    return resp.json()["code"]


def _activate(client: TestClient, code: str, passkey: SoftPasskey, password: str = "martin-demo"):
    opts = client.post(f"{ACTIVATE}/options", json={"code": code, "password": password})
    if opts.status_code != 200:
        return opts
    return client.post(
        f"{ACTIVATE}/verify",
        json={"code": code, "credential": passkey.create(opts.json()["public_key"]["challenge"])},
    )


def _step_up_with(client: TestClient, passkey: SoftPasskey) -> dict:
    body = client.post("/login", json=LOGIN).json()
    assert body["outcome"] == LoginOutcome.MFA_REQUIRED.value, body
    opts = client.post("/mfa/webauthn/options", json={"challenge_id": body["challenge_id"]}).json()
    return client.post(
        "/mfa/webauthn/verify",
        json={"challenge_id": body["challenge_id"], "credential": passkey.get(opts["public_key"]["challenge"])},
    ).json()


# ================================================================ the mock OTP


def test_the_mock_otp_does_not_exist_unless_enabled() -> None:
    """With it on, `000000` passes any step-up for anyone holding a password."""
    with _deployed(_step_up_pdp()) as client:
        resp = client.post(
            "/mfa/verify",
            json={"challenge_id": "7c2e1b3d-4a6f-4c8e-ad1b-3a6f9c8e4f9a", "code": "000000"},
        )
        assert resp.status_code == 404


# ================================================================ the step-up is not a door


def test_a_step_up_without_a_passkey_is_refused_not_turned_into_enrollment() -> None:
    pdp = _step_up_pdp()
    with _deployed(pdp) as client:
        body = client.post("/login", json=LOGIN).json()
        assert body["outcome"] == LoginOutcome.SECOND_FACTOR_MISSING.value
        assert "session" not in body and "challenge_id" not in body
        # The verdict was still recorded by the PDP; the refusal is on the row.
        assert len(pdp.calls) == 1
        with client.app.state.session_factory() as session:
            rows = session.query(MfaChallenge).all()
        assert [(r.denied_reason, r.consumed_at is not None) for r in rows] == [
            ("no_second_factor", True)
        ]
        assert rows[0].event_id == str(pdp.calls[0].event_id)


def test_a_refused_challenge_cannot_be_used_to_enroll() -> None:
    with _deployed(_step_up_pdp()) as client:
        client.post("/login", json=LOGIN)
        with client.app.state.session_factory() as session:
            challenge_id = session.query(MfaChallenge).one().challenge_id
        resp = client.post("/mfa/webauthn/options", json={"challenge_id": challenge_id})
        assert resp.status_code == 400


# ================================================================ door 1: a usual-context login


def test_a_usual_login_offers_one_passkey_and_only_once() -> None:
    passkey = SoftPasskey()
    pdp = _usual_pdp()
    with _deployed(pdp) as client:
        body = client.post("/login", json=LOGIN).json()
        assert body["outcome"] == "AUTHENTICATED" and body["passkey_offer"] is True
        auth = bearer(body["session"]["token"])
        opts = client.post("/passkeys/options", headers=auth).json()
        done = client.post(
            "/passkeys/verify",
            headers=auth,
            json={"credential": passkey.create(opts["public_key"]["challenge"])},
        )
        assert done.status_code == 204
        # Once: the same session cannot add a second authenticator.
        assert client.post("/passkeys/options", headers=auth).status_code == 403
        # And a user who has one is not offered another.
        again = client.post("/login", json=LOGIN).json()
        assert "passkey_offer" not in again

        # The passkey now carries a step-up, with no mock OTP anywhere.
        pdp.action, pdp.risk_level, pdp.risk_score = Action.REQUIRE_MFA, RiskLevel.MEDIUM, 0.61
        assert _step_up_with(client, passkey)["outcome"] == LoginOutcome.AUTHENTICATED.value


@pytest.mark.parametrize(
    "why",
    ["monitor_allowed_a_risky_verdict", "engine_fallback", "engine_off"],
)
def test_an_allow_the_engine_did_not_judge_usual_offers_nothing(why: str) -> None:
    pdp = _usual_pdp()
    policies = StubPolicy()
    if why == "monitor_allowed_a_risky_verdict":
        pdp.action, pdp.enforced, pdp.engine_mode = Action.REAUTHENTICATE, Action.ALLOW, EngineMode.MONITOR
    elif why == "engine_fallback":
        pdp.fallback = True
    else:
        policies.policies["roku-bank"] = stub_policy("roku-bank", engine_mode=EngineMode.OFF)
    with _deployed(pdp, policy_client=policies) as client:
        body = client.post("/login", json=LOGIN).json()
        assert body["outcome"] == "AUTHENTICATED"
        assert "passkey_offer" not in body
        resp = client.post("/passkeys/options", headers=bearer(body["session"]["token"]))
        assert resp.status_code == 403


def test_the_offer_expires() -> None:
    with _deployed(_usual_pdp(), enroll_window_seconds=0) as client:
        body = client.post("/login", json=LOGIN).json()
        resp = client.post("/passkeys/options", headers=bearer(body["session"]["token"]))
        assert resp.status_code == 403


def test_enrollment_needs_a_session(client: TestClient) -> None:
    assert client.post("/passkeys/options").status_code == 401


# ================================================================ door 2: an activation code


def test_an_operator_code_plus_the_password_enrolls_a_passkey() -> None:
    passkey = SoftPasskey()
    with _deployed(_step_up_pdp()) as client:
        # Martín has no passkey and the bank steps him up: refused.
        assert client.post("/login", json=LOGIN).json()["outcome"] == "SECOND_FACTOR_MISSING"

        code = _issue_code(client)
        assert len(code) == 14 and code.count("-") == 2
        assert _activate(client, code.lower().replace("-", " "), passkey).status_code == 204

        assert _step_up_with(client, passkey)["outcome"] == LoginOutcome.AUTHENTICATED.value


def test_a_code_without_the_password_enrolls_nothing() -> None:
    with _deployed(_step_up_pdp()) as client:
        code = _issue_code(client)
        wrong_password = client.post(f"{ACTIVATE}/options", json={"code": code, "password": "nope"})
        wrong_code = client.post(
            f"{ACTIVATE}/options", json={"code": "AAAA-BBBB-CCCC", "password": "martin-demo"}
        )
        # Indistinguishable, so neither half can be confirmed on its own.
        assert wrong_password.status_code == wrong_code.status_code == 400
        assert wrong_password.json() == wrong_code.json() == {"detail": "invalid or expired code"}
        # The code survives a wrong password; it is single-use, not single-try.
        assert _activate(client, code, SoftPasskey()).status_code == 204


def test_a_code_works_once() -> None:
    with _deployed(_step_up_pdp()) as client:
        code = _issue_code(client)
        assert _activate(client, code, SoftPasskey()).status_code == 204
        assert _activate(client, code, SoftPasskey()).status_code == 400


def test_a_new_code_replaces_the_old_one() -> None:
    with _deployed(_step_up_pdp()) as client:
        old = _issue_code(client)
        new = _issue_code(client)
        assert _activate(client, old, SoftPasskey()).status_code == 400
        assert _activate(client, new, SoftPasskey()).status_code == 204


def test_a_code_expires() -> None:
    with _deployed(_step_up_pdp(), activation_ttl_seconds=0) as client:
        assert _activate(client, _issue_code(client), SoftPasskey()).status_code == 400


def test_issuing_a_code_is_a_write_inside_the_operators_tenant() -> None:
    with _deployed(_step_up_pdp()) as client:
        ana = _operator(client, ANA)  # support: reads only
        resp = client.post("/admin/api/users/usr_rb_martin/activation-code", headers=bearer(ana))
        assert resp.status_code == 403
        diego = _operator(client)
        resp = client.post("/admin/api/users/usr_kz_martin/activation-code", headers=bearer(diego))
        assert resp.status_code == 404


def test_the_activation_page_is_served(client: TestClient) -> None:
    resp = client.get(ACTIVATE)
    assert resp.status_code == 200
    assert 'id="form-activate"' in resp.text
    assert "/static/passkey.js" in resp.text


# ================================================================ break glass


def test_the_cli_issues_the_first_code(monkeypatch, capsys) -> None:
    """Fresh cloud databases: nobody has a passkey, so the first code comes
    from someone with access to the cluster."""
    with _deployed(_step_up_pdp()) as client:
        factory = client.app.state.session_factory
        monkeypatch.setattr(activation, "make_engine", lambda *a, **k: None)
        monkeypatch.setattr(activation, "make_session_factory", lambda _engine: factory)
        assert activation.main(["juan@rokusec.example", "--tenant", "rokusec"]) == 0
        code = capsys.readouterr().out.split()[0]
        resp = _activate(client, code, SoftPasskey(), password="juan-demo")
        assert resp.status_code == 204
        # A user of another tenant is not found by name alone.
        assert activation.main(["juan@rokusec.example", "--tenant", "roku-bank"]) == 1


def test_the_test_code_field_exists_only_where_the_mock_otp_does() -> None:
    """Locally the page offers the test code to a user with no passkey; a
    deployment never tells the page such a code exists."""
    with _deployed(_step_up_pdp()) as client:
        assert '"mock_otp": false' in client.get("/console/login").text
    with client_for(_step_up_pdp(), settings=make_settings(mock_otp_enabled=True)) as client:
        assert '"mock_otp": true' in client.get("/console/login").text
