"""RF-08 (ADR-0048): a user or an application that always asks for the passkey."""

from __future__ import annotations

from fastapi.testclient import TestClient
from rba_contracts import EngineMode, LoginOutcome

from tests.helpers import DIEGO, LOGIN, StubPdp, bearer, client_for, console_token


def _set(client: TestClient, path: str, value: bool) -> dict:
    token = console_token(client, DIEGO)
    resp = client.patch(path, headers=bearer(token), json={"always_passkey": value})
    assert resp.status_code == 200, resp.text
    return resp.json()


def test_a_user_switch_turns_a_usual_login_into_a_passkey(client: TestClient, pdp: StubPdp) -> None:
    assert client.post("/login", json=LOGIN).json()["outcome"] == LoginOutcome.AUTHENTICATED.value
    assert _set(client, "/admin/api/users/usr_rb_martin", True)["always_passkey"] is True

    body = client.post("/login", json=LOGIN).json()
    assert body["outcome"] == LoginOutcome.MFA_REQUIRED.value
    assert pdp.calls[-1].step_up_required is True
    assert "unusual" not in body  # a rule asked, not the engine

    _set(client, "/admin/api/users/usr_rb_martin", False)
    assert client.post("/login", json=LOGIN).json()["outcome"] == LoginOutcome.AUTHENTICATED.value
    assert pdp.calls[-1].step_up_required is False


def test_an_application_switch_applies_to_everyone_signing_in_to_it(client: TestClient, pdp: StubPdp) -> None:
    assert _set(client, "/admin/api/applications/roku-bank-web", True)["always_passkey"] is True
    body = client.post("/login", json=LOGIN).json()
    assert body["outcome"] == LoginOutcome.MFA_REQUIRED.value
    assert pdp.calls[-1].step_up_required is True


def test_it_holds_with_the_engine_off() -> None:
    """The engine is not called at all; the IdP still asks for the passkey."""
    pdp = StubPdp()
    with client_for(pdp) as client:
        _set(client, "/admin/api/users/usr_rb_martin", True)
        token = console_token(client, DIEGO)
        policy = client.get("/admin/api/policy", headers=bearer(token)).json()
        policy["engine_mode"] = EngineMode.OFF.value
        assert client.put("/admin/api/policy", headers=bearer(token), json=policy).status_code == 200
        before = len(pdp.calls)
        body = client.post("/login", json=LOGIN).json()
    assert body["outcome"] == LoginOutcome.MFA_REQUIRED.value
    assert len(pdp.calls) == before
