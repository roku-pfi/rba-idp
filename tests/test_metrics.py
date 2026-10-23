"""IdP metrics (RF-20): what the IdP answered and whether step-ups were passed."""

from __future__ import annotations

from rba_contracts import LoginOutcome

from rba_idp import metrics


def _value(counter, **labels) -> float:
    return counter.labels(**labels)._value.get()


def test_logins_are_counted_by_surface_and_outcome() -> None:
    before = _value(metrics.LOGINS, surface="app", outcome="MFA_REQUIRED")
    metrics.observe_login("app", LoginOutcome.MFA_REQUIRED)
    assert _value(metrics.LOGINS, surface="app", outcome="MFA_REQUIRED") == before + 1


def test_a_step_up_is_passed_only_when_it_authenticates() -> None:
    passed = _value(metrics.STEP_UPS, method="passkey", result="passed")
    failed = _value(metrics.STEP_UPS, method="passkey", result="failed")
    metrics.observe_step_up("passkey", LoginOutcome.AUTHENTICATED)
    metrics.observe_step_up("passkey", LoginOutcome.INVALID_CREDENTIALS)
    assert _value(metrics.STEP_UPS, method="passkey", result="passed") == passed + 1
    assert _value(metrics.STEP_UPS, method="passkey", result="failed") == failed + 1


def test_the_listener_is_off_without_a_port() -> None:
    metrics.serve(0)
    assert metrics._started is False
