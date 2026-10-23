"""Authentication metrics (RF-20 / RNF-04).

The PDP exports scores and decisions; these are the IdP's side of a login: what
it answered, and whether the step-up was passed. Served on their own port,
inside the cluster only: the IdP's HTTP port is public through CloudFront.
"""

from __future__ import annotations

from prometheus_client import Counter, start_http_server

LOGINS = Counter(
    "rba_idp_logins_total",
    "Answers to a password, by surface (app or console) and outcome",
    labelnames=("surface", "outcome"),
)
STEP_UPS = Counter(
    "rba_idp_step_ups_total",
    "Step-up attempts by method and result (passed, failed)",
    labelnames=("method", "result"),
)
PDP_UNAVAILABLE = Counter(
    "rba_idp_pdp_unavailable_total",
    "Logins decided by the IdP's fallback because the PDP did not answer (ADR-0028)",
)

_started = False


def serve(port: int) -> None:
    """Start the metrics listener once per process; 0 disables it (tests)."""
    global _started
    if port and not _started:
        start_http_server(port)
        _started = True


def observe_login(surface: str, outcome) -> None:
    LOGINS.labels(surface=surface, outcome=getattr(outcome, "value", outcome) or "none").inc()


def observe_step_up(method: str, outcome) -> None:
    passed = getattr(outcome, "value", outcome) == "AUTHENTICATED"
    STEP_UPS.labels(method=method, result="passed" if passed else "failed").inc()
