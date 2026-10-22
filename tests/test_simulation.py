"""C-3 / ADR-0032: overrides need a signed ticket where client signals are not trusted."""

from __future__ import annotations

import json
import re

import pytest
from fastapi.testclient import TestClient

from rba_idp.simulation import issue_ticket, verify_ticket
from tests.helpers import LOGIN, StubPdp, client_for
from tests.helpers import test_settings as make_settings

SECRET = "s" * 40
HEADER = {"X-RokuSec-Simulation-Secret": SECRET}


def _cloudlike(pdp: StubPdp, **over) -> TestClient:
    values = {
        "trust_client_reported_ip": False,
        "private_ip_is_home": False,
        "simulation_secret": SECRET,
        **over,
    }
    settings = make_settings(**values)
    return client_for(pdp, settings=settings)


def _boot(html: str) -> dict:
    return json.loads(re.search(r'<script type="application/json" id="boot">(.*?)</script>', html, re.S).group(1))


# ---------------------------------------------------------------- the ticket


def test_a_ticket_round_trips() -> None:
    ticket, _ = issue_ticket(SECRET, country="JP", asn="2516", ttl_seconds=60)
    signals = verify_ticket(SECRET, ticket)
    assert (signals.country, signals.asn) == ("JP", "2516")


@pytest.mark.parametrize("mutate", ["forged", "expired", "other-secret", "garbage", "empty"])
def test_a_bad_ticket_is_nothing(mutate: str) -> None:
    ticket, _ = issue_ticket(SECRET, country="JP", asn=None, ttl_seconds=60, now=1000.0)
    if mutate == "forged":
        payload, _, sig = ticket.partition(".")
        other, _ = issue_ticket(SECRET, country="AR", asn=None, ttl_seconds=60, now=1000.0)
        ticket = other.partition(".")[0] + "." + sig
        assert verify_ticket(SECRET, ticket, now=1001.0) is None
    elif mutate == "expired":
        assert verify_ticket(SECRET, ticket, now=2000.0) is None
    elif mutate == "other-secret":
        assert verify_ticket("t" * 40, ticket, now=1001.0) is None
    elif mutate == "garbage":
        assert verify_ticket(SECRET, "abc.def") is None
    else:
        assert verify_ticket("", ticket) is None and verify_ticket(SECRET, None) is None


# ---------------------------------------------------------------- the endpoint


def test_tickets_need_the_secret() -> None:
    with _cloudlike(StubPdp()) as client:
        assert client.post("/simulation/ticket", json={"country": "JP"}).status_code == 404
        wrong = {"X-RokuSec-Simulation-Secret": "x" * 40}
        assert client.post("/simulation/ticket", json={"country": "JP"}, headers=wrong).status_code == 404
        ok = client.post("/simulation/ticket", json={"country": "jp"}, headers=HEADER)
        assert ok.status_code == 200
        assert verify_ticket(SECRET, ok.json()["ticket"]).country == "JP"


def test_without_a_configured_secret_there_is_no_simulation() -> None:
    with _cloudlike(StubPdp(), simulation_secret="") as client:
        assert client.post("/simulation/ticket", json={"country": "JP"}, headers=HEADER).status_code == 404


# ---------------------------------------------------------------- the login path


def test_a_bare_override_is_dropped_where_clients_are_not_trusted() -> None:
    """An attacker claiming the victim's home country gets nothing for it."""
    pdp = StubPdp()
    with _cloudlike(pdp) as client:
        client.post("/login", json={**LOGIN, "country": "AR", "asn": "7303"})
        page = _boot(client.get("/login", params={"application_id": "roku-bank-web", "country": "AR"}).text)
    call = pdp.calls[0]
    assert (call.country, call.asn, call.simulated) == (None, None, False)
    assert page["country"] is None and page["simulation_ticket"] is None


def test_a_ticketed_override_is_applied_and_marked_simulated() -> None:
    pdp = StubPdp()
    with _cloudlike(pdp) as client:
        ticket = client.post("/simulation/ticket", json={"country": "JP", "asn": "2516"}, headers=HEADER).json()["ticket"]
        # The presenter's link carries the ticket; the page passes it on.
        page = _boot(client.get("/login", params={"application_id": "roku-bank-web", "simulation_ticket": ticket}).text)
        assert (page["country"], page["simulated"], page["simulation_ticket"]) == ("JP", True, ticket)
        client.post("/login", json={**LOGIN, "simulation_ticket": ticket})
    call = pdp.calls[0]
    assert (call.country, call.asn, call.simulated) == ("JP", "2516", True)


def test_locally_an_override_that_changes_the_country_is_marked_simulated() -> None:
    pdp = StubPdp()
    with client_for(pdp) as client:
        home = {**LOGIN, "ip_address": "203.0.113.10", "asn": "7303"}
        client.post("/login", json={**home, "country": "AR"})  # what the address says anyway
        client.post("/login", json={**home, "country": "JP"})
    assert [(c.country, c.simulated) for c in pdp.calls] == [("AR", False), ("JP", True)]
