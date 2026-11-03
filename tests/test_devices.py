"""RF-02 (ADR-0047): the IdP's device cookie and the id the PDP sees."""

from __future__ import annotations

from fastapi.testclient import TestClient

from rba_idp.devices import COOKIE, device_id
from tests.helpers import DIEGO, LOGIN, StubPdp


def test_a_login_sets_a_long_lived_http_only_device_cookie(client: TestClient) -> None:
    resp = client.post("/login", json=LOGIN)
    header = resp.headers["set-cookie"].lower()
    assert header.startswith(f"{COOKIE}=")
    assert "httponly" in header and "samesite=lax" in header and "max-age=" in header


def test_the_pdp_sees_the_same_tenant_hash_on_every_login(client: TestClient, pdp: StubPdp) -> None:
    client.post("/login", json=LOGIN)
    raw = client.cookies.get(COOKIE)
    client.post("/login", json=LOGIN)
    first, second = pdp.calls[-2], pdp.calls[-1]
    assert first.device_id == second.device_id == device_id("roku-bank", raw)
    assert raw not in first.model_dump_json()  # only the hash leaves the IdP


def test_the_console_door_reports_the_device_too(client: TestClient, pdp: StubPdp) -> None:
    client.post("/console/login", json=DIEGO)
    assert pdp.calls[-1].device_id == device_id("roku-bank", client.cookies.get(COOKIE))


def test_a_malformed_cookie_is_replaced(client: TestClient) -> None:
    resp = client.post("/login", json=LOGIN, headers={"cookie": f"{COOKIE}=not-valid"})
    issued = resp.headers["set-cookie"].split(";", 1)[0].split("=", 1)[1]
    assert issued != "not-valid" and len(issued) >= 32


def test_one_browser_is_a_different_device_to_each_tenant() -> None:
    assert device_id("roku-bank", "x" * 43) != device_id("kaze-labs", "x" * 43)
    assert device_id("roku-bank", None) is None
