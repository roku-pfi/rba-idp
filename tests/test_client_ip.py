"""C-2 / ADR-0032: the scored address is the client's, as seen by a trusted proxy.

The threat: an attacker holding Martín's password, logging in from abroad,
claims Martín's usual address so the login looks like home.
"""

from __future__ import annotations

import pytest
from starlette.requests import Request

from rba_idp.geo import HOME_IP, is_unroutable, scored_ip
from rba_idp.web.context import client_ip
from tests.helpers import LOGIN, StubPdp, client_for
from tests.helpers import test_settings as make_settings

ALB = "10.0.3.17"  # inside the public subnets
PROXIES = "10.0.0.0/20,10.0.16.0/20"


def _request(peer: str, headers: dict[str, str]) -> Request:
    return Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/",
            "headers": [(k.lower().encode(), v.encode()) for k, v in headers.items()],
            "client": (peer, 51000),
        }
    )


def _settings(**over):
    return make_settings(trusted_proxy_cidrs=PROXIES, **over)


def test_without_trusted_proxies_the_peer_is_the_client() -> None:
    req = _request("198.51.100.7", {"x-forwarded-for": "203.0.113.10"})
    assert client_ip(req, make_settings()) == "198.51.100.7"


def test_an_untrusted_peer_cannot_forward_an_address() -> None:
    req = _request("192.0.2.50", {"x-forwarded-for": "203.0.113.10"})
    assert client_ip(req, _settings()) == "192.0.2.50"


def test_right_most_untrusted_hop_wins_behind_a_trusted_proxy() -> None:
    """The client may prepend anything; only what our proxy appended counts."""
    req = _request(ALB, {"x-forwarded-for": "203.0.113.10, 192.0.2.50"})
    assert client_ip(req, _settings()) == "192.0.2.50"


def test_a_chain_of_trusted_proxies_is_skipped() -> None:
    req = _request(ALB, {"x-forwarded-for": "192.0.2.50, 10.0.17.4"})
    assert client_ip(req, _settings()) == "192.0.2.50"


@pytest.mark.parametrize(
    ("header", "expected"),
    [
        ("192.0.2.50:46532", "192.0.2.50"),
        ("2001:db8:85a3::8a2e:370:7334:46532", "2001:db8:85a3::8a2e:370:7334"),
    ],
)
def test_behind_cloudfront_the_viewer_header_is_used(header: str, expected: str) -> None:
    """CloudFront appends the edge to X-Forwarded-For, so XFF's right-most
    untrusted hop would be CloudFront itself."""
    req = _request(
        ALB,
        {"cloudfront-viewer-address": header, "x-forwarded-for": f"{expected}, 130.176.1.1"},
    )
    assert client_ip(req, _settings(client_ip_header="cloudfront-viewer-address")) == expected


def test_a_malformed_viewer_header_falls_back_to_the_peer() -> None:
    req = _request(ALB, {"cloudfront-viewer-address": "not-an-address"})
    assert client_ip(req, _settings(client_ip_header="cloudfront-viewer-address")) == ALB


def test_the_body_address_is_replaced_when_clients_are_not_trusted() -> None:
    """The hosted page posts the address it was given; a curl can post any."""
    pdp = StubPdp()
    settings = make_settings(trust_client_reported_ip=False, private_ip_is_home=False)
    with client_for(pdp, settings=settings) as client:
        client.post("/login", json={**LOGIN, "ip_address": "203.0.113.10"})
        client.post(
            "/console/login",
            json={"email": "diego@rokubank.example", "password": "diego-demo",
                  "ip_address": "203.0.113.10"},
        )
    # TestClient's peer is "testclient": not an address, so not home either.
    assert [c.ip_address for c in pdp.calls] == ["testclient", "testclient"]


def test_locally_the_body_address_is_still_honoured() -> None:
    pdp = StubPdp()
    with client_for(pdp) as client:
        client.post("/login", json={**LOGIN, "ip_address": "192.0.2.1"})
    assert pdp.calls[0].ip_address == "192.0.2.1"
    assert pdp.calls[0].country == "AR"  # the body's override, as before


@pytest.mark.parametrize(
    ("ip", "unroutable"),
    [
        ("10.1.2.3", True),
        ("192.168.1.1", True),
        ("::1", True),
        ("fe80::1", True),
        ("fd00::1", True),  # ULA
        ("::ffff:10.0.0.1", True),
        ("2001:db8::1", False),  # global IPv6 used to count as "home"
        ("2800:810:4c2::1", False),
        ("203.0.113.10", False),
    ],
)
def test_unroutable_addresses(ip: str, unroutable: bool) -> None:
    assert is_unroutable(ip) is unroutable


def test_a_private_address_is_home_only_when_configured() -> None:
    assert scored_ip("10.0.3.17") == HOME_IP
    assert scored_ip("10.0.3.17", private_is_home=False) == "10.0.3.17"
    assert scored_ip("2001:db8::1") == "2001:db8::1"
