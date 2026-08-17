"""IdP-5: hosted login HTML on the IdP origin."""

from __future__ import annotations

import json
import re

from fastapi.testclient import TestClient

from tests.helpers import LOGIN

BOOT_RE = re.compile(
    r'<script type="application/json" id="boot">(.*?)</script>',
    re.S,
)


def _boot(html: str) -> dict:
    match = BOOT_RE.search(html)
    assert match, html
    return json.loads(match.group(1))


def test_hosted_login_page(client: TestClient) -> None:
    resp = client.get("/login")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    html = resp.text
    assert 'id="form-login"' in html
    assert 'id="panel-denied"' in html
    assert "/static/login.js" in html
    boot = _boot(html)
    assert boot["application_id"] == "demo-banking-app"
    assert boot["application_name"] == "Demo banking app"
    assert boot["unknown_application"] is False
    assert boot["ip_address"]
    assert boot["redirect_uri"] == "http://localhost:8002/callback"


def test_root_serves_the_same_hosted_page(client: TestClient) -> None:
    resp = client.get("/")
    assert resp.status_code == 200
    assert 'id="form-login"' in resp.text


def test_hosted_login_unknown_application(client: TestClient) -> None:
    resp = client.get("/login", params={"application_id": "not-a-registered-app"})
    assert resp.status_code == 200
    boot = _boot(resp.text)
    assert boot["application_id"] == "not-a-registered-app"
    assert boot["unknown_application"] is True
    assert boot["application_name"] is None
    assert 'id="panel-unknown"' in resp.text


def test_hosted_login_uses_forwarded_ip(client: TestClient) -> None:
    resp = client.get("/login", headers={"x-forwarded-for": "198.51.100.20, 10.0.0.1"})
    boot = _boot(resp.text)
    assert boot["ip_address"] == "198.51.100.20"
    assert boot["country"] == "DE"
    assert boot["asn"] == "3320"


def test_hosted_login_country_override(client: TestClient) -> None:
    resp = client.get(
        "/login",
        params={"country": "jp", "asn": "AS2516"},
        headers={"x-forwarded-for": "203.0.113.10"},
    )
    boot = _boot(resp.text)
    assert boot["ip_address"] == "203.0.113.10"
    assert boot["country"] == "JP"
    assert boot["asn"] == "2516"


def test_hosted_login_junk_override_falls_back_to_prefix(client: TestClient) -> None:
    resp = client.get(
        "/login",
        params={"country": "Argentina", "asn": "nope"},
        headers={"x-forwarded-for": "203.0.113.10"},
    )
    boot = _boot(resp.text)
    assert boot["country"] == "AR"
    assert boot["asn"] == "7303"


def test_hosted_login_loopback_uses_home_testnet(client: TestClient) -> None:
    boot = _boot(client.get("/login").text)
    assert boot["ip_address"] == "203.0.113.10"
    assert boot["country"] == "AR"
    assert boot["asn"] == "7303"


def test_hosted_login_rejects_unknown_redirect_uri(client: TestClient) -> None:
    boot = _boot(
        client.get(
            "/login", params={"redirect_uri": "http://evil.example/callback"}
        ).text
    )
    assert boot["redirect_uri"] is None


def test_static_assets(client: TestClient) -> None:
    css = client.get("/static/login.css")
    js = client.get("/static/login.js")
    assert css.status_code == 200
    assert js.status_code == 200
    assert "RBA Identity" in css.text or "accent" in css.text
    assert "POST" in js.text
    assert "/login" in js.text
    assert "boot.country" in js.text
    assert "/mfa/webauthn/options" in js.text
    assert "/mfa/webauthn/verify" in js.text
    assert "Confirm it’s you" in js.text or "Confirm" in js.text
    assert "ACCESS_DENIED" in js.text
    assert "redirect_to" in js.text


def test_json_login_still_works_alongside_html(client: TestClient) -> None:
    resp = client.post("/login", json=LOGIN)
    assert resp.status_code == 200
    assert resp.json()["outcome"] == "AUTHENTICATED"
