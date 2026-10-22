"""IdP-5: hosted login HTML on the IdP origin."""

from __future__ import annotations

import json
import re

from fastapi.testclient import TestClient

from rba_idp.client_ids import SEEDED
from tests.helpers import LOGIN

BANK_CLIENT = SEEDED["roku-bank-web"]

BOOT_RE = re.compile(
    r'<script type="application/json" id="boot">(.*?)</script>',
    re.S,
)


def _boot(html: str) -> dict:
    match = BOOT_RE.search(html)
    assert match, html
    return json.loads(match.group(1))


def test_hosted_login_page(client: TestClient) -> None:
    resp = client.get("/login", params={"client_id": BANK_CLIENT})
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    html = resp.text
    assert 'id="form-login"' in html
    assert 'id="panel-denied"' in html
    assert "/static/login.js" in html
    boot = _boot(html)
    assert boot["client_id"] == BANK_CLIENT
    # The internal id never reaches the browser.
    assert "roku-bank-web" not in html
    assert boot["application_name"] == "Roku Bank"
    assert boot["tenant_name"] == "Roku Bank"
    assert boot["console"] is False
    assert boot["unknown_application"] is False
    assert boot["ip_address"]
    assert boot["redirect_uri"] == "http://localhost:8002/callback"


def test_root_without_an_application_is_the_console_login(client: TestClient) -> None:
    resp = client.get("/")
    assert resp.status_code == 200
    assert 'id="form-login"' in resp.text
    boot = _boot(resp.text)
    assert boot["console"] is True
    assert boot["client_id"] is None
    assert boot["unknown_application"] is False


def test_hosted_login_unknown_application(client: TestClient) -> None:
    resp = client.get("/login", params={"client_id": "rk_notARegisteredApp"})
    assert resp.status_code == 200
    boot = _boot(resp.text)
    assert boot["client_id"] is None
    assert boot["unknown_application"] is True
    assert boot["application_name"] is None
    assert 'id="panel-unknown"' in resp.text


def test_forwarded_for_from_an_untrusted_peer_is_ignored(client: TestClient) -> None:
    """With no trusted proxy configured, a client cannot pick its address by
    sending its own X-Forwarded-For (ADR-0032)."""
    resp = client.get("/login", headers={"x-forwarded-for": "198.51.100.20"})
    boot = _boot(resp.text)
    assert boot["ip_address"] != "198.51.100.20"
    assert boot["country"] != "DE"
    assert boot["asn"] != "3320"


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


def test_static_assets_are_versioned_and_revalidated(client: TestClient) -> None:
    """A phone ran an old cached script against a new page; never again."""
    import re as _re

    for path in (f"/login?client_id={BANK_CLIENT}", "/activate"):
        html = client.get(path).text
        refs = _re.findall(r'/static/[\w.-]+\?v=([0-9a-f]{12})"', html)
        assert refs and len(set(refs)) == 1, path
        assert "/static/form.js?v=" in html
    resp = client.get("/static/login.js")
    assert resp.headers["cache-control"] == "no-cache"
    again = client.get("/static/login.js", headers={"if-none-match": resp.headers["etag"]})
    assert again.status_code == 304


def test_an_internal_application_id_in_the_url_is_not_a_login(client: TestClient) -> None:
    """Applications link with their public client_id; the internal id names
    nothing in a URL, so it cannot be guessed from how a tenant names apps."""
    boot = _boot(client.get("/login", params={"client_id": "roku-bank-web"}).text)
    assert boot["unknown_application"] is True


def test_a_login_by_client_id_is_the_same_login(client: TestClient) -> None:
    body = {key: value for key, value in LOGIN.items() if key != "application_id"}
    by_client = client.post("/login", json={**body, "client_id": BANK_CLIENT})
    assert by_client.status_code == 200
    assert by_client.json()["outcome"] in {"AUTHENTICATED", "MFA_REQUIRED"}
    unknown = client.post("/login", json={**body, "client_id": "rk_doesNotExist0000"})
    assert unknown.status_code == 400  # unknown application, like any unknown id
    both = client.post("/login", json={**body, "client_id": BANK_CLIENT, "application_id": "roku-bank-web"})
    assert both.status_code == 422


def test_every_application_has_a_client_id(client: TestClient) -> None:
    from rba_idp.db.models import Application

    with client.app.state.session_factory() as session:
        apps = session.query(Application).all()
    assert apps and all(app.client_id and app.client_id.startswith("rk_") for app in apps)
