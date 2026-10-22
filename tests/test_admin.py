"""Admin console BFF (users, apps, decisions, policy), for one tenant's operator.

Cross-tenant isolation has its own file, `test_tenancy.py`.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from uuid import UUID

from fastapi.testclient import TestClient
from rba_contracts import Action, DecisionRecord, EngineMode, Reason, RiskLevel

from rba_idp.client_ids import SEEDED
from tests.helpers import (
    ADMIN_LOGIN,
    BANK,
    LOGIN,
    FailingAudit,
    StubAudit,
    StubPdp,
    client_for,
    console_token,
)

EVENT_ID = UUID("4f9a8c2e-1b3d-4a6f-9c8e-2d1b3a6f9c8e")
DECISION = DecisionRecord(
    event_id=EVENT_ID,
    occurred_at=datetime(2026, 8, 15, 12, 0, tzinfo=timezone.utc),
    tenant_id=BANK,
    application_id="roku-bank-web",
    user_id="usr_rb_martin",
    risk_score=0.61,
    risk_level=RiskLevel.MEDIUM,
    action=Action.REQUIRE_MFA,
    enforced_action=Action.REQUIRE_MFA,
    engine_mode=EngineMode.MONITOR,
    reasons=[
        Reason(
            code="signal_novel",
            signal="device_type",
            contribution=1.8,
            detail="device_type not previously seen for this user",
        )
    ],
    model_version="freeman-0.1.0",
    policy_version="1.0.0",
    feature_schema_version="1.0.0",
    fallback=False,
)


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _admin_token(client: TestClient) -> str:
    return console_token(client, ADMIN_LOGIN)


def test_admin_page(client: TestClient) -> None:
    resp = client.get("/admin")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    assert "<title>RokuSec</title>" in resp.text
    assert 'id="root"' in resp.text


def test_console_pages_are_urls(client: TestClient) -> None:
    """Every section has its own address; a reload lands on the same page."""
    for slug in ("resumen", "eventos", "eventos/4f9a8c2e", "politica", "usuarios", "grupos", "roles", "aplicaciones", "cuenta"):
        resp = client.get(f"/admin/{slug}")
        assert resp.status_code == 200 and 'id="root"' in resp.text, slug
    assert client.get("/admin/api/nope").status_code == 404


def test_admin_bundle_is_served(client: TestClient) -> None:
    index = client.get("/admin").text
    script = re.search(r'src="(/admin/assets/[^"]+\.js)"', index)
    assert script, index
    js = client.get(script.group(1))
    assert js.status_code == 200
    assert "/admin/api/policy" in js.text
    assert "/admin/api/groups" in js.text


def test_console_login_page_goes_to_admin(client: TestClient) -> None:
    resp = client.get("/console/login")
    assert resp.status_code == 200
    assert '"console": true' in resp.text
    assert '"next": "/admin"' in resp.text


def test_bank_session_is_forbidden_on_admin(client: TestClient) -> None:
    token = client.post("/login", json=LOGIN).json()["session"]["token"]
    resp = client.get("/admin/api/users", headers=_auth(token))
    assert resp.status_code == 403
    assert resp.json()["detail"] == "not a console session"


def test_support_operator_reads_but_cannot_write(client: TestClient) -> None:
    from tests.helpers import ANA

    token = console_token(client, ANA)
    assert client.get("/admin/api/users", headers=_auth(token)).status_code == 200
    resp = client.post(
        "/admin/api/users", headers=_auth(token), json={"email": "x@correo.example", "password": "x"}
    )
    assert resp.status_code == 403
    assert resp.json()["detail"] == "requires permission admin:write"
    resp = client.put("/admin/api/policy", headers=_auth(token), json={})
    assert resp.status_code in (403, 422)


def test_admin_requires_session(client: TestClient) -> None:
    assert client.get("/admin/api/users").status_code == 401


def test_a_user_row_says_groups_passkeys_and_last_login(client: TestClient) -> None:
    """What the Usuarios page shows without a second request per user."""
    token = _admin_token(client)
    rows = {row["email"]: row for row in client.get("/admin/api/users", headers=_auth(token)).json()}
    diego, martin = rows["diego@rokubank.example"], rows["martin@correo.example"]
    # Diego just signed in to the console; Martín has not signed in at all.
    assert diego["last_login_at"] is not None
    assert martin["last_login_at"] is None
    assert [g["name"] for g in diego["groups"]]
    assert martin["passkeys"] == 0


def test_admin_lists_users_and_creates(client: TestClient) -> None:
    token = _admin_token(client)
    listed = client.get("/admin/api/users", headers=_auth(token))
    assert listed.status_code == 200
    emails = {row["email"] for row in listed.json()}
    assert "diego@rokubank.example" in emails
    assert "martin@correo.example" in emails
    assert {row["tenant_id"] for row in listed.json()} == {BANK}
    admin = next(row for row in listed.json() if row["email"] == "diego@rokubank.example")
    assert admin["is_admin"] is True
    assert "password" not in admin
    assert "password_hash" not in admin

    created = client.post(
        "/admin/api/users",
        headers=_auth(token),
        json={
            "email": "analyst@rokubank.example",
            "password": "analyst-password",
            "is_admin": False,
        },
    )
    assert created.status_code == 201
    assert created.json()["email"] == "analyst@rokubank.example"
    assert created.json()["tenant_id"] == BANK
    assert created.json()["is_admin"] is False

    dup = client.post(
        "/admin/api/users",
        headers=_auth(token),
        json={"email": "analyst@rokubank.example", "password": "x"},
    )
    assert dup.status_code == 409

    patched = client.patch(
        f"/admin/api/users/{created.json()['user_id']}",
        headers=_auth(token),
        json={"enabled": False},
    )
    assert patched.status_code == 200
    assert patched.json()["enabled"] is False


def test_admin_applications(client: TestClient) -> None:
    token = _admin_token(client)
    listed = client.get("/admin/api/applications", headers=_auth(token))
    ids = {row["application_id"] for row in listed.json()}
    assert ids == {"roku-bank-web", "roku-bank-console"}
    banking = next(
        row for row in listed.json() if row["application_id"] == "roku-bank-web"
    )
    assert banking["redirect_uri"] == "http://localhost:8002/callback"

    created = client.post(
        "/admin/api/applications",
        headers=_auth(token),
        json={"application_id": "roku-bank-app", "name": "Roku Bank app"},
    )
    assert created.status_code == 201
    assert created.json()["tenant_id"] == BANK
    patched = client.patch(
        "/admin/api/applications/roku-bank-app",
        headers=_auth(token),
        json={"enabled": False},
    )
    assert patched.json()["enabled"] is False


def test_console_cannot_be_disabled(client: TestClient) -> None:
    token = _admin_token(client)
    resp = client.patch(
        "/admin/api/applications/roku-bank-console",
        headers=_auth(token),
        json={"enabled": False},
    )
    assert resp.status_code == 409


def test_admin_session_exposes_is_admin(client: TestClient) -> None:
    demo = client.get(
        "/session",
        headers=_auth(client.post("/login", json=LOGIN).json()["session"]["token"]),
    ).json()
    assert demo["user"]["is_admin"] is False
    admin = client.get(
        "/session",
        headers=_auth(_admin_token(client)),
    ).json()
    assert admin["user"]["is_admin"] is True
    assert admin["user"]["email"] == "diego@rokubank.example"
    assert admin["user"]["tenant_id"] == BANK
    assert admin["application_id"] == "roku-bank-console"


def test_admin_decision_browser_includes_reasons() -> None:
    with client_for(StubPdp(), audit_client=StubAudit([DECISION])) as client:
        token = _admin_token(client)
        listed = client.get("/admin/api/decisions", headers=_auth(token))
        assert listed.status_code == 200
        body = listed.json()
        assert body["count"] == 1
        item = body["items"][0]
        assert item["action"] == "REQUIRE_MFA"
        assert item["reasons"][0]["signal"] == "device_type"
        got = client.get(f"/admin/api/decisions/{EVENT_ID}", headers=_auth(token))
        assert got.status_code == 200
        assert got.json()["user_id"] == "usr_rb_martin"


def test_admin_decisions_fail_closed_when_audit_down() -> None:
    with client_for(StubPdp(), audit_client=FailingAudit()) as client:
        token = _admin_token(client)
        resp = client.get("/admin/api/decisions", headers=_auth(token))
        assert resp.status_code == 503
        assert resp.json()["detail"] == "decision store unavailable"


def test_admin_policy_get_and_put(client: TestClient) -> None:
    token = _admin_token(client)
    got = client.get("/admin/api/policy", headers=_auth(token))
    assert got.status_code == 200
    body = got.json()
    assert body["tenant_id"] == BANK
    assert body["policy_version"] == "1.0.0"
    body["policy_version"] = "1.0.0-from-admin"
    put = client.put("/admin/api/policy", headers=_auth(token), json=body)
    assert put.status_code == 200
    assert put.json()["policy_version"] == "1.0.0-from-admin"
    assert client.get("/admin/api/policy", headers=_auth(token)).json()[
        "policy_version"
    ] == "1.0.0-from-admin"


def test_login_styles_and_fonts_are_served(client: TestClient) -> None:
    """The login and activation pages hang off login.css, and it hangs off the
    woff2 files next to it. A 404 on either is silent (the page renders in the
    wrong face), so it is asserted here."""
    css = client.get("/static/login.css")
    assert css.status_code == 200
    for look in ('[data-look="console"]', '[data-look="tenant"]'):
        assert look in css.text

    # Self-hosted on purpose: a login page should not hand a third-party CDN a
    # request on every sign-in attempt.
    assert "fonts.googleapis.com" not in css.text
    assert "fonts.gstatic.com" not in css.text

    for name in ("ibm-plex-sans-latin-400-normal", "ibm-plex-sans-latin-600-normal", "ibm-plex-mono-400-latin"):
        assert f"fonts/{name}.woff2" in css.text
        served = client.get(f"/static/fonts/{name}.woff2")
        assert served.status_code == 200, name
        assert served.content[:4] == b"wOF2", name


def test_the_login_looks_like_where_you_are_going(client: TestClient) -> None:
    """ADR-0036: the console's login is RokuSec's, dark; an app's follows its
    tenant: Kaze Labs uses RokuSec's page (light), Roku Bank its own."""
    console = client.get("/console/login").text
    assert 'data-look="console"' in console

    kaze = client.get(f"/login?client_id={SEEDED['kaze-portal']}").text
    assert 'data-look="rokusec"' in kaze

    bank = client.get(f"/login?client_id={SEEDED['roku-bank-web']}").text
    assert 'data-look="tenant"' in bank
    assert "--t-primary:" in bank
    assert "Protegido por RokuSec" in bank
    # The bank's own mark, served by the bank (B-3).
    assert "localhost:8002/static/brand/roku-bank-mark.svg" in bank
    assert "Protegido por RokuSec" not in kaze


def test_every_static_file_ships_in_the_package() -> None:
    """Static files are package data. A folder missing from pyproject's list
    works from the source tree and 404s in the image (it happened to brand/)."""
    import tomllib
    from fnmatch import fnmatch
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    patterns = tomllib.loads((root / "pyproject.toml").read_text())["tool"]["setuptools"]["package-data"]["rba_idp"]
    package = root / "src" / "rba_idp"
    web = [p for p in (package / "web").rglob("*") if p.is_file() and "__pycache__" not in p.parts and p.suffix != ".py"]
    unshipped = [
        str(p.relative_to(package)) for p in web if not any(fnmatch(str(p.relative_to(package)), pat) and "/" not in str(p.relative_to(package))[len(pat.rstrip("*")):] for pat in patterns)
    ]
    assert unshipped == []


def test_the_effectiveness_numbers_are_served_to_operators(client: TestClient) -> None:
    """D-2's comparison, for the console's Efectividad page."""
    assert client.get("/admin/api/effectiveness").status_code == 401
    body = client.get("/admin/api/effectiveness", headers=_auth(_admin_token(client))).json()
    assert body["meta"]["ato"] == 38
    assert body["policies"]["adaptive_default"]["ato_stopped"]["k"] == 32
