"""IdP-6 admin console BFF (users, apps, decisions, policy)."""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

from fastapi.testclient import TestClient
from rba_contracts import Action, DecisionRecord, Reason, RiskLevel

from tests.helpers import ADMIN_LOGIN, LOGIN, FailingAudit, StubAudit, StubPdp, client_for

EVENT_ID = UUID("4f9a8c2e-1b3d-4a6f-9c8e-2d1b3a6f9c8e")
DECISION = DecisionRecord(
    event_id=EVENT_ID,
    occurred_at=datetime(2026, 8, 15, 12, 0, tzinfo=timezone.utc),
    application_id="demo-banking-app",
    user_id="usr_demo",
    risk_score=0.61,
    risk_level=RiskLevel.MEDIUM,
    action=Action.REQUIRE_MFA,
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
    body = client.post("/login", json=ADMIN_LOGIN).json()
    assert body["outcome"] == "AUTHENTICATED", body
    return body["session"]["token"]


def test_admin_page(client: TestClient) -> None:
    resp = client.get("/admin")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    assert "RBA Admin" in resp.text
    assert "/static/admin.js" in resp.text or 'id="root"' in resp.text


def test_admin_static_assets(client: TestClient) -> None:
    css = client.get("/static/admin.css")
    js = client.get("/static/admin.js")
    assert css.status_code == 200
    assert js.status_code == 200
    assert "Decisions" in js.text
    assert "/admin/api/policy" in js.text
    assert "/admin/api/groups" in js.text


def test_hosted_login_forwards_next(client: TestClient) -> None:
    resp = client.get(
        "/login",
        params={"application_id": "idp-admin-console", "next": "/admin"},
    )
    assert resp.status_code == 200
    assert '"next": "/admin"' in resp.text or "/admin" in resp.text


def test_demo_user_is_forbidden_on_admin(client: TestClient) -> None:
    token = client.post("/login", json=LOGIN).json()["session"]["token"]
    resp = client.get("/admin/api/users", headers=_auth(token))
    assert resp.status_code == 403
    assert resp.json()["detail"] == "admin required"


def test_admin_requires_session(client: TestClient) -> None:
    assert client.get("/admin/api/users").status_code == 401


def test_admin_lists_users_and_creates(client: TestClient) -> None:
    token = _admin_token(client)
    listed = client.get("/admin/api/users", headers=_auth(token))
    assert listed.status_code == 200
    emails = {row["email"] for row in listed.json()}
    assert "admin@example.com" in emails
    assert "demo@example.com" in emails
    admin = next(row for row in listed.json() if row["email"] == "admin@example.com")
    assert admin["is_admin"] is True
    assert "password" not in admin
    assert "password_hash" not in admin

    created = client.post(
        "/admin/api/users",
        headers=_auth(token),
        json={
            "email": "analyst@example.com",
            "password": "analyst-password",
            "is_admin": False,
        },
    )
    assert created.status_code == 201
    assert created.json()["email"] == "analyst@example.com"
    assert created.json()["is_admin"] is False

    dup = client.post(
        "/admin/api/users",
        headers=_auth(token),
        json={"email": "analyst@example.com", "password": "x"},
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
    assert "demo-banking-app" in ids
    assert "idp-admin-console" in ids
    banking = next(
        row for row in listed.json() if row["application_id"] == "demo-banking-app"
    )
    assert banking["redirect_uri"] == "http://localhost:8002/callback"

    created = client.post(
        "/admin/api/applications",
        headers=_auth(token),
        json={"application_id": "demo-forum-app", "name": "Demo forum"},
    )
    assert created.status_code == 201
    patched = client.patch(
        "/admin/api/applications/demo-forum-app",
        headers=_auth(token),
        json={"enabled": False},
    )
    assert patched.json()["enabled"] is False


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
    assert admin["user"]["email"] == "admin@example.com"


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
        assert got.json()["user_id"] == "usr_demo"


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
    assert body["policy_version"] == "1.0.0"
    body["policy_version"] = "1.0.0-from-admin"
    put = client.put("/admin/api/policy", headers=_auth(token), json=body)
    assert put.status_code == 200
    assert put.json()["policy_version"] == "1.0.0-from-admin"
    assert client.get("/admin/api/policy", headers=_auth(token)).json()[
        "policy_version"
    ] == "1.0.0-from-admin"
