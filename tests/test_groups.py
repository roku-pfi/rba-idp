"""IdP-7 groups / app-scoped access grants."""

from __future__ import annotations

from fastapi.testclient import TestClient
from rba_contracts import LoginOutcome

from tests.helpers import ADMIN_LOGIN, LOGIN

BANKING = "grp_banking"
OPERATORS = "grp_operators"


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _admin_token(client: TestClient) -> str:
    body = client.post("/login", json=ADMIN_LOGIN).json()
    assert body["outcome"] == "AUTHENTICATED", body
    return body["session"]["token"]


def test_seeded_groups(client: TestClient) -> None:
    token = _admin_token(client)
    listed = client.get("/admin/api/groups", headers=_auth(token))
    assert listed.status_code == 200
    by_id = {row["group_id"]: row for row in listed.json()}
    assert BANKING in by_id
    assert OPERATORS in by_id
    assert by_id[BANKING]["member_count"] == 1
    banking = client.get(f"/admin/api/groups/{BANKING}", headers=_auth(token)).json()
    assert {m["email"] for m in banking["members"]} == {"demo@example.com"}
    assert {g["application_id"] for g in banking["grants"]} == {"demo-banking-app"}
    operators = client.get(f"/admin/api/groups/{OPERATORS}", headers=_auth(token)).json()
    assert {g["application_id"] for g in operators["grants"]} == {
        "demo-banking-app",
        "idp-admin-console",
    }


def test_group_crud_members_and_grants(client: TestClient) -> None:
    token = _admin_token(client)
    created = client.post(
        "/admin/api/groups",
        headers=_auth(token),
        json={
            "group_id": "grp_forum",
            "name": "Forum users",
            "description": "Demo forum",
        },
    )
    assert created.status_code == 201
    assert created.json()["group_id"] == "grp_forum"
    assert created.json()["member_count"] == 0

    dup = client.post(
        "/admin/api/groups",
        headers=_auth(token),
        json={"group_id": "grp_forum", "name": "Other"},
    )
    assert dup.status_code == 409

    patched = client.patch(
        "/admin/api/groups/grp_forum",
        headers=_auth(token),
        json={"description": "Forum readers"},
    )
    assert patched.json()["description"] == "Forum readers"

    user = client.post(
        "/admin/api/users",
        headers=_auth(token),
        json={"email": "reader@example.com", "password": "reader-password"},
    ).json()
    app = client.post(
        "/admin/api/applications",
        headers=_auth(token),
        json={"application_id": "demo-forum-app", "name": "Demo forum"},
    )
    assert app.status_code == 201

    added = client.post(
        "/admin/api/groups/grp_forum/members",
        headers=_auth(token),
        json={"user_id": user["user_id"]},
    )
    assert added.status_code == 200
    assert added.json()["member_count"] == 1
    again = client.post(
        "/admin/api/groups/grp_forum/members",
        headers=_auth(token),
        json={"user_id": user["user_id"]},
    )
    assert again.status_code == 409

    granted = client.post(
        "/admin/api/groups/grp_forum/grants",
        headers=_auth(token),
        json={"application_id": "demo-forum-app"},
    )
    assert granted.status_code == 200
    assert granted.json()["grants"][0]["permission"] == "access"

    login = client.post(
        "/login",
        json={
            **LOGIN,
            "email": "reader@example.com",
            "password": "reader-password",
            "application_id": "demo-forum-app",
        },
    )
    assert login.json()["outcome"] == LoginOutcome.AUTHENTICATED.value

    client.delete(
        "/admin/api/groups/grp_forum/grants/demo-forum-app",
        headers=_auth(token),
    )
    denied = client.post(
        "/login",
        json={
            **LOGIN,
            "email": "reader@example.com",
            "password": "reader-password",
            "application_id": "demo-forum-app",
        },
    )
    assert denied.json()["outcome"] == LoginOutcome.ACCESS_DENIED.value

    client.post(
        "/admin/api/groups/grp_forum/grants",
        headers=_auth(token),
        json={"application_id": "demo-forum-app"},
    )
    client.delete(
        f"/admin/api/groups/grp_forum/members/{user['user_id']}",
        headers=_auth(token),
    )
    denied_member = client.post(
        "/login",
        json={
            **LOGIN,
            "email": "reader@example.com",
            "password": "reader-password",
            "application_id": "demo-forum-app",
        },
    )
    assert denied_member.json()["outcome"] == LoginOutcome.ACCESS_DENIED.value

    gone = client.delete("/admin/api/groups/grp_forum", headers=_auth(token))
    assert gone.status_code == 204
    assert (
        client.get("/admin/api/groups/grp_forum", headers=_auth(token)).status_code
        == 404
    )


def test_groups_require_admin(client: TestClient) -> None:
    token = client.post("/login", json=LOGIN).json()["session"]["token"]
    resp = client.get("/admin/api/groups", headers=_auth(token))
    assert resp.status_code == 403
