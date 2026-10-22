"""Groups and role assignment (ADR-0029).

Groups answer *who*; roles answer *what you may do*. Holding a role on an
application is what grants sign-in to it, so these tests check both halves:
losing the role must close the door, and losing the group membership must close
it too.
"""

from __future__ import annotations

from fastapi.testclient import TestClient
from rba_contracts import LoginOutcome

from tests.helpers import ADMIN_LOGIN, LOGIN, console_token

BANKING = "grp_rb_customers"
ADMINS = "grp_roku_bank_admins"
VIEWERS = "grp_rb_viewers"
SUPPORT = "grp_rb_support"


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _admin_token(client: TestClient) -> str:
    return console_token(client, ADMIN_LOGIN)


def _forum_login(client: TestClient):
    return client.post(
        "/login",
        json={
            **LOGIN,
            "email": "reader@correo.example",
            "password": "reader-password",
            "application_id": "roku-bank-forum",
        },
    )


def test_seeded_groups(client: TestClient) -> None:
    token = _admin_token(client)
    listed = client.get("/admin/api/groups", headers=_auth(token))
    assert listed.status_code == 200
    by_id = {row["group_id"]: row for row in listed.json()}
    assert by_id.keys() == {BANKING, VIEWERS, SUPPORT, ADMINS}
    assert by_id[BANKING]["member_count"] == 1

    banking = client.get(f"/admin/api/groups/{BANKING}", headers=_auth(token)).json()
    assert {m["email"] for m in banking["members"]} == {"martin@correo.example"}
    assert {r["name"] for r in banking["roles"]} == {"customer"}

    viewers = client.get(f"/admin/api/groups/{VIEWERS}", headers=_auth(token)).json()
    assert {m["email"] for m in viewers["members"]} == {"sofia@correo.example"}
    assert {r["name"] for r in viewers["roles"]} == {"viewer"}

    admins = client.get(f"/admin/api/groups/{ADMINS}", headers=_auth(token)).json()
    assert {(r["application_id"], r["name"]) for r in admins["roles"]} == {
        ("roku-bank-console", "tenant-admin"),
    }

    support = client.get(f"/admin/api/groups/{SUPPORT}", headers=_auth(token)).json()
    assert {r["name"] for r in support["roles"]} == {"support"}


def test_group_crud_members_and_roles(client: TestClient) -> None:
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
        json={"email": "reader@correo.example", "password": "reader-password"},
    ).json()
    app = client.post(
        "/admin/api/applications",
        headers=_auth(token),
        json={"application_id": "roku-bank-forum", "name": "Demo forum"},
    )
    assert app.status_code == 201

    role = client.post(
        "/admin/api/roles",
        headers=_auth(token),
        json={
            "role_id": "role_forum_reader",
            "application_id": "roku-bank-forum",
            "name": "reader",
            "description": "Read threads",
        },
    )
    assert role.status_code == 201
    assert role.json()["permission_count"] == 0

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

    # A member of a group with no role here still cannot sign in.
    assert _forum_login(client).json()["outcome"] == LoginOutcome.ACCESS_DENIED.value

    assigned = client.post(
        "/admin/api/groups/grp_forum/roles",
        headers=_auth(token),
        json={"role_id": "role_forum_reader"},
    )
    assert assigned.status_code == 200
    assert assigned.json()["roles"][0]["name"] == "reader"
    assert (
        client.post(
            "/admin/api/groups/grp_forum/roles",
            headers=_auth(token),
            json={"role_id": "role_forum_reader"},
        ).status_code
        == 409
    )

    # A role with zero permissions still grants sign-in — that is the point of
    # making the role itself the grant.
    assert _forum_login(client).json()["outcome"] == LoginOutcome.AUTHENTICATED.value

    client.delete(
        "/admin/api/groups/grp_forum/roles/role_forum_reader",
        headers=_auth(token),
    )
    assert _forum_login(client).json()["outcome"] == LoginOutcome.ACCESS_DENIED.value

    # Re-assign, then remove the *membership* instead: the other way to lose it.
    client.post(
        "/admin/api/groups/grp_forum/roles",
        headers=_auth(token),
        json={"role_id": "role_forum_reader"},
    )
    client.delete(
        f"/admin/api/groups/grp_forum/members/{user['user_id']}",
        headers=_auth(token),
    )
    assert _forum_login(client).json()["outcome"] == LoginOutcome.ACCESS_DENIED.value

    gone = client.delete("/admin/api/groups/grp_forum", headers=_auth(token))
    assert gone.status_code == 204
    assert (
        client.get("/admin/api/groups/grp_forum", headers=_auth(token)).status_code
        == 404
    )
    # Deleting the group must not delete the role it referenced.
    assert (
        client.get("/admin/api/roles/role_forum_reader", headers=_auth(token)).status_code
        == 200
    )


def test_groups_require_admin(client: TestClient) -> None:
    token = client.post("/login", json=LOGIN).json()["session"]["token"]
    resp = client.get("/admin/api/groups", headers=_auth(token))
    assert resp.status_code == 403
