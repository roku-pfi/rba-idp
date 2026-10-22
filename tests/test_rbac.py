"""RBAC: user → group → role → permission (ADR-0029).

The claims under test are the ones RF-13 and RF-21 actually make: permissions
resolve through the chain and nowhere else; they are scoped to one application;
and the console's own guards distinguish reading a decision from changing who
may log in.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from tests.helpers import ADMIN_LOGIN, ANA, LOGIN, LUCAS, SIGNALS

BANK = "roku-bank-web"
CONSOLE = "roku-bank-console"

CUSTOMER_LOGIN = LOGIN
VIEWER_LOGIN = {**LOGIN, "email": "sofia@correo.example", "password": "sofia-demo"}
SUPPORT_LOGIN = ANA


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _token(client: TestClient, payload: dict) -> str:
    # An app login names its application; a console login names none.
    path = "/login" if "application_id" in payload else "/console/login"
    body = client.post(path, json=payload).json()
    assert body["outcome"] == "AUTHENTICATED", body
    return body["session"]["token"]


def _session(client: TestClient, payload: dict) -> dict:
    token = _token(client, payload)
    resp = client.get("/session", headers=_auth(token))
    assert resp.status_code == 200
    return resp.json()


# ------------------------------------------------------------- resolution


def test_customer_permissions_resolve_through_the_chain(client: TestClient) -> None:
    body = _session(client, CUSTOMER_LOGIN)
    assert body["application_id"] == BANK
    assert body["permissions"] == [
        "account:read",
        "transaction:read",
        "transfer:create",
    ]


def test_viewer_is_the_same_user_one_permission_short(client: TestClient) -> None:
    """The whole demonstration of RF-21 in one assertion."""
    body = _session(client, VIEWER_LOGIN)
    assert body["permissions"] == ["account:read", "transaction:read"]
    assert "transfer:create" not in body["permissions"]


def test_permissions_are_scoped_to_the_session_application(client: TestClient) -> None:
    """Lucas administers Kaze Labs and its portal, but a *portal* session must
    not expose console permissions — otherwise a relying party could authorize
    console operations."""
    portal_session = _session(client, LUCAS | {"application_id": "kaze-portal"})
    assert portal_session["application_id"] == "kaze-portal"
    assert portal_session["permissions"] == [
        "portal:read",
        "projects:write",
        "settings:manage",
    ]
    assert not any(p.startswith("admin:") for p in portal_session["permissions"])

    console_session = _session(client, LUCAS)
    assert console_session["application_id"] == "kaze-labs-console"
    assert "admin:write" in console_session["permissions"]
    assert "settings:manage" not in console_session["permissions"]


def test_support_operator_holds_only_the_read_pair(client: TestClient) -> None:
    """HU-10's actor: can explain a login, cannot change anything."""
    body = _session(client, SUPPORT_LOGIN)
    assert sorted(body["permissions"]) == ["admin:read", "decisions:read"]


# ------------------------------------------------------------- console guards


def test_support_operator_can_read_but_not_write(client: TestClient) -> None:
    token = _token(client, SUPPORT_LOGIN)

    assert client.get("/admin/api/users", headers=_auth(token)).status_code == 200
    assert client.get("/admin/api/roles", headers=_auth(token)).status_code == 200

    created = client.post(
        "/admin/api/users",
        headers=_auth(token),
        json={"email": "nope@example.com", "password": "nope-password"},
    )
    assert created.status_code == 403
    assert created.json()["detail"] == "requires permission admin:write"


def test_support_operator_cannot_change_policy(client: TestClient) -> None:
    """Reading a decision and retuning the risk engine are different powers."""
    token = _token(client, SUPPORT_LOGIN)
    current = client.get("/admin/api/policy", headers=_auth(token))
    assert current.status_code == 200
    resp = client.put(
        "/admin/api/policy", headers=_auth(token), json=current.json()
    )
    assert resp.status_code == 403
    assert resp.json()["detail"] == "requires permission policy:write"


def test_bank_customer_cannot_open_the_console(client: TestClient) -> None:
    token = _token(client, CUSTOMER_LOGIN)
    resp = client.get("/admin/api/users", headers=_auth(token))
    assert resp.status_code == 403
    assert resp.json()["detail"] == "not a console session"


def test_an_admin_permission_on_an_app_does_not_open_the_console(
    client: TestClient,
) -> None:
    """A tenant admin can name a permission `admin:read` on their own app. It
    must not turn that app's sessions into console sessions."""
    token = _token(client, ADMIN_LOGIN)
    perm = client.post(
        "/admin/api/permissions",
        headers=_auth(token),
        json={"application_id": BANK, "resource": "admin", "operation": "read"},
    ).json()
    client.put(
        "/admin/api/roles/role_rb_customer/permissions",
        headers=_auth(token),
        json={"permission_ids": [perm["permission_id"]]},
    )
    customer = _token(client, CUSTOMER_LOGIN)
    assert "admin:read" in client.get("/session", headers=_auth(customer)).json()["permissions"]
    resp = client.get("/admin/api/users", headers=_auth(customer))
    assert resp.status_code == 403
    assert resp.json()["detail"] == "not a console session"


# ------------------------------------------------------------- role admin


def test_role_permissions_are_replaced_wholesale(client: TestClient) -> None:
    token = _token(client, ADMIN_LOGIN)
    perms = client.get(
        "/admin/api/permissions", headers=_auth(token), params={"application_id": BANK}
    ).json()
    by_scope = {row["scope"]: row["permission_id"] for row in perms}
    assert set(by_scope) == {"account:read", "transaction:read", "transfer:create"}

    updated = client.put(
        "/admin/api/roles/role_rb_viewer/permissions",
        headers=_auth(token),
        json={"permission_ids": [by_scope["account:read"]]},
    )
    assert updated.status_code == 200
    assert [p["scope"] for p in updated.json()["permissions"]] == ["account:read"]
    assert updated.json()["permission_count"] == 1

    # The change is visible to the next session immediately.
    assert _session(client, VIEWER_LOGIN)["permissions"] == ["account:read"]


def test_a_role_cannot_carry_another_applications_permission(
    client: TestClient,
) -> None:
    """Cross-application leakage is the failure that makes RBAC worthless."""
    token = _token(client, ADMIN_LOGIN)
    console_perms = client.get(
        "/admin/api/permissions",
        headers=_auth(token),
        params={"application_id": CONSOLE},
    ).json()
    admin_write = next(
        row["permission_id"] for row in console_perms if row["scope"] == "admin:write"
    )
    resp = client.put(
        "/admin/api/roles/role_rb_customer/permissions",
        headers=_auth(token),
        json={"permission_ids": [admin_write]},
    )
    assert resp.status_code == 422
    assert "different application" in resp.json()["detail"]
    # And the role is untouched.
    assert "transfer:create" in _session(client, CUSTOMER_LOGIN)["permissions"]


def test_unknown_permission_id_is_rejected(client: TestClient) -> None:
    token = _token(client, ADMIN_LOGIN)
    resp = client.put(
        "/admin/api/roles/role_rb_viewer/permissions",
        headers=_auth(token),
        json={"permission_ids": ["perm_does_not_exist"]},
    )
    assert resp.status_code == 404
    assert "perm_does_not_exist" in resp.json()["detail"]


def test_role_names_are_unique_per_application_not_globally(
    client: TestClient,
) -> None:
    """`viewer` on the bank and `viewer` on the console are different things."""
    token = _token(client, ADMIN_LOGIN)
    clash = client.post(
        "/admin/api/roles",
        headers=_auth(token),
        json={"application_id": BANK, "name": "viewer"},
    )
    assert clash.status_code == 409

    fine = client.post(
        "/admin/api/roles",
        headers=_auth(token),
        json={"application_id": CONSOLE, "name": "viewer"},
    )
    assert fine.status_code == 201


def test_deleting_a_role_revokes_access_that_depended_on_it(
    client: TestClient,
) -> None:
    token = _token(client, ADMIN_LOGIN)
    assert client.delete(
        "/admin/api/roles/role_rb_viewer", headers=_auth(token)
    ).status_code == 204

    denied = client.post("/login", json=VIEWER_LOGIN)
    assert denied.json()["outcome"] == "ACCESS_DENIED"


def test_is_admin_flag_and_the_admin_group_stay_in_step(
    client: TestClient,
) -> None:
    """`is_admin` is a label, but ticking it must really confer the power."""
    token = _token(client, ADMIN_LOGIN)
    created = client.post(
        "/admin/api/users",
        headers=_auth(token),
        json={
            "email": "newadmin@rokubank.example",
            "password": "newadmin-password",
            "is_admin": True,
        },
    ).json()
    assert created["is_admin"] is True

    new_token = _token(
        client,
        {**SIGNALS, "email": "newadmin@rokubank.example", "password": "newadmin-password"},
    )
    assert client.get("/admin/api/users", headers=_auth(new_token)).status_code == 200

    # Clearing it removes the role, so the console closes.
    client.patch(
        f"/admin/api/users/{created['user_id']}",
        headers=_auth(token),
        json={"is_admin": False},
    )
    assert client.get("/admin/api/users", headers=_auth(new_token)).status_code == 403


def test_permissions_are_read_fresh_on_every_request(client: TestClient) -> None:
    """A token issued before a revocation must not outlive it.

    Permissions are resolved inside the session lookup rather than baked into
    the token, so there is no window where a removed role still works.
    """
    token = _token(client, CUSTOMER_LOGIN)
    assert "transfer:create" in client.get(
        "/session", headers=_auth(token)
    ).json()["permissions"]

    admin_token = _token(client, ADMIN_LOGIN)
    perms = client.get(
        "/admin/api/permissions",
        headers=_auth(admin_token),
        params={"application_id": BANK},
    ).json()
    keep = [
        row["permission_id"] for row in perms if row["scope"] != "transfer:create"
    ]
    client.put(
        "/admin/api/roles/role_rb_customer/permissions",
        headers=_auth(admin_token),
        json={"permission_ids": keep},
    )

    # Same token, no re-login.
    assert "transfer:create" not in client.get(
        "/session", headers=_auth(token)
    ).json()["permissions"]
