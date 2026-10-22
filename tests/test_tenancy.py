"""Multi-tenancy (ADR-0033) and per-tenant enforcement (ADR-0034).

Three claims, each a way the product could leak or mislead:

1. A login is decided inside one tenant — the one its application belongs to,
   or for the console the one its email domain belongs to — and the operator
   console can be used to learn nothing about other tenants.
2. Every admin endpoint is scoped server-side: Diego (Roku Bank) touching a
   Kaze Labs object gets the same 404 as for an object that does not exist.
3. What the IdP applies is the PDP's ``enforced_action``; with the engine
   ``OFF`` the PDP is not called at all.
"""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

import pytest
from fastapi.testclient import TestClient
from rba_contracts import (
    Action,
    BasePolicy,
    DecisionRecord,
    EngineMode,
    LoginOutcome,
    RiskLevel,
)

from rba_idp.db.models import MfaChallenge
from tests.helpers import (
    BANK,
    DIEGO,
    JUAN,
    KAZE,
    LOGIN,
    LUCAS,
    MOCK_OTP,
    PLATFORM,
    SIGNALS,
    StubAudit,
    StubPdp,
    StubPolicy,
    bearer,
    client_for,
    console_token,
    stub_policy,
)

KAZE_PORTAL_LOGIN = {
    **LOGIN,
    "email": "martin@kazelabs.example",
    "password": "martin-demo",
    "application_id": "kaze-portal",
}


def _decision(tenant_id: str, event_id: str, user_id: str) -> DecisionRecord:
    return DecisionRecord(
        event_id=UUID(event_id),
        occurred_at=datetime(2026, 10, 21, 12, 0, tzinfo=timezone.utc),
        tenant_id=tenant_id,
        application_id="x",
        user_id=user_id,
        risk_score=0.4,
        risk_level=RiskLevel.MEDIUM,
        action=Action.REQUIRE_MFA,
        enforced_action=Action.REQUIRE_MFA,
        engine_mode=EngineMode.ACTIVE,
        model_version="freeman-0.1.0",
        policy_version="1.0.0",
        feature_schema_version="1.0.0",
    )


BANK_EVENT = "11111111-1111-4111-8111-111111111111"
KAZE_EVENT = "22222222-2222-4222-8222-222222222222"


@pytest.fixture
def audit() -> StubAudit:
    return StubAudit(
        [
            _decision(BANK, BANK_EVENT, "usr_rb_martin"),
            _decision(KAZE, KAZE_EVENT, "usr_kz_martin"),
        ]
    )


@pytest.fixture
def tenancy(pdp: StubPdp, audit: StubAudit):
    with client_for(pdp, audit_client=audit) as client:
        yield client


# ================================================================ app login


def test_app_login_is_scored_under_the_applications_tenant(
    tenancy: TestClient, pdp: StubPdp
) -> None:
    assert tenancy.post("/login", json=LOGIN).json()["outcome"] == "AUTHENTICATED"
    assert tenancy.post("/login", json=KAZE_PORTAL_LOGIN).json()["outcome"] == "AUTHENTICATED"
    assert [(c.tenant_id, c.application_id) for c in pdp.calls] == [
        (BANK, "roku-bank-web"),
        (KAZE, "kaze-portal"),
    ]


def test_another_tenants_user_is_unknown_to_this_tenants_app(
    tenancy: TestClient, pdp: StubPdp
) -> None:
    """Martín of Kaze Labs, correct password, at the bank: there is no such
    user in Roku Bank — not ACCESS_DENIED, which would confirm the account."""
    resp = tenancy.post(
        "/login",
        json={**KAZE_PORTAL_LOGIN, "application_id": "roku-bank-web"},
    )
    assert resp.json() == {"outcome": "INVALID_CREDENTIALS"}
    assert pdp.calls == []


def test_the_same_address_is_two_people_in_two_tenants(tenancy: TestClient) -> None:
    lucas = console_token(tenancy, LUCAS)
    created = tenancy.post(
        "/admin/api/users",
        headers=bearer(lucas),
        json={"email": "martin@correo.example", "password": "kaze-secret"},
    )
    assert created.status_code == 201
    assert created.json()["tenant_id"] == KAZE
    kaze_martin = created.json()["user_id"]
    assert kaze_martin != "usr_rb_martin"

    # The bank still knows only its own Martín and his own password.
    assert tenancy.post("/login", json=LOGIN).json()["user_id"] == "usr_rb_martin"
    assert (
        tenancy.post("/login", json={**LOGIN, "password": "kaze-secret"}).json()["outcome"]
        == "INVALID_CREDENTIALS"
    )


# ================================================================ enforcement


def test_the_idp_enforces_enforced_action_not_the_verdict(pdp: StubPdp) -> None:
    """MONITOR (ADR-0034): the engine would allow, the bank still asks for the
    passkey. The IdP must apply the second."""
    pdp.action = Action.ALLOW
    pdp.enforced = Action.REQUIRE_MFA
    pdp.engine_mode = EngineMode.MONITOR
    with client_for(pdp) as client:
        body = client.post("/login", json=LOGIN).json()
    assert body["outcome"] == LoginOutcome.MFA_REQUIRED.value
    assert body["action"] == Action.REQUIRE_MFA.value
    assert "session" not in body


def test_monitor_mode_does_not_enforce_a_block(pdp: StubPdp) -> None:
    pdp.action = Action.BLOCK
    pdp.enforced = Action.ALLOW
    pdp.engine_mode = EngineMode.MONITOR
    with client_for(pdp) as client:
        body = client.post("/login", json=LOGIN).json()
    assert body["outcome"] == LoginOutcome.AUTHENTICATED.value


@pytest.mark.parametrize(
    ("base", "outcome"),
    [
        (BasePolicy.PASSWORD_ONLY, LoginOutcome.AUTHENTICATED),
        (BasePolicy.ALWAYS_MFA, LoginOutcome.MFA_REQUIRED),
    ],
)
def test_engine_off_skips_the_pdp_and_applies_the_base_policy(
    pdp: StubPdp, base: BasePolicy, outcome: LoginOutcome
) -> None:
    policies = StubPolicy()
    policies.policies[BANK] = stub_policy(BANK, engine_mode=EngineMode.OFF, base_policy=base)
    with client_for(pdp, policy_client=policies) as client:
        body = client.post("/login", json=LOGIN).json()
        assert body["outcome"] == outcome.value
        # Nothing was scored, so there is nothing to show.
        assert "event_id" not in body and "risk_score" not in body
        if outcome is LoginOutcome.MFA_REQUIRED:
            done = client.post(
                "/mfa/verify", json={"challenge_id": body["challenge_id"], "code": MOCK_OTP}
            ).json()
            assert done["outcome"] == LoginOutcome.AUTHENTICATED.value
            with client.app.state.session_factory() as session:
                row = session.get(MfaChallenge, body["challenge_id"])
                assert row.event_id is None and row.risk_score is None
        # A wrong password is not reported either: the engine is off.
        client.post("/login", json={**LOGIN, "password": "wrong"})
    assert pdp.calls == []
    # Another tenant's mode is its own.
    with client_for(pdp, policy_client=policies) as client:
        client.post("/login", json=KAZE_PORTAL_LOGIN)
    assert [c.tenant_id for c in pdp.calls] == [KAZE]


def test_tenant_policy_is_cached_between_logins(pdp: StubPdp) -> None:
    policies = StubPolicy()
    with client_for(pdp, policy_client=policies) as client:
        for _ in range(3):
            client.post("/login", json=LOGIN)
    assert policies.reads.count(BANK) == 1


def test_saving_a_policy_drops_this_idps_cached_copy(pdp: StubPdp) -> None:
    policies = StubPolicy()
    with client_for(pdp, policy_client=policies) as client:
        client.post("/login", json=LOGIN)
        diego = console_token(client, DIEGO)
        body = client.get("/admin/api/policy", headers=bearer(diego)).json()
        body["engine_mode"] = "OFF"
        assert client.put("/admin/api/policy", headers=bearer(diego), json=body).status_code == 200
        before = len(pdp.calls)
        assert client.post("/login", json=LOGIN).json()["outcome"] == "AUTHENTICATED"
        assert len(pdp.calls) == before  # OFF took effect at once


def test_unreachable_policy_falls_through_to_the_pdp_path() -> None:
    """No policy read → the IdP cannot know the tenant is OFF, so it calls the
    PDP, and the PDP-unavailable path decides as before."""
    from tests.helpers import FailingPdp

    policies = StubPolicy({})
    with client_for(FailingPdp(), policy_client=policies) as client:
        body = client.post("/login", json=LOGIN).json()
    assert body["outcome"] == LoginOutcome.MFA_REQUIRED.value
    assert body["reasons"][0]["code"] == "pdp_unavailable"


# ================================================================ console login


def test_console_login_finds_the_tenant_from_the_email_domain(
    tenancy: TestClient, pdp: StubPdp
) -> None:
    for who, tenant in ((DIEGO, BANK), (LUCAS, KAZE), (JUAN, PLATFORM)):
        token = console_token(tenancy, who)
        session = tenancy.get("/session", headers=bearer(token)).json()
        assert session["user"]["tenant_id"] == tenant
        assert session["application_id"] == f"{tenant}-console"
    # Operators are scored like anyone else, under their own tenant's policy.
    assert [(c.tenant_id, c.application_id) for c in pdp.calls] == [
        (BANK, "roku-bank-console"),
        (KAZE, "kaze-labs-console"),
        (PLATFORM, "rokusec-console"),
    ]


def test_console_domain_is_case_insensitive(tenancy: TestClient) -> None:
    body = tenancy.post(
        "/console/login", json={**DIEGO, "email": "Diego@RokuBank.EXAMPLE"}
    ).json()
    assert body["outcome"] == "AUTHENTICATED"


@pytest.mark.parametrize(
    ("email", "password"),
    [
        ("lucas@nadie.example", "lucas-demo"),  # domain nobody registered
        ("nobody@kazelabs.example", "x"),  # Diego probing Kaze Labs
        ("diego@rokubank.example", "wrong"),  # wrong password
        ("martin@kazelabs.example", "martin-demo"),  # right password, no console role
        ("martin@correo.example", "martin-demo"),  # a customer, not an operator
        ("not-an-email", "x"),
    ],
)
def test_every_console_login_failure_looks_the_same(
    tenancy: TestClient, pdp: StubPdp, email: str, password: str
) -> None:
    resp = tenancy.post(
        "/console/login", json={**SIGNALS, "email": email, "password": password}
    )
    assert resp.status_code == 200
    assert resp.json() == {"outcome": "INVALID_CREDENTIALS"}
    # Nothing that failed before the password check reaches the PDP.
    assert all(c.login_successful is False for c in pdp.calls)


def test_console_login_names_no_application(tenancy: TestClient) -> None:
    resp = tenancy.post(
        "/console/login", json={**DIEGO, "application_id": "kaze-labs-console"}
    )
    assert resp.status_code == 422


def test_console_login_cannot_go_through_the_app_login(tenancy: TestClient) -> None:
    """`POST /login` with the console's client id works (it is an application
    like any other) but only finds users of that console's tenant."""
    resp = tenancy.post(
        "/login",
        json={**LOGIN, **{k: DIEGO[k] for k in ("email", "password")},
              "application_id": "kaze-labs-console"},
    )
    assert resp.json() == {"outcome": "INVALID_CREDENTIALS"}


# ================================================================ admin scoping
#
# Diego administers Roku Bank. Every one of these names a Kaze Labs object and
# must answer exactly as if it did not exist.

CROSS_TENANT = [
    ("GET", "/admin/api/groups/grp_kz_team", None),
    ("PATCH", "/admin/api/groups/grp_kz_team", {"description": "mine now"}),
    ("DELETE", "/admin/api/groups/grp_kz_team", None),
    ("POST", "/admin/api/groups/grp_kz_team/members", {"user_id": "usr_rb_martin"}),
    ("DELETE", "/admin/api/groups/grp_kz_team/members/usr_kz_martin", None),
    ("POST", "/admin/api/groups/grp_kz_team/roles", {"role_id": "role_rb_customer"}),
    ("DELETE", "/admin/api/groups/grp_kz_team/roles/role_kz_member", None),
    # Pulling Kaze's people or roles into a bank group.
    ("POST", "/admin/api/groups/grp_rb_customers/members", {"user_id": "usr_kz_martin"}),
    ("POST", "/admin/api/groups/grp_rb_customers/roles", {"role_id": "role_kz_admin"}),
    ("PATCH", "/admin/api/users/usr_kz_martin", {"enabled": False}),
    ("GET", "/admin/api/roles/role_kz_admin", None),
    ("PATCH", "/admin/api/roles/role_kz_admin", {"description": "x"}),
    ("DELETE", "/admin/api/roles/role_kz_admin", None),
    ("PUT", "/admin/api/roles/role_kz_admin/permissions", {"permission_ids": []}),
    (
        "PUT",
        "/admin/api/roles/role_rb_customer/permissions",
        {"permission_ids": ["perm_kaze_portal_settings_manage"]},
    ),
    ("POST", "/admin/api/roles", {"application_id": "kaze-portal", "name": "spy"}),
    (
        "POST",
        "/admin/api/permissions",
        {"application_id": "kaze-portal", "resource": "spy", "operation": "read"},
    ),
    ("PATCH", "/admin/api/applications/kaze-portal", {"enabled": False}),
    ("GET", f"/admin/api/decisions/{KAZE_EVENT}", None),
]


@pytest.mark.parametrize(("method", "path", "body"), CROSS_TENANT)
def test_another_tenants_object_is_indistinguishable_from_a_missing_one(
    tenancy: TestClient, method: str, path: str, body: dict | None
) -> None:
    diego = console_token(tenancy, DIEGO)
    resp = tenancy.request(method, path, headers=bearer(diego), json=body)
    assert resp.status_code == 404, resp.text
    # The same "unknown <thing>" a missing object gets.
    assert resp.json()["detail"].startswith("unknown ")
    # And Kaze Labs is untouched.
    lucas = console_token(tenancy, LUCAS)
    team = tenancy.get("/admin/api/groups/grp_kz_team", headers=bearer(lucas)).json()
    assert {m["user_id"] for m in team["members"]} == {"usr_kz_martin"}
    assert team["description"] == "Empleados de Kaze Labs"
    assert [r["role_id"] for r in team["roles"]] == ["role_kz_member"]


@pytest.mark.parametrize(
    "path",
    [
        "/admin/api/users",
        "/admin/api/applications",
        "/admin/api/groups",
        "/admin/api/roles",
        "/admin/api/permissions",
    ],
)
def test_lists_show_only_the_operators_tenant(tenancy: TestClient, path: str) -> None:
    # The other tenant's ids all carry its marker (`kaze`, `rb_`/`roku_bank`).
    for who, tenant, foreign in (
        (DIEGO, BANK, ("kaze",)),
        (LUCAS, KAZE, ("rb_", "roku", "rokubank")),
    ):
        rows = tenancy.get(path, headers=bearer(console_token(tenancy, who))).json()
        assert rows, path
        if "tenant_id" in rows[0]:
            assert {row["tenant_id"] for row in rows} == {tenant}
        flat = repr(rows).lower()
        assert not any(marker in flat for marker in foreign), (path, who["email"])


def test_decisions_are_read_for_the_operators_tenant_only(
    tenancy: TestClient, audit: StubAudit
) -> None:
    diego = console_token(tenancy, DIEGO)
    listed = tenancy.get("/admin/api/decisions", headers=bearer(diego)).json()
    assert [item["event_id"] for item in listed["items"]] == [BANK_EVENT]
    assert tenancy.get(
        f"/admin/api/decisions/{BANK_EVENT}", headers=bearer(diego)
    ).status_code == 200
    assert audit.tenants_asked == [BANK]


def test_policy_is_the_operators_tenants(tenancy: TestClient) -> None:
    diego = console_token(tenancy, DIEGO)
    mine = tenancy.get("/admin/api/policy", headers=bearer(diego)).json()
    assert mine["tenant_id"] == BANK
    # Writing Kaze's policy by putting its id in the body is refused.
    resp = tenancy.put(
        "/admin/api/policy", headers=bearer(diego), json={**mine, "tenant_id": KAZE}
    )
    assert resp.status_code == 422
    lucas = console_token(tenancy, LUCAS)
    assert tenancy.get("/admin/api/policy", headers=bearer(lucas)).json()["tenant_id"] == KAZE


def test_new_objects_land_in_the_operators_tenant(tenancy: TestClient) -> None:
    diego = console_token(tenancy, DIEGO)
    group = tenancy.post(
        "/admin/api/groups", headers=bearer(diego), json={"name": "Equipo"}
    )
    # "Equipo" exists in Kaze Labs; names are unique per tenant only.
    assert group.status_code == 201
    assert group.json()["tenant_id"] == BANK


@pytest.mark.parametrize("named", [KAZE, "no-such-tenant", PLATFORM])
def test_a_tenant_operator_cannot_switch_tenants(tenancy: TestClient, named: str) -> None:
    """Same 403 for a real tenant and an invented one: the header is no oracle."""
    diego = console_token(tenancy, DIEGO)
    resp = tenancy.get("/admin/api/users", headers=bearer(diego, named))
    assert resp.status_code == 403
    assert resp.json()["detail"] == "requires permission tenants:read"
    # Naming one's own tenant is harmless.
    assert tenancy.get("/admin/api/users", headers=bearer(diego, BANK)).status_code == 200


def test_a_tenant_operator_cannot_reach_the_tenant_registry(tenancy: TestClient) -> None:
    diego = console_token(tenancy, DIEGO)
    assert tenancy.get("/admin/api/tenants", headers=bearer(diego)).status_code == 403
    assert tenancy.post(
        "/admin/api/tenants", headers=bearer(diego), json={"tenant_id": "x", "name": "X"}
    ).status_code == 403
    assert tenancy.patch(
        f"/admin/api/tenants/{KAZE}", headers=bearer(diego), json={"name": "Mine"}
    ).status_code == 403
    current = tenancy.get("/admin/api/tenant", headers=bearer(diego)).json()
    assert current["tenant_id"] == BANK
    assert current["operator_domains"] == ["rokubank.example"]


def test_granting_oneself_tenants_read_on_a_tenant_console_grants_nothing(
    tenancy: TestClient,
) -> None:
    """The permission is only honoured on the platform tenant's console."""
    diego = console_token(tenancy, DIEGO)
    perm = tenancy.post(
        "/admin/api/permissions",
        headers=bearer(diego),
        json={"application_id": "roku-bank-console", "resource": "tenants", "operation": "read"},
    ).json()
    role = tenancy.get("/admin/api/roles/role_roku_bank_tenant_admin", headers=bearer(diego)).json()
    ids = [p["permission_id"] for p in role["permissions"]] + [perm["permission_id"]]
    tenancy.put(
        "/admin/api/roles/role_roku_bank_tenant_admin/permissions",
        headers=bearer(diego),
        json={"permission_ids": ids},
    )
    assert "tenants:read" in tenancy.get("/session", headers=bearer(diego)).json()["permissions"]
    assert tenancy.get("/admin/api/users", headers=bearer(diego, KAZE)).status_code == 403
    assert tenancy.get("/admin/api/tenants", headers=bearer(diego)).status_code == 403


# ================================================================ platform operator


def test_platform_operator_lists_and_switches_tenants(tenancy: TestClient) -> None:
    juan = console_token(tenancy, JUAN)
    tenants = tenancy.get("/admin/api/tenants", headers=bearer(juan)).json()
    assert {t["tenant_id"]: t["is_platform"] for t in tenants} == {
        BANK: False,
        KAZE: False,
        PLATFORM: True,
    }
    # Default: his own tenant.
    own = tenancy.get("/admin/api/users", headers=bearer(juan)).json()
    assert {u["tenant_id"] for u in own} == {PLATFORM}

    kaze = tenancy.get("/admin/api/users", headers=bearer(juan, KAZE)).json()
    assert {u["email"] for u in kaze} == {
        "lucas@kazelabs.example",
        "martin@kazelabs.example",
        "valen@kazelabs.example",
    }
    assert tenancy.get("/admin/api/tenant", headers=bearer(juan, KAZE)).json()["name"] == "Kaze Labs"

    # Writes while switched land in the tenant switched to.
    created = tenancy.post(
        "/admin/api/users",
        headers=bearer(juan, KAZE),
        json={"email": "nueva@kazelabs.example", "password": "x"},
    ).json()
    assert created["tenant_id"] == KAZE

    assert tenancy.get(
        "/admin/api/users", headers=bearer(juan, "no-such-tenant")
    ).status_code == 404


def test_platform_operator_creates_a_tenant_ready_to_use(pdp: StubPdp) -> None:
    policies = StubPolicy()
    with client_for(pdp, policy_client=policies) as client:
        juan = console_token(client, JUAN)
        resp = client.post(
            "/admin/api/tenants",
            headers=bearer(juan),
            json={"tenant_id": "tora-seguros", "name": "Tora Seguros",
                  "operator_domains": ["toraseguros.example"]},
        )
        assert resp.status_code == 201, resp.text
        assert resp.json()["operator_domains"] == ["toraseguros.example"]
        # A starter policy exists before the first login can need it.
        assert policies.policies["tora-seguros"].engine_mode is EngineMode.MONITOR

        apps = client.get("/admin/api/applications", headers=bearer(juan, "tora-seguros")).json()
        assert [a["application_id"] for a in apps] == ["tora-seguros-console"]

        # An admin ticked in through the switcher can sign in to the new console.
        client.post(
            "/admin/api/users",
            headers=bearer(juan, "tora-seguros"),
            json={"email": "ines@toraseguros.example", "password": "ines-pw", "is_admin": True},
        )
        token = console_token(
            client, {**SIGNALS, "email": "ines@toraseguros.example", "password": "ines-pw"}
        )
        assert client.get("/admin/api/tenant", headers=bearer(token)).json()["tenant_id"] == "tora-seguros"


def test_an_operator_domain_belongs_to_one_tenant(tenancy: TestClient) -> None:
    juan = console_token(tenancy, JUAN)
    clash = tenancy.post(
        "/admin/api/tenants",
        headers=bearer(juan),
        json={"tenant_id": "copycat", "name": "Copycat", "operator_domains": ["rokubank.example"]},
    )
    assert clash.status_code == 409
    moved = tenancy.patch(
        f"/admin/api/tenants/{KAZE}",
        headers=bearer(juan),
        json={"operator_domains": ["kazelabs.example", "rokubank.example"]},
    )
    assert moved.status_code == 409
    renamed = tenancy.patch(
        f"/admin/api/tenants/{KAZE}",
        headers=bearer(juan),
        json={"operator_domains": ["kaze.example"]},
    )
    assert renamed.json()["operator_domains"] == ["kaze.example"]
    # Lucas now has to sign in with the new domain; the old one routes nowhere.
    assert tenancy.post("/console/login", json=LUCAS).json() == {"outcome": "INVALID_CREDENTIALS"}
