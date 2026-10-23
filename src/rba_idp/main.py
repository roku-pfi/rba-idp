"""FastAPI application factory: hosted login, console login, tenant-scoped admin API."""

from __future__ import annotations

import hmac
import json
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated
from uuid import UUID

from fastapi import FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import FileResponse, HTMLResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from rba_contracts import (
    Action,
    ActivationCodeResponse,
    ActivationOptionsRequest,
    ActivationVerifyRequest,
    AddGroupMemberRequest,
    AddGroupRoleRequest,
    AdminUserPublic,
    ApplicationPublic,
    CallbackTokenRequest,
    CallbackTokenResponse,
    ConsoleLoginRequest,
    CreateApplicationRequest,
    CreateGroupRequest,
    CreatePermissionRequest,
    CreateRoleRequest,
    CreateTenantRequest,
    CreateUserRequest,
    DecisionListResponse,
    DecisionRecord,
    GroupDetail,
    GroupPublic,
    LoginRequest,
    LoginResponse,
    MfaVerifyRequest,
    MfaWebAuthnOptionsRequest,
    MfaWebAuthnOptionsResponse,
    MfaWebAuthnVerifyRequest,
    PasskeyOptionsResponse,
    PasskeyVerifyRequest,
    PatchApplicationRequest,
    PatchGroupRequest,
    PatchRoleRequest,
    PatchTenantRequest,
    PatchUserRequest,
    PermissionPublic,
    RoleDetail,
    RolePublic,
    SessionResponse,
    SetRolePermissionsRequest,
    SimulationTicketRequest,
    SimulationTicketResponse,
    TenantPolicy,
    TenantPublic,
)

from rba_idp import metrics
from rba_idp.clients import AuditClient, HttpAuditClient, HttpPolicyClient, PolicyClient
from rba_idp.config import Settings, get_settings
from rba_idp.db.models import Application
from rba_idp.db.session import make_engine, make_session_factory, session_scope
from rba_idp.geo import configure_geoip
from rba_idp.simulation import issue_ticket, verify_ticket
from rba_idp.pdp import HttpPdpClient, PdpClient
from rba_idp.init import initialise
from rba_idp.services.admin import (
    ActiveAlert,
    ADMIN_READ,
    ADMIN_WRITE,
    DECISIONS_READ,
    POLICY_WRITE,
    TENANT_HEADER,
    TENANTS_READ,
    TENANTS_WRITE,
    AdminService,
    Operator,
)
from rba_idp.services.enrollment import EnrollmentService
from rba_idp.services.login import LoginService
from rba_idp.tenancy import TenantPolicyCache
from rba_idp.web import WEB_DIR, RevalidatingStaticFiles, static_version
from rba_idp.web.context import client_ip, hosted_boot

logger = logging.getLogger(__name__)

# Module level: route signatures are resolved here (`from __future__` makes
# every annotation a string).
Auth = Annotated[str | None, Header(alias="Authorization")]
# A platform operator acting on another tenant names it here (ADR-0033).
ActingTenant = Annotated[str | None, Header(alias=TENANT_HEADER)]

ADMIN_DIR = WEB_DIR / "admin"
# Served only when admin-ui has not been built (`npm run build` writes ADMIN_DIR).
ADMIN_MISSING_HTML = """<!doctype html>
<html lang="es"><head><meta charset="utf-8"><title>Consola · RokuSec</title></head>
<body><p>La consola no está compilada: <code>cd admin-ui &amp;&amp; npm run build</code>.</p></body>
</html>
"""


def create_app(
    settings: Settings | None = None,
    *,
    pdp_client: PdpClient | None = None,
    policy_client: PolicyClient | None = None,
    audit_client: AuditClient | None = None,
) -> FastAPI:
    settings = settings or get_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        logging.basicConfig(level=logging.INFO)
        metrics.serve(settings.metrics_port)
        geo = configure_geoip(settings.geoip_country_db, settings.geoip_asn_db)
        logger.info("GeoIP: %s", "DB-IP Lite loaded" if geo.loaded else "TEST-NET table only")
        engine = make_engine(settings.database_url, memory=settings.use_memory_db)
        if settings.init_on_startup:
            initialise(settings, engine)
        session_factory = make_session_factory(engine)
        pdp = pdp_client or HttpPdpClient(
            settings.pdp_base_url,
            timeout=settings.pdp_timeout_seconds,
        )
        policy = policy_client or HttpPolicyClient(
            settings.pdp_base_url,
            timeout=settings.pdp_timeout_seconds,
        )
        audit = audit_client or HttpAuditClient(
            settings.audit_base_url,
            timeout=settings.audit_timeout_seconds,
        )
        policy_cache = TenantPolicyCache(policy, ttl=settings.policy_cache_seconds)
        login_service = LoginService(session_factory, pdp, settings, policy_cache)
        app.state.settings = settings
        app.state.pdp_client = pdp
        app.state.policy_client = policy
        app.state.audit_client = audit
        app.state.session_factory = session_factory
        app.state.login_service = login_service
        app.state.admin_service = AdminService(
            session_factory, login_service, policy, audit, policy_cache, settings
        )
        app.state.enrollment_service = EnrollmentService(session_factory, settings)
        logger.info(
            "rba-idp ready (multi-tenant). bank redirect=%s kaze redirect=%s pdp=%s audit=%s",
            settings.seed_bank_redirect_uri,
            settings.seed_kaze_redirect_uri,
            settings.pdp_base_url,
            settings.audit_base_url,
        )
        yield
        for client in (pdp, policy, audit):
            close = getattr(client, "close", None)
            if callable(close):
                close()

    app = FastAPI(
        title=settings.app_name,
        version="0.5.0",
        lifespan=lifespan,
    )
    templates = Jinja2Templates(directory=str(WEB_DIR / "templates"))
    templates.env.globals["v"] = static_version()
    app.mount(
        "/static", RevalidatingStaticFiles(directory=str(WEB_DIR / "static")), name="static"
    )
    assets = ADMIN_DIR / "assets"
    if assets.is_dir():
        app.mount("/admin/assets", StaticFiles(directory=str(assets)), name="admin-assets")

    def hosted_login(
        request: Request, client_id: str | None = None, *, console: bool = False
    ):
        boot = hosted_boot(request, client_id, console=console)
        return templates.TemplateResponse(
            request=request,
            name="login.html",
            context={"boot": boot},
        )

    @app.get("/", include_in_schema=False)
    def home(request: Request, client_id: str | None = None):
        # Without an application there is no tenant to sign in to; the only
        # login that needs none is the operators' console.
        return hosted_login(request, client_id, console=client_id is None)

    @app.get("/login", include_in_schema=False)
    def login_page(request: Request, client_id: str | None = None):
        # Applications link here with their public client_id, never their
        # internal application_id (rba_idp.client_ids).
        return hosted_login(request, client_id)

    @app.get("/console/login", include_in_schema=False)
    def console_login_page(request: Request):
        return hosted_login(request, console=True)

    @app.get("/activate", include_in_schema=False)
    def activate_page(request: Request):
        return templates.TemplateResponse(request=request, name="activate.html", context={})

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.post(
        "/login",
        response_model=LoginResponse,
        response_model_exclude_none=True,
        response_model_exclude_defaults=True,
    )
    def login(body: LoginRequest, request: Request) -> LoginResponse:
        body = _observed(_resolve_client(body, request), request)
        result = _run(request, lambda svc: svc.login(body))
        metrics.observe_login("app", result.outcome)
        return result

    @app.post(
        "/console/login",
        response_model=LoginResponse,
        response_model_exclude_none=True,
        response_model_exclude_defaults=True,
    )
    def console_login(body: ConsoleLoginRequest, request: Request) -> LoginResponse:
        body = _observed(body, request)
        result = _run(request, lambda svc: svc.console_login(body))
        metrics.observe_login("console", result.outcome)
        return result

    @app.post(
        "/mfa/verify",
        response_model=LoginResponse,
        response_model_exclude_none=True,
        response_model_exclude_defaults=True,
    )
    def verify_mfa(body: MfaVerifyRequest, request: Request) -> LoginResponse:
        result = _run(request, lambda svc: svc.verify_mfa(body))
        metrics.observe_step_up("otp", result.outcome)
        return result

    @app.post(
        "/mfa/webauthn/options",
        response_model=MfaWebAuthnOptionsResponse,
        response_model_exclude_none=True,
    )
    def mfa_webauthn_options(
        body: MfaWebAuthnOptionsRequest, request: Request
    ) -> MfaWebAuthnOptionsResponse:
        return _run(request, lambda svc: svc.webauthn_options(body))

    @app.post(
        "/mfa/webauthn/verify",
        response_model=LoginResponse,
        response_model_exclude_none=True,
        response_model_exclude_defaults=True,
    )
    def mfa_webauthn_verify(
        body: MfaWebAuthnVerifyRequest, request: Request
    ) -> LoginResponse:
        result = _run(request, lambda svc: svc.verify_webauthn(body))
        metrics.observe_step_up("passkey", result.outcome)
        return result

    # ---------------------------------------------------------------- enrollment (ADR-0037)

    def _enroll(request: Request) -> EnrollmentService:
        return request.app.state.enrollment_service

    @app.post("/passkeys/options", response_model=PasskeyOptionsResponse)
    def passkey_options(request: Request, authorization: Auth = None) -> PasskeyOptionsResponse:
        return _enroll(request).session_options(authorization)

    @app.post("/passkeys/verify", status_code=204)
    def passkey_verify(
        body: PasskeyVerifyRequest, request: Request, authorization: Auth = None
    ) -> Response:
        _enroll(request).session_verify(authorization, body)
        return Response(status_code=204)

    @app.post("/activate/options", response_model=PasskeyOptionsResponse)
    def activate_options(body: ActivationOptionsRequest, request: Request) -> PasskeyOptionsResponse:
        return _enroll(request).activation_options(body)

    @app.post("/activate/verify", status_code=204)
    def activate_verify(body: ActivationVerifyRequest, request: Request) -> Response:
        _enroll(request).activation_verify(body)
        return Response(status_code=204)

    @app.post("/simulation/ticket", response_model=SimulationTicketResponse)
    def simulation_ticket(
        body: SimulationTicketRequest,
        secret: Annotated[str | None, Header(alias="X-RokuSec-Simulation-Secret")] = None,
    ) -> SimulationTicketResponse:
        """Presenter only (ADR-0032). Same 404 whether disabled or the secret is wrong."""
        configured = settings.simulation_secret
        if not configured or not secret or not hmac.compare_digest(secret, configured):
            raise HTTPException(status_code=404, detail="not found")
        ticket, expires = issue_ticket(
            configured,
            country=body.country.upper() if body.country else None,
            asn=body.asn,
            ttl_seconds=settings.simulation_ttl_seconds,
        )
        return SimulationTicketResponse(
            ticket=ticket, expires_at=datetime.fromtimestamp(expires, tz=timezone.utc)
        )

    @app.get("/session", response_model=SessionResponse)
    def get_session(
        request: Request,
        authorization: Annotated[str | None, Header()] = None,
    ) -> SessionResponse:
        return _run(request, lambda svc: svc.get_session(authorization))

    @app.post("/logout", status_code=204)
    def logout(
        request: Request,
        authorization: Annotated[str | None, Header()] = None,
    ) -> Response:
        _run(request, lambda svc: svc.logout(authorization))
        return Response(status_code=204)

    @app.post(
        "/callback/token",
        response_model=CallbackTokenResponse,
        response_model_exclude_none=True,
    )
    def exchange_callback(
        body: CallbackTokenRequest, request: Request
    ) -> CallbackTokenResponse:
        return _run(request, lambda svc: svc.exchange_code(body))

    def _admin(request: Request) -> AdminService:
        return request.app.state.admin_service

    def _op(
        request: Request,
        authorization: str | None,
        tenant: str | None,
        needs: tuple[str, str] = ADMIN_READ,
    ) -> tuple[AdminService, Operator]:
        """Every admin route starts here: who, on which tenant, allowed to what."""
        service = _admin(request)
        return service, service.authorize(authorization, tenant, needs)

    # ---------------------------------------------------------------- tenants

    @app.get("/admin/api/tenant", response_model=TenantPublic)
    def admin_current_tenant(
        request: Request, authorization: Auth = None, tenant: ActingTenant = None
    ) -> TenantPublic:
        service, op = _op(request, authorization, tenant)
        return service.current_tenant(op)

    @app.get("/admin/api/tenants", response_model=list[TenantPublic])
    def admin_list_tenants(request: Request, authorization: Auth = None) -> list[TenantPublic]:
        service = _admin(request)
        service.authorize_platform(authorization, TENANTS_READ)
        return service.list_tenants()

    @app.post("/admin/api/tenants", response_model=TenantPublic, status_code=201)
    def admin_create_tenant(
        body: CreateTenantRequest, request: Request, authorization: Auth = None
    ) -> TenantPublic:
        service = _admin(request)
        service.authorize_platform(authorization, TENANTS_WRITE)
        return service.create_tenant(body)

    @app.patch("/admin/api/tenants/{tenant_id}", response_model=TenantPublic)
    def admin_patch_tenant(
        tenant_id: str, body: PatchTenantRequest, request: Request, authorization: Auth = None
    ) -> TenantPublic:
        service = _admin(request)
        service.authorize_platform(authorization, TENANTS_WRITE)
        return service.patch_tenant(tenant_id, body)

    # ---------------------------------------------------------------- users

    @app.get("/admin/api/users", response_model=list[AdminUserPublic])
    def admin_list_users(
        request: Request, authorization: Auth = None, tenant: ActingTenant = None
    ) -> list[AdminUserPublic]:
        service, op = _op(request, authorization, tenant)
        return service.list_users(op)

    @app.post("/admin/api/users", response_model=AdminUserPublic, status_code=201)
    def admin_create_user(
        body: CreateUserRequest,
        request: Request,
        authorization: Auth = None,
        tenant: ActingTenant = None,
    ) -> AdminUserPublic:
        service, op = _op(request, authorization, tenant, ADMIN_WRITE)
        return service.create_user(op, body)

    @app.patch("/admin/api/users/{user_id}", response_model=AdminUserPublic)
    def admin_patch_user(
        user_id: str,
        body: PatchUserRequest,
        request: Request,
        authorization: Auth = None,
        tenant: ActingTenant = None,
    ) -> AdminUserPublic:
        service, op = _op(request, authorization, tenant, ADMIN_WRITE)
        return service.patch_user(op, user_id, body)

    @app.post(
        "/admin/api/users/{user_id}/activation-code",
        response_model=ActivationCodeResponse,
        status_code=201,
    )
    def admin_issue_activation_code(
        user_id: str, request: Request, authorization: Auth = None, tenant: ActingTenant = None
    ) -> ActivationCodeResponse:
        service, op = _op(request, authorization, tenant, ADMIN_WRITE)
        return service.issue_activation_code(op, user_id)

    # ---------------------------------------------------------------- applications

    @app.get("/admin/api/applications", response_model=list[ApplicationPublic])
    def admin_list_apps(
        request: Request, authorization: Auth = None, tenant: ActingTenant = None
    ) -> list[ApplicationPublic]:
        service, op = _op(request, authorization, tenant)
        return service.list_applications(op)

    @app.post("/admin/api/applications", response_model=ApplicationPublic, status_code=201)
    def admin_create_app(
        body: CreateApplicationRequest,
        request: Request,
        authorization: Auth = None,
        tenant: ActingTenant = None,
    ) -> ApplicationPublic:
        service, op = _op(request, authorization, tenant, ADMIN_WRITE)
        return service.create_application(op, body)

    @app.patch("/admin/api/applications/{application_id}", response_model=ApplicationPublic)
    def admin_patch_app(
        application_id: str,
        body: PatchApplicationRequest,
        request: Request,
        authorization: Auth = None,
        tenant: ActingTenant = None,
    ) -> ApplicationPublic:
        service, op = _op(request, authorization, tenant, ADMIN_WRITE)
        return service.patch_application(op, application_id, body)

    # ---------------------------------------------------------------- groups

    @app.get("/admin/api/groups", response_model=list[GroupPublic])
    def admin_list_groups(
        request: Request, authorization: Auth = None, tenant: ActingTenant = None
    ) -> list[GroupPublic]:
        service, op = _op(request, authorization, tenant)
        return service.list_groups(op)

    @app.post("/admin/api/groups", response_model=GroupDetail, status_code=201)
    def admin_create_group(
        body: CreateGroupRequest,
        request: Request,
        authorization: Auth = None,
        tenant: ActingTenant = None,
    ) -> GroupDetail:
        service, op = _op(request, authorization, tenant, ADMIN_WRITE)
        return service.create_group(op, body)

    @app.get("/admin/api/groups/{group_id}", response_model=GroupDetail)
    def admin_get_group(
        group_id: str, request: Request, authorization: Auth = None, tenant: ActingTenant = None
    ) -> GroupDetail:
        service, op = _op(request, authorization, tenant)
        return service.get_group(op, group_id)

    @app.patch("/admin/api/groups/{group_id}", response_model=GroupDetail)
    def admin_patch_group(
        group_id: str,
        body: PatchGroupRequest,
        request: Request,
        authorization: Auth = None,
        tenant: ActingTenant = None,
    ) -> GroupDetail:
        service, op = _op(request, authorization, tenant, ADMIN_WRITE)
        return service.patch_group(op, group_id, body)

    @app.delete("/admin/api/groups/{group_id}", status_code=204)
    def admin_delete_group(
        group_id: str, request: Request, authorization: Auth = None, tenant: ActingTenant = None
    ) -> Response:
        service, op = _op(request, authorization, tenant, ADMIN_WRITE)
        service.delete_group(op, group_id)
        return Response(status_code=204)

    @app.post("/admin/api/groups/{group_id}/members", response_model=GroupDetail)
    def admin_add_member(
        group_id: str,
        body: AddGroupMemberRequest,
        request: Request,
        authorization: Auth = None,
        tenant: ActingTenant = None,
    ) -> GroupDetail:
        service, op = _op(request, authorization, tenant, ADMIN_WRITE)
        return service.add_member(op, group_id, body)

    @app.delete("/admin/api/groups/{group_id}/members/{user_id}", response_model=GroupDetail)
    def admin_remove_member(
        group_id: str,
        user_id: str,
        request: Request,
        authorization: Auth = None,
        tenant: ActingTenant = None,
    ) -> GroupDetail:
        service, op = _op(request, authorization, tenant, ADMIN_WRITE)
        return service.remove_member(op, group_id, user_id)

    @app.post("/admin/api/groups/{group_id}/roles", response_model=GroupDetail)
    def admin_add_group_role(
        group_id: str,
        body: AddGroupRoleRequest,
        request: Request,
        authorization: Auth = None,
        tenant: ActingTenant = None,
    ) -> GroupDetail:
        service, op = _op(request, authorization, tenant, ADMIN_WRITE)
        return service.add_group_role(op, group_id, body)

    @app.delete("/admin/api/groups/{group_id}/roles/{role_id}", response_model=GroupDetail)
    def admin_remove_group_role(
        group_id: str,
        role_id: str,
        request: Request,
        authorization: Auth = None,
        tenant: ActingTenant = None,
    ) -> GroupDetail:
        service, op = _op(request, authorization, tenant, ADMIN_WRITE)
        return service.remove_group_role(op, group_id, role_id)

    # ---------------------------------------------------------------- roles and permissions

    @app.get("/admin/api/roles", response_model=list[RolePublic])
    def admin_list_roles(
        request: Request,
        authorization: Auth = None,
        tenant: ActingTenant = None,
        application_id: str | None = None,
    ) -> list[RolePublic]:
        service, op = _op(request, authorization, tenant)
        return service.list_roles(op, application_id)

    @app.post("/admin/api/roles", response_model=RoleDetail, status_code=201)
    def admin_create_role(
        body: CreateRoleRequest,
        request: Request,
        authorization: Auth = None,
        tenant: ActingTenant = None,
    ) -> RoleDetail:
        service, op = _op(request, authorization, tenant, ADMIN_WRITE)
        return service.create_role(op, body)

    @app.get("/admin/api/roles/{role_id}", response_model=RoleDetail)
    def admin_get_role(
        role_id: str, request: Request, authorization: Auth = None, tenant: ActingTenant = None
    ) -> RoleDetail:
        service, op = _op(request, authorization, tenant)
        return service.get_role(op, role_id)

    @app.patch("/admin/api/roles/{role_id}", response_model=RoleDetail)
    def admin_patch_role(
        role_id: str,
        body: PatchRoleRequest,
        request: Request,
        authorization: Auth = None,
        tenant: ActingTenant = None,
    ) -> RoleDetail:
        service, op = _op(request, authorization, tenant, ADMIN_WRITE)
        return service.patch_role(op, role_id, body)

    @app.delete("/admin/api/roles/{role_id}", status_code=204)
    def admin_delete_role(
        role_id: str, request: Request, authorization: Auth = None, tenant: ActingTenant = None
    ) -> Response:
        service, op = _op(request, authorization, tenant, ADMIN_WRITE)
        service.delete_role(op, role_id)
        return Response(status_code=204)

    @app.put("/admin/api/roles/{role_id}/permissions", response_model=RoleDetail)
    def admin_set_role_permissions(
        role_id: str,
        body: SetRolePermissionsRequest,
        request: Request,
        authorization: Auth = None,
        tenant: ActingTenant = None,
    ) -> RoleDetail:
        service, op = _op(request, authorization, tenant, ADMIN_WRITE)
        return service.set_role_permissions(op, role_id, body)

    @app.get("/admin/api/permissions", response_model=list[PermissionPublic])
    def admin_list_permissions(
        request: Request,
        authorization: Auth = None,
        tenant: ActingTenant = None,
        application_id: str | None = None,
    ) -> list[PermissionPublic]:
        service, op = _op(request, authorization, tenant)
        return service.list_permissions(op, application_id)

    @app.post("/admin/api/permissions", response_model=PermissionPublic, status_code=201)
    def admin_create_permission(
        body: CreatePermissionRequest,
        request: Request,
        authorization: Auth = None,
        tenant: ActingTenant = None,
    ) -> PermissionPublic:
        service, op = _op(request, authorization, tenant, ADMIN_WRITE)
        return service.create_permission(op, body)

    # ---------------------------------------------------------------- decisions and policy

    @app.get("/admin/api/decisions", response_model=DecisionListResponse)
    def admin_list_decisions(
        request: Request,
        authorization: Auth = None,
        tenant: ActingTenant = None,
        user_id: str | None = None,
        application_id: str | None = None,
        action: Action | None = None,
        limit: int = Query(default=50, ge=1, le=200),
    ) -> DecisionListResponse:
        service, op = _op(request, authorization, tenant, DECISIONS_READ)
        return service.list_decisions(
            op, user_id=user_id, application_id=application_id, action=action, limit=limit
        )

    @app.get("/admin/api/decisions/{event_id}", response_model=DecisionRecord)
    def admin_get_decision(
        event_id: UUID, request: Request, authorization: Auth = None, tenant: ActingTenant = None
    ) -> DecisionRecord:
        service, op = _op(request, authorization, tenant, DECISIONS_READ)
        return service.get_decision(op, event_id)

    @app.get("/admin/api/alerts", response_model=list[ActiveAlert])
    def admin_alerts(
        request: Request, authorization: Auth = None, tenant: ActingTenant = None
    ) -> list[ActiveAlert]:
        service, op = _op(request, authorization, tenant)
        return service.alerts(op)

    @app.get("/admin/api/policy", response_model=TenantPolicy)
    def admin_get_policy(
        request: Request, authorization: Auth = None, tenant: ActingTenant = None
    ) -> TenantPolicy:
        service, op = _op(request, authorization, tenant)
        return service.get_policy(op)

    @app.put("/admin/api/policy", response_model=TenantPolicy)
    def admin_put_policy(
        body: TenantPolicy,
        request: Request,
        authorization: Auth = None,
        tenant: ActingTenant = None,
    ) -> TenantPolicy:
        service, op = _op(request, authorization, tenant, POLICY_WRITE)
        return service.put_policy(op, body)

    @app.get("/admin/api/effectiveness")
    def admin_effectiveness(
        request: Request, authorization: Auth = None, tenant: ActingTenant = None
    ) -> dict:
        """D-2: how each policy did on the held-out evaluation logins. The same
        numbers for every tenant: they are evidence about the engine, not data
        of the tenant."""
        _op(request, authorization, tenant)
        return json.loads((Path(__file__).parent / "data" / "policy_comparison.json").read_text())

    @app.get("/admin", include_in_schema=False)
    @app.get("/admin/{path:path}", include_in_schema=False)
    def admin_spa(path: str = "") -> Response:
        if path.startswith("api/"):
            raise HTTPException(status_code=404, detail="not found")
        index = ADMIN_DIR / "index.html"
        if index.is_file():
            return FileResponse(index, media_type="text/html")
        return HTMLResponse(ADMIN_MISSING_HTML, status_code=503)

    return app


def _resolve_client(body: LoginRequest, request: Request) -> LoginRequest:
    """Turn a public client_id into the internal application_id the rest of the
    login uses. An unknown client_id stays unknown: it is passed on as an
    application id no application has, and fails like one."""
    if body.client_id is None:
        return body
    with session_scope(request.app.state.session_factory) as session:
        app_id = session.scalar(
            select(Application.application_id).where(Application.client_id == body.client_id)
        )
    return body.model_copy(update={"application_id": app_id or f"unknown:{body.client_id}", "client_id": None})


def _observed(body, request: Request):
    """Score what the request shows, not what the body claims (ADR-0032).

    Where client-reported signals are not trusted (the cloud): the address is
    the request's, and a country/ASN override counts only inside a valid
    simulation ticket — otherwise it is dropped.
    """
    settings: Settings = request.app.state.settings
    if settings.trust_client_reported_ip:
        return body
    ticket = verify_ticket(settings.simulation_secret, getattr(body, "simulation_ticket", None))
    update = {
        "ip_address": client_ip(request, settings),
        "country": ticket.country if ticket else None,
        "asn": ticket.asn if ticket else None,
    }
    if hasattr(body, "simulation_ticket"):
        update["simulation_ticket"] = None
    return body.model_copy(update=update)


def _run(request: Request, op):
    service: LoginService = request.app.state.login_service
    try:
        return op(service)
    except HTTPException:
        raise
    except Exception as exc:  # pragma: no cover
        logger.exception("unhandled IdP error")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


app = create_app()
