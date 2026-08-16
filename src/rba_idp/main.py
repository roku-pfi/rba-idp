"""FastAPI application factory. IdP-7: hosted login + admin console + groups."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import Annotated
from uuid import UUID

from fastapi import FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import FileResponse, HTMLResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from rba_contracts import (
    Action,
    AddGroupMemberRequest,
    AdminUserPublic,
    ApplicationPublic,
    CreateApplicationRequest,
    CreateGroupGrantRequest,
    CreateGroupRequest,
    CreateUserRequest,
    DecisionListResponse,
    DecisionRecord,
    GroupDetail,
    GroupPublic,
    LoginRequest,
    LoginResponse,
    MfaVerifyRequest,
    PatchApplicationRequest,
    PatchGroupRequest,
    PatchUserRequest,
    PolicyConfig,
    SessionResponse,
)

from rba_idp.clients import AuditClient, HttpAuditClient, HttpPolicyClient, PolicyClient
from rba_idp.config import Settings, get_settings
from rba_idp.db.session import create_tables, make_engine, make_session_factory
from rba_idp.pdp import HttpPdpClient, PdpClient
from rba_idp.seed import seed_identity
from rba_idp.services.admin import AdminService
from rba_idp.services.login import LoginService
from rba_idp.web import WEB_DIR
from rba_idp.web.context import hosted_boot

logger = logging.getLogger(__name__)

ADMIN_DIR = WEB_DIR / "admin"
ADMIN_INDEX_HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>RBA Admin</title>
  <link rel="stylesheet" href="/static/admin.css">
</head>
<body>
  <div id="root"></div>
  <script src="/static/admin.js"></script>
</body>
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
        engine = make_engine(settings.database_url, memory=settings.use_memory_db)
        create_tables(engine)
        session_factory = make_session_factory(engine)
        with session_factory() as session:
            seed_identity(session, settings)
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
        login_service = LoginService(session_factory, pdp, settings)
        app.state.settings = settings
        app.state.pdp_client = pdp
        app.state.policy_client = policy
        app.state.audit_client = audit
        app.state.session_factory = session_factory
        app.state.login_service = login_service
        app.state.admin_service = AdminService(
            session_factory, login_service, policy, audit
        )
        logger.info(
            "rba-idp ready (IdP-7: groups). seed app=%s admin=%s pdp=%s audit=%s",
            settings.seed_application_id,
            settings.seed_admin_email,
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
        version="0.3.0",
        lifespan=lifespan,
    )
    templates = Jinja2Templates(directory=str(WEB_DIR / "templates"))
    app.mount("/static", StaticFiles(directory=str(WEB_DIR / "static")), name="static")
    assets = ADMIN_DIR / "assets"
    if assets.is_dir():
        app.mount("/admin/assets", StaticFiles(directory=str(assets)), name="admin-assets")

    def hosted_login(request: Request, application_id: str | None = None):
        boot = hosted_boot(request, settings, application_id)
        return templates.TemplateResponse(
            request=request,
            name="login.html",
            context={"boot": boot},
        )

    @app.get("/", include_in_schema=False)
    def home(request: Request, application_id: str | None = None):
        return hosted_login(request, application_id)

    @app.get("/login", include_in_schema=False)
    def login_page(request: Request, application_id: str | None = None):
        return hosted_login(request, application_id)

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
        return _run(request, lambda svc: svc.login(body))

    @app.post(
        "/mfa/verify",
        response_model=LoginResponse,
        response_model_exclude_none=True,
        response_model_exclude_defaults=True,
    )
    def verify_mfa(body: MfaVerifyRequest, request: Request) -> LoginResponse:
        return _run(request, lambda svc: svc.verify_mfa(body))

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

    def _admin(request: Request) -> AdminService:
        return request.app.state.admin_service

    def _guard(request: Request, authorization: str | None) -> AdminService:
        service = _admin(request)
        service.require_admin(authorization)
        return service

    @app.get("/admin/api/users", response_model=list[AdminUserPublic])
    def admin_list_users(
        request: Request,
        authorization: Annotated[str | None, Header()] = None,
    ) -> list[AdminUserPublic]:
        return _guard(request, authorization).list_users()

    @app.post(
        "/admin/api/users",
        response_model=AdminUserPublic,
        status_code=201,
    )
    def admin_create_user(
        body: CreateUserRequest,
        request: Request,
        authorization: Annotated[str | None, Header()] = None,
    ) -> AdminUserPublic:
        return _guard(request, authorization).create_user(body)

    @app.patch("/admin/api/users/{user_id}", response_model=AdminUserPublic)
    def admin_patch_user(
        user_id: str,
        body: PatchUserRequest,
        request: Request,
        authorization: Annotated[str | None, Header()] = None,
    ) -> AdminUserPublic:
        return _guard(request, authorization).patch_user(user_id, body)

    @app.get("/admin/api/applications", response_model=list[ApplicationPublic])
    def admin_list_apps(
        request: Request,
        authorization: Annotated[str | None, Header()] = None,
    ) -> list[ApplicationPublic]:
        return _guard(request, authorization).list_applications()

    @app.post(
        "/admin/api/applications",
        response_model=ApplicationPublic,
        status_code=201,
    )
    def admin_create_app(
        body: CreateApplicationRequest,
        request: Request,
        authorization: Annotated[str | None, Header()] = None,
    ) -> ApplicationPublic:
        return _guard(request, authorization).create_application(body)

    @app.patch(
        "/admin/api/applications/{application_id}",
        response_model=ApplicationPublic,
    )
    def admin_patch_app(
        application_id: str,
        body: PatchApplicationRequest,
        request: Request,
        authorization: Annotated[str | None, Header()] = None,
    ) -> ApplicationPublic:
        return _guard(request, authorization).patch_application(application_id, body)

    @app.get("/admin/api/groups", response_model=list[GroupPublic])
    def admin_list_groups(
        request: Request,
        authorization: Annotated[str | None, Header()] = None,
    ) -> list[GroupPublic]:
        return _guard(request, authorization).list_groups()

    @app.post(
        "/admin/api/groups",
        response_model=GroupDetail,
        status_code=201,
    )
    def admin_create_group(
        body: CreateGroupRequest,
        request: Request,
        authorization: Annotated[str | None, Header()] = None,
    ) -> GroupDetail:
        return _guard(request, authorization).create_group(body)

    @app.get("/admin/api/groups/{group_id}", response_model=GroupDetail)
    def admin_get_group(
        group_id: str,
        request: Request,
        authorization: Annotated[str | None, Header()] = None,
    ) -> GroupDetail:
        return _guard(request, authorization).get_group(group_id)

    @app.patch("/admin/api/groups/{group_id}", response_model=GroupDetail)
    def admin_patch_group(
        group_id: str,
        body: PatchGroupRequest,
        request: Request,
        authorization: Annotated[str | None, Header()] = None,
    ) -> GroupDetail:
        return _guard(request, authorization).patch_group(group_id, body)

    @app.delete("/admin/api/groups/{group_id}", status_code=204)
    def admin_delete_group(
        group_id: str,
        request: Request,
        authorization: Annotated[str | None, Header()] = None,
    ) -> Response:
        _guard(request, authorization).delete_group(group_id)
        return Response(status_code=204)

    @app.post("/admin/api/groups/{group_id}/members", response_model=GroupDetail)
    def admin_add_member(
        group_id: str,
        body: AddGroupMemberRequest,
        request: Request,
        authorization: Annotated[str | None, Header()] = None,
    ) -> GroupDetail:
        return _guard(request, authorization).add_member(group_id, body)

    @app.delete(
        "/admin/api/groups/{group_id}/members/{user_id}",
        response_model=GroupDetail,
    )
    def admin_remove_member(
        group_id: str,
        user_id: str,
        request: Request,
        authorization: Annotated[str | None, Header()] = None,
    ) -> GroupDetail:
        return _guard(request, authorization).remove_member(group_id, user_id)

    @app.post("/admin/api/groups/{group_id}/grants", response_model=GroupDetail)
    def admin_add_grant(
        group_id: str,
        body: CreateGroupGrantRequest,
        request: Request,
        authorization: Annotated[str | None, Header()] = None,
    ) -> GroupDetail:
        return _guard(request, authorization).add_grant(group_id, body)

    @app.delete(
        "/admin/api/groups/{group_id}/grants/{application_id}",
        response_model=GroupDetail,
    )
    def admin_remove_grant(
        group_id: str,
        application_id: str,
        request: Request,
        authorization: Annotated[str | None, Header()] = None,
    ) -> GroupDetail:
        return _guard(request, authorization).remove_grant(group_id, application_id)

    @app.get("/admin/api/decisions", response_model=DecisionListResponse)
    def admin_list_decisions(
        request: Request,
        authorization: Annotated[str | None, Header()] = None,
        user_id: str | None = None,
        application_id: str | None = None,
        action: Action | None = None,
        limit: int = Query(default=50, ge=1, le=200),
    ) -> DecisionListResponse:
        return _guard(request, authorization).list_decisions(
            user_id=user_id,
            application_id=application_id,
            action=action,
            limit=limit,
        )

    @app.get("/admin/api/decisions/{event_id}", response_model=DecisionRecord)
    def admin_get_decision(
        event_id: UUID,
        request: Request,
        authorization: Annotated[str | None, Header()] = None,
    ) -> DecisionRecord:
        return _guard(request, authorization).get_decision(event_id)

    @app.get("/admin/api/policy", response_model=PolicyConfig)
    def admin_get_policy(
        request: Request,
        authorization: Annotated[str | None, Header()] = None,
    ) -> PolicyConfig:
        return _guard(request, authorization).get_policy()

    @app.put("/admin/api/policy", response_model=PolicyConfig)
    def admin_put_policy(
        body: PolicyConfig,
        request: Request,
        authorization: Annotated[str | None, Header()] = None,
    ) -> PolicyConfig:
        return _guard(request, authorization).put_policy(body)

    @app.get("/admin", include_in_schema=False)
    @app.get("/admin/{path:path}", include_in_schema=False)
    def admin_spa(path: str = "") -> Response:
        if path.startswith("api/"):
            raise HTTPException(status_code=404, detail="not found")
        index = ADMIN_DIR / "index.html"
        if index.is_file():
            return FileResponse(index, media_type="text/html")
        return HTMLResponse(ADMIN_INDEX_HTML)

    return app


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
