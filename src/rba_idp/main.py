"""FastAPI application factory. IdP-5: hosted login UI on the IdP origin."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import Annotated

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from rba_contracts import LoginRequest, LoginResponse, MfaVerifyRequest, SessionResponse

from rba_idp.config import Settings, get_settings
from rba_idp.db.session import create_tables, make_engine, make_session_factory
from rba_idp.pdp import HttpPdpClient, PdpClient
from rba_idp.seed import seed_identity
from rba_idp.services.login import LoginService
from rba_idp.web import WEB_DIR
from rba_idp.web.context import hosted_boot

logger = logging.getLogger(__name__)


def create_app(
    settings: Settings | None = None,
    *,
    pdp_client: PdpClient | None = None,
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
        app.state.settings = settings
        app.state.pdp_client = pdp
        app.state.session_factory = session_factory
        app.state.login_service = LoginService(session_factory, pdp, settings)
        logger.info(
            "rba-idp ready (IdP-5: hosted login). seed app=%s user=%s pdp=%s",
            settings.seed_application_id,
            settings.seed_email,
            settings.pdp_base_url,
        )
        yield
        close = getattr(pdp, "close", None)
        if callable(close):
            close()

    app = FastAPI(
        title=settings.app_name,
        version="0.1.0",
        lifespan=lifespan,
    )
    templates = Jinja2Templates(directory=str(WEB_DIR / "templates"))
    app.mount("/static", StaticFiles(directory=str(WEB_DIR / "static")), name="static")

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
