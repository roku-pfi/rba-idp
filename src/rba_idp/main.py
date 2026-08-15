"""FastAPI application factory. IdP-3: POST /login verifies then asks the PDP."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from rba_contracts import LoginRequest, LoginResponse

from rba_idp.config import Settings, get_settings
from rba_idp.db.session import create_tables, make_engine, make_session_factory
from rba_idp.pdp import HttpPdpClient, PdpClient
from rba_idp.seed import seed_identity
from rba_idp.services.login import LoginService

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
        app.state.login_service = LoginService(session_factory, pdp)
        logger.info(
            "rba-idp ready (IdP-3: PDP enforce). seed app=%s user=%s pdp=%s",
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
        service: LoginService = request.app.state.login_service
        try:
            return service.login(body)
        except HTTPException:
            raise
        except Exception as exc:  # pragma: no cover
            logger.exception("unhandled login error")
            raise HTTPException(status_code=500, detail=str(exc)) from exc

    return app


app = create_app()
