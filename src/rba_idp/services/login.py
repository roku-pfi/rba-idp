"""Password verify then PDP enforce (IdP-3). No session, no MFA challenge."""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from fastapi import HTTPException
from rba_contracts import (
    LoginOutcome,
    LoginRequest,
    LoginResponse,
    RiskEvaluateRequest,
    outcome_from_action,
)
from sqlalchemy import select
from sqlalchemy.orm import sessionmaker

from rba_idp.db.models import Application, User
from rba_idp.db.session import session_scope
from rba_idp.passwords import verify_password
from rba_idp.pdp import PdpClient, PdpUnavailable


class LoginService:
    def __init__(self, session_factory: sessionmaker, pdp: PdpClient) -> None:
        self._session_factory = session_factory
        self._pdp = pdp

    def login(self, body: LoginRequest) -> LoginResponse:
        email = body.email.strip().lower()
        with session_scope(self._session_factory) as session:
            app = session.get(Application, body.application_id)
            if app is None or not app.enabled:
                raise HTTPException(status_code=400, detail="unknown application")

            user = session.scalar(select(User).where(User.email == email))
            if user is None or not user.enabled:
                verify_password(body.password, None)
                return LoginResponse(outcome=LoginOutcome.INVALID_CREDENTIALS)

            if not verify_password(body.password, user.password_hash):
                return LoginResponse(outcome=LoginOutcome.INVALID_CREDENTIALS)

            user_id = user.user_id

        request = RiskEvaluateRequest(
            event_id=uuid4(),
            application_id=body.application_id,
            user_id=user_id,
            timestamp=datetime.now(timezone.utc),
            ip_address=body.ip_address,
            asn=body.asn,
            country=body.country,
            device_type=body.device_type,
            os=body.os,
            browser=body.browser,
            login_successful=True,
            user_agent=body.user_agent,
        )
        try:
            decision = self._pdp.evaluate(request)
        except PdpUnavailable as exc:
            raise HTTPException(status_code=503, detail="PDP unavailable") from exc

        return LoginResponse(
            outcome=outcome_from_action(decision.action),
            user_id=user_id,
            event_id=decision.event_id,
            action=decision.action,
            risk_score=decision.risk_score,
            risk_level=decision.risk_level,
            reasons=decision.reasons,
        )
