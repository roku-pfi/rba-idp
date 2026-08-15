"""Password verify only (IdP-2). No PDP call, no session, no MFA."""

from __future__ import annotations

from fastapi import HTTPException
from rba_contracts import LoginOutcome, LoginRequest, LoginResponse
from sqlalchemy import select
from sqlalchemy.orm import sessionmaker

from rba_idp.db.models import Application, User
from rba_idp.db.session import session_scope
from rba_idp.passwords import verify_password


class LoginService:
    def __init__(self, session_factory: sessionmaker) -> None:
        self._session_factory = session_factory

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

            return LoginResponse(
                outcome=LoginOutcome.AUTHENTICATED,
                user_id=user.user_id,
            )
