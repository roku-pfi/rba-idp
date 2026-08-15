"""IdP-6 admin BFF: users/apps locally; decisions and policy via HTTP."""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from fastapi import HTTPException
from rba_contracts import (
    Action,
    AdminUserPublic,
    ApplicationPublic,
    CreateApplicationRequest,
    CreateUserRequest,
    DecisionListResponse,
    DecisionRecord,
    PatchApplicationRequest,
    PatchUserRequest,
    PolicyConfig,
)
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

from rba_idp.clients import (
    AuditClient,
    AuditNotFound,
    ControlPlaneUnavailable,
    PolicyClient,
    PolicyRejected,
)
from rba_idp.db.models import Application, User
from rba_idp.db.session import session_scope
from rba_idp.passwords import hash_password
from rba_idp.services.login import LoginService, _as_utc


def _user_public(row: User) -> AdminUserPublic:
    return AdminUserPublic(
        user_id=row.user_id,
        email=row.email,
        enabled=row.enabled,
        is_admin=bool(row.is_admin),
        created_at=_as_utc(row.created_at),
    )


def _app_public(row: Application) -> ApplicationPublic:
    return ApplicationPublic(
        application_id=row.application_id,
        name=row.name,
        enabled=row.enabled,
        created_at=_as_utc(row.created_at),
    )


class AdminService:
    def __init__(
        self,
        session_factory: sessionmaker,
        login: LoginService,
        policy: PolicyClient,
        audit: AuditClient,
    ) -> None:
        self._session_factory = session_factory
        self._login = login
        self._policy = policy
        self._audit = audit

    def require_admin(self, authorization: str | None) -> User:
        return self._login.require_admin(authorization)

    def list_users(self) -> list[AdminUserPublic]:
        with session_scope(self._session_factory) as session:
            rows = session.scalars(select(User).order_by(User.email)).all()
            return [_user_public(row) for row in rows]

    def create_user(self, body: CreateUserRequest) -> AdminUserPublic:
        email = body.email.strip().lower()
        user_id = f"usr_{uuid4().hex[:12]}"
        with session_scope(self._session_factory) as session:
            if session.scalar(select(User).where(User.email == email)) is not None:
                raise HTTPException(status_code=409, detail="email already exists")
            row = User(
                user_id=user_id,
                email=email,
                password_hash=hash_password(body.password),
                enabled=True,
                is_admin=body.is_admin,
                created_at=datetime.now(timezone.utc),
            )
            session.add(row)
            try:
                session.flush()
            except IntegrityError as exc:
                raise HTTPException(status_code=409, detail="email already exists") from exc
            session.refresh(row)
            return _user_public(row)

    def patch_user(self, user_id: str, body: PatchUserRequest) -> AdminUserPublic:
        with session_scope(self._session_factory) as session:
            row = session.get(User, user_id)
            if row is None:
                raise HTTPException(status_code=404, detail="unknown user")
            if body.enabled is not None:
                row.enabled = body.enabled
            if body.is_admin is not None:
                row.is_admin = body.is_admin
            if body.password is not None:
                row.password_hash = hash_password(body.password)
            session.flush()
            session.refresh(row)
            return _user_public(row)

    def list_applications(self) -> list[ApplicationPublic]:
        with session_scope(self._session_factory) as session:
            rows = session.scalars(
                select(Application).order_by(Application.application_id)
            ).all()
            return [_app_public(row) for row in rows]

    def create_application(self, body: CreateApplicationRequest) -> ApplicationPublic:
        with session_scope(self._session_factory) as session:
            if session.get(Application, body.application_id) is not None:
                raise HTTPException(
                    status_code=409, detail="application_id already exists"
                )
            row = Application(
                application_id=body.application_id,
                name=body.name,
                enabled=True,
                created_at=datetime.now(timezone.utc),
            )
            session.add(row)
            session.flush()
            session.refresh(row)
            return _app_public(row)

    def patch_application(
        self, application_id: str, body: PatchApplicationRequest
    ) -> ApplicationPublic:
        with session_scope(self._session_factory) as session:
            row = session.get(Application, application_id)
            if row is None:
                raise HTTPException(status_code=404, detail="unknown application")
            if body.name is not None:
                row.name = body.name
            if body.enabled is not None:
                row.enabled = body.enabled
            session.flush()
            session.refresh(row)
            return _app_public(row)

    def list_decisions(
        self,
        *,
        user_id: str | None = None,
        application_id: str | None = None,
        action: Action | None = None,
        limit: int = 50,
    ) -> DecisionListResponse:
        try:
            return self._audit.list_decisions(
                user_id=user_id,
                application_id=application_id,
                action=action,
                limit=limit,
            )
        except ControlPlaneUnavailable as exc:
            raise HTTPException(status_code=503, detail="decision store unavailable") from exc

    def get_decision(self, event_id) -> DecisionRecord:
        try:
            return self._audit.get_decision(event_id)
        except AuditNotFound as exc:
            raise HTTPException(status_code=404, detail="unknown event") from exc
        except ControlPlaneUnavailable as exc:
            raise HTTPException(status_code=503, detail="decision store unavailable") from exc

    def get_policy(self) -> PolicyConfig:
        try:
            return self._policy.get_policy()
        except ControlPlaneUnavailable as exc:
            raise HTTPException(status_code=503, detail="PDP unavailable") from exc

    def put_policy(self, body: PolicyConfig) -> PolicyConfig:
        try:
            return self._policy.put_policy(body)
        except PolicyRejected as exc:
            raise HTTPException(status_code=422, detail=exc.detail) from exc
        except ControlPlaneUnavailable as exc:
            raise HTTPException(status_code=503, detail="PDP unavailable") from exc
