"""IdP-6/7 admin BFF: users/apps/groups locally; decisions and policy via HTTP."""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from fastapi import HTTPException
from rba_contracts import (
    Action,
    AddGroupMemberRequest,
    AdminUserPublic,
    AppPermission,
    ApplicationPublic,
    CreateApplicationRequest,
    CreateGroupGrantRequest,
    CreateGroupRequest,
    CreateUserRequest,
    DecisionListResponse,
    DecisionRecord,
    GroupDetail,
    GroupGrantPublic,
    GroupMemberPublic,
    GroupPublic,
    PatchApplicationRequest,
    PatchGroupRequest,
    PatchUserRequest,
    PolicyConfig,
)
from sqlalchemy import delete, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

from rba_idp.clients import (
    AuditClient,
    AuditNotFound,
    ControlPlaneUnavailable,
    PolicyClient,
    PolicyRejected,
)
from rba_idp.db.models import Application, Group, GroupAppGrant, GroupMembership, User
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
        redirect_uri=row.redirect_uri,
    )


def _member_counts(session, group_ids: list[str]) -> dict[str, int]:
    if not group_ids:
        return {}
    rows = session.execute(
        select(GroupMembership.group_id, func.count())
        .where(GroupMembership.group_id.in_(group_ids))
        .group_by(GroupMembership.group_id)
    ).all()
    return {group_id: count for group_id, count in rows}


def _group_detail(session, row: Group) -> GroupDetail:
    members = session.scalars(
        select(GroupMembership).where(GroupMembership.group_id == row.group_id)
    ).all()
    users_by_id = {}
    if members:
        users_by_id = {
            user.user_id: user
            for user in session.scalars(
                select(User).where(User.user_id.in_([m.user_id for m in members]))
            ).all()
        }
    grants = session.scalars(
        select(GroupAppGrant).where(GroupAppGrant.group_id == row.group_id)
    ).all()
    return GroupDetail(
        group_id=row.group_id,
        name=row.name,
        description=row.description,
        member_count=len(members),
        created_at=_as_utc(row.created_at),
        members=[
            GroupMemberPublic(
                user_id=item.user_id,
                email=users_by_id[item.user_id].email
                if item.user_id in users_by_id
                else item.user_id,
            )
            for item in sorted(members, key=lambda m: m.user_id)
        ],
        grants=[
            GroupGrantPublic(
                application_id=item.application_id,
                permission=AppPermission(item.permission),
            )
            for item in sorted(grants, key=lambda g: g.application_id)
        ],
    )


def _require_group(session, group_id: str) -> Group:
    row = session.get(Group, group_id)
    if row is None:
        raise HTTPException(status_code=404, detail="unknown group")
    return row


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
                redirect_uri=body.redirect_uri,
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
            if body.redirect_uri is not None:
                row.redirect_uri = body.redirect_uri or None
            session.flush()
            session.refresh(row)
            return _app_public(row)

    def list_groups(self) -> list[GroupPublic]:
        with session_scope(self._session_factory) as session:
            rows = session.scalars(select(Group).order_by(Group.name)).all()
            counts = _member_counts(session, [row.group_id for row in rows])
            return [
                GroupPublic(
                    group_id=row.group_id,
                    name=row.name,
                    description=row.description,
                    member_count=counts.get(row.group_id, 0),
                    created_at=_as_utc(row.created_at),
                )
                for row in rows
            ]

    def get_group(self, group_id: str) -> GroupDetail:
        with session_scope(self._session_factory) as session:
            return _group_detail(session, _require_group(session, group_id))

    def create_group(self, body: CreateGroupRequest) -> GroupDetail:
        group_id = body.group_id or f"grp_{uuid4().hex[:12]}"
        with session_scope(self._session_factory) as session:
            if session.get(Group, group_id) is not None:
                raise HTTPException(status_code=409, detail="group_id already exists")
            existing_name = session.scalar(select(Group).where(Group.name == body.name))
            if existing_name is not None:
                raise HTTPException(status_code=409, detail="group name already exists")
            row = Group(
                group_id=group_id,
                name=body.name,
                description=body.description,
                created_at=datetime.now(timezone.utc),
            )
            session.add(row)
            try:
                session.flush()
            except IntegrityError as exc:
                raise HTTPException(
                    status_code=409, detail="group_id or name already exists"
                ) from exc
            session.refresh(row)
            return _group_detail(session, row)

    def patch_group(self, group_id: str, body: PatchGroupRequest) -> GroupDetail:
        with session_scope(self._session_factory) as session:
            row = _require_group(session, group_id)
            if body.name is not None:
                clash = session.scalar(
                    select(Group).where(Group.name == body.name, Group.group_id != group_id)
                )
                if clash is not None:
                    raise HTTPException(status_code=409, detail="group name already exists")
                row.name = body.name
            if body.description is not None:
                row.description = body.description
            try:
                session.flush()
            except IntegrityError as exc:
                raise HTTPException(
                    status_code=409, detail="group name already exists"
                ) from exc
            session.refresh(row)
            return _group_detail(session, row)

    def delete_group(self, group_id: str) -> None:
        with session_scope(self._session_factory) as session:
            _require_group(session, group_id)
            session.execute(
                delete(GroupMembership).where(GroupMembership.group_id == group_id)
            )
            session.execute(
                delete(GroupAppGrant).where(GroupAppGrant.group_id == group_id)
            )
            session.execute(delete(Group).where(Group.group_id == group_id))

    def add_member(self, group_id: str, body: AddGroupMemberRequest) -> GroupDetail:
        with session_scope(self._session_factory) as session:
            row = _require_group(session, group_id)
            user = session.get(User, body.user_id)
            if user is None:
                raise HTTPException(status_code=404, detail="unknown user")
            if session.get(GroupMembership, (group_id, body.user_id)) is not None:
                raise HTTPException(status_code=409, detail="user is already a member")
            session.add(GroupMembership(group_id=group_id, user_id=body.user_id))
            session.flush()
            return _group_detail(session, row)

    def remove_member(self, group_id: str, user_id: str) -> GroupDetail:
        with session_scope(self._session_factory) as session:
            row = _require_group(session, group_id)
            membership = session.get(GroupMembership, (group_id, user_id))
            if membership is None:
                raise HTTPException(status_code=404, detail="unknown membership")
            session.delete(membership)
            session.flush()
            return _group_detail(session, row)

    def add_grant(self, group_id: str, body: CreateGroupGrantRequest) -> GroupDetail:
        permission = body.permission.value
        with session_scope(self._session_factory) as session:
            row = _require_group(session, group_id)
            app = session.get(Application, body.application_id)
            if app is None:
                raise HTTPException(status_code=404, detail="unknown application")
            key = (group_id, body.application_id, permission)
            if session.get(GroupAppGrant, key) is not None:
                raise HTTPException(status_code=409, detail="grant already exists")
            session.add(
                GroupAppGrant(
                    group_id=group_id,
                    application_id=body.application_id,
                    permission=permission,
                )
            )
            session.flush()
            return _group_detail(session, row)

    def remove_grant(self, group_id: str, application_id: str) -> GroupDetail:
        with session_scope(self._session_factory) as session:
            row = _require_group(session, group_id)
            grants = session.scalars(
                select(GroupAppGrant).where(
                    GroupAppGrant.group_id == group_id,
                    GroupAppGrant.application_id == application_id,
                )
            ).all()
            if not grants:
                raise HTTPException(status_code=404, detail="unknown grant")
            for grant in grants:
                session.delete(grant)
            session.flush()
            return _group_detail(session, row)

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
