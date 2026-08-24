"""Admin BFF: users / apps / groups / roles locally; decisions and policy via HTTP.

Authorization is RBAC (ADR-0029). `require_admin` is the console entry guard
(`admin:read`); anything that writes asks separately for `admin:write` or
`policy:write`, which is what lets the support operator read a decision
without being able to change who may log in.
"""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from fastapi import HTTPException
from rba_contracts import (
    Action,
    AddGroupMemberRequest,
    AddGroupRoleRequest,
    AdminUserPublic,
    ApplicationPublic,
    CreateApplicationRequest,
    CreateGroupRequest,
    CreatePermissionRequest,
    CreateRoleRequest,
    CreateUserRequest,
    DecisionListResponse,
    DecisionRecord,
    GroupDetail,
    GroupMemberPublic,
    GroupPublic,
    GroupRolePublic,
    PatchApplicationRequest,
    PatchGroupRequest,
    PatchRoleRequest,
    PatchUserRequest,
    PermissionPublic,
    PolicyConfig,
    RoleDetail,
    RolePublic,
    SetRolePermissionsRequest,
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
from rba_idp.authz import ADMIN_WRITE, POLICY_WRITE
from rba_idp.db.models import (
    Application,
    Group,
    GroupMembership,
    GroupRole,
    Permission,
    Role,
    RolePermission,
    User,
)
from rba_idp.db.session import session_scope
from rba_idp.passwords import hash_password
from rba_idp.seed import SEED_OPERATORS_GROUP_ID
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


def _permission_public(row: Permission) -> PermissionPublic:
    return PermissionPublic(
        permission_id=row.permission_id,
        application_id=row.application_id,
        resource=row.resource,
        operation=row.operation,
        description=row.description,
    )


def _role_permissions(session, role_id: str) -> list[Permission]:
    return list(
        session.scalars(
            select(Permission)
            .join(RolePermission, RolePermission.permission_id == Permission.permission_id)
            .where(RolePermission.role_id == role_id)
            .order_by(Permission.resource, Permission.operation)
        ).all()
    )


def _role_detail(session, row: Role) -> RoleDetail:
    permissions = _role_permissions(session, row.role_id)
    return RoleDetail(
        role_id=row.role_id,
        application_id=row.application_id,
        name=row.name,
        description=row.description,
        permission_count=len(permissions),
        created_at=_as_utc(row.created_at),
        permissions=[_permission_public(item) for item in permissions],
    )


def _require_role(session, role_id: str) -> Role:
    row = session.get(Role, role_id)
    if row is None:
        raise HTTPException(status_code=404, detail="unknown role")
    return row


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
    roles = session.scalars(
        select(Role)
        .join(GroupRole, GroupRole.role_id == Role.role_id)
        .where(GroupRole.group_id == row.group_id)
        .order_by(Role.application_id, Role.name)
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
        roles=[
            GroupRolePublic(
                role_id=item.role_id,
                application_id=item.application_id,
                name=item.name,
            )
            for item in roles
        ],
    )


def _sync_admin_flag(session, user_id: str, is_admin: bool) -> None:
    """Keep `User.is_admin` and the platform-admin role from ever disagreeing.

    `is_admin` is a directory label, not an authorization input (ADR-0029) — but
    an operator who ticks it plainly means "make this person an admin". So the
    flag drives membership of the platform-admins group, which is what actually
    carries the role. Setting the label really does confer the power; clearing
    it really does remove it.
    """
    if session.get(Group, SEED_OPERATORS_GROUP_ID) is None:
        return  # unseeded database; nothing to sync against
    key = (SEED_OPERATORS_GROUP_ID, user_id)
    membership = session.get(GroupMembership, key)
    if is_admin and membership is None:
        session.add(
            GroupMembership(group_id=SEED_OPERATORS_GROUP_ID, user_id=user_id)
        )
    elif not is_admin and membership is not None:
        session.delete(membership)


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
        """Console entry: `admin:read`. Enough to look, never enough to change."""
        return self._login.require_admin(authorization)

    def require_write(self, authorization: str | None) -> User:
        """`admin:write` — identity, applications, groups and roles."""
        return self._login.require_permission(authorization, *ADMIN_WRITE)

    def require_policy_write(self, authorization: str | None) -> User:
        """`policy:write` — risk thresholds, actions and monitor mode.

        Separate from `admin:write` on purpose: changing who may log in and
        changing how risky a login has to be before it is challenged are
        different powers, and RNF-05 makes the second one editable at runtime.
        """
        return self._login.require_permission(authorization, *POLICY_WRITE)

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
            _sync_admin_flag(session, user_id, body.is_admin)
            session.flush()
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
                _sync_admin_flag(session, user_id, body.is_admin)
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
            session.execute(delete(GroupRole).where(GroupRole.group_id == group_id))
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

    # ---------------------------------------------------------------- roles

    def add_group_role(self, group_id: str, body: AddGroupRoleRequest) -> GroupDetail:
        """Assign a role to a group. This is also what grants sign-in to the
        role's application — there is no separate access grant (ADR-0029)."""
        with session_scope(self._session_factory) as session:
            row = _require_group(session, group_id)
            _require_role(session, body.role_id)
            if session.get(GroupRole, (group_id, body.role_id)) is not None:
                raise HTTPException(status_code=409, detail="role already assigned")
            session.add(GroupRole(group_id=group_id, role_id=body.role_id))
            session.flush()
            return _group_detail(session, row)

    def remove_group_role(self, group_id: str, role_id: str) -> GroupDetail:
        with session_scope(self._session_factory) as session:
            row = _require_group(session, group_id)
            assignment = session.get(GroupRole, (group_id, role_id))
            if assignment is None:
                raise HTTPException(status_code=404, detail="unknown role assignment")
            session.delete(assignment)
            session.flush()
            return _group_detail(session, row)

    def list_roles(self, application_id: str | None = None) -> list[RolePublic]:
        with session_scope(self._session_factory) as session:
            stmt = select(Role).order_by(Role.application_id, Role.name)
            if application_id is not None:
                stmt = stmt.where(Role.application_id == application_id)
            rows = session.scalars(stmt).all()
            counts = dict(
                session.execute(
                    select(RolePermission.role_id, func.count())
                    .where(RolePermission.role_id.in_([r.role_id for r in rows]))
                    .group_by(RolePermission.role_id)
                ).all()
            ) if rows else {}
            return [
                RolePublic(
                    role_id=row.role_id,
                    application_id=row.application_id,
                    name=row.name,
                    description=row.description,
                    permission_count=counts.get(row.role_id, 0),
                    created_at=_as_utc(row.created_at),
                )
                for row in rows
            ]

    def get_role(self, role_id: str) -> RoleDetail:
        with session_scope(self._session_factory) as session:
            return _role_detail(session, _require_role(session, role_id))

    def create_role(self, body: CreateRoleRequest) -> RoleDetail:
        role_id = body.role_id or f"role_{uuid4().hex[:12]}"
        with session_scope(self._session_factory) as session:
            if session.get(Application, body.application_id) is None:
                raise HTTPException(status_code=404, detail="unknown application")
            if session.get(Role, role_id) is not None:
                raise HTTPException(status_code=409, detail="role_id already exists")
            clash = session.scalar(
                select(Role).where(
                    Role.application_id == body.application_id, Role.name == body.name
                )
            )
            if clash is not None:
                raise HTTPException(
                    status_code=409, detail="role name already exists for this application"
                )
            row = Role(
                role_id=role_id,
                application_id=body.application_id,
                name=body.name,
                description=body.description,
                created_at=datetime.now(timezone.utc),
            )
            session.add(row)
            try:
                session.flush()
            except IntegrityError as exc:
                raise HTTPException(
                    status_code=409, detail="role_id or name already exists"
                ) from exc
            session.refresh(row)
            return _role_detail(session, row)

    def patch_role(self, role_id: str, body: PatchRoleRequest) -> RoleDetail:
        with session_scope(self._session_factory) as session:
            row = _require_role(session, role_id)
            if body.name is not None:
                clash = session.scalar(
                    select(Role).where(
                        Role.application_id == row.application_id,
                        Role.name == body.name,
                        Role.role_id != role_id,
                    )
                )
                if clash is not None:
                    raise HTTPException(
                        status_code=409,
                        detail="role name already exists for this application",
                    )
                row.name = body.name
            if body.description is not None:
                row.description = body.description
            session.flush()
            session.refresh(row)
            return _role_detail(session, row)

    def delete_role(self, role_id: str) -> None:
        with session_scope(self._session_factory) as session:
            _require_role(session, role_id)
            session.execute(
                delete(RolePermission).where(RolePermission.role_id == role_id)
            )
            session.execute(delete(GroupRole).where(GroupRole.role_id == role_id))
            session.execute(delete(Role).where(Role.role_id == role_id))

    def set_role_permissions(
        self, role_id: str, body: SetRolePermissionsRequest
    ) -> RoleDetail:
        """Replace the role's permission set.

        Wholesale replacement rather than add/remove: an operator editing a role
        in the console is answering "what may this role do", and a PUT of the
        whole answer cannot leave a stale permission behind.
        """
        wanted = set(body.permission_ids)
        with session_scope(self._session_factory) as session:
            row = _require_role(session, role_id)
            if wanted:
                found = session.scalars(
                    select(Permission).where(Permission.permission_id.in_(wanted))
                ).all()
                by_id = {item.permission_id: item for item in found}
                missing = sorted(wanted - by_id.keys())
                if missing:
                    raise HTTPException(
                        status_code=404,
                        detail=f"unknown permission(s): {', '.join(missing)}",
                    )
                foreign = sorted(
                    pid
                    for pid, item in by_id.items()
                    if item.application_id != row.application_id
                )
                if foreign:
                    # A role scoped to one application must never carry another
                    # application's permissions, or one tenant's admin could
                    # grant rights inside someone else's app.
                    raise HTTPException(
                        status_code=422,
                        detail=(
                            "permission(s) belong to a different application: "
                            + ", ".join(foreign)
                        ),
                    )
            session.execute(
                delete(RolePermission).where(RolePermission.role_id == role_id)
            )
            for permission_id in sorted(wanted):
                session.add(
                    RolePermission(role_id=role_id, permission_id=permission_id)
                )
            session.flush()
            return _role_detail(session, row)

    def list_permissions(
        self, application_id: str | None = None
    ) -> list[PermissionPublic]:
        with session_scope(self._session_factory) as session:
            stmt = select(Permission).order_by(
                Permission.application_id, Permission.resource, Permission.operation
            )
            if application_id is not None:
                stmt = stmt.where(Permission.application_id == application_id)
            return [_permission_public(row) for row in session.scalars(stmt).all()]

    def create_permission(self, body: CreatePermissionRequest) -> PermissionPublic:
        permission_id = (
            f"perm_{body.application_id}_{body.resource}_{body.operation}"
        ).replace("-", "_")
        with session_scope(self._session_factory) as session:
            if session.get(Application, body.application_id) is None:
                raise HTTPException(status_code=404, detail="unknown application")
            if session.get(Permission, permission_id) is not None:
                raise HTTPException(status_code=409, detail="permission already exists")
            row = Permission(
                permission_id=permission_id,
                application_id=body.application_id,
                resource=body.resource,
                operation=body.operation,
                description=body.description,
                created_at=datetime.now(timezone.utc),
            )
            session.add(row)
            try:
                session.flush()
            except IntegrityError as exc:
                raise HTTPException(
                    status_code=409, detail="permission already exists"
                ) from exc
            session.refresh(row)
            return _permission_public(row)

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
