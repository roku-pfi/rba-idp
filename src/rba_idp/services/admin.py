"""Admin BFF: directory locally; decisions and policy via HTTP. Tenant-scoped.

Authorization is RBAC (ADR-0029) inside a tenant (ADR-0033). Every request
resolves to an ``Operator``: who is asking, which tenant they act on, and what
they may do there. Every method below takes that tenant and filters by it, so a
missing ``WHERE tenant_id`` is the only way to leak — and each endpoint has a
cross-tenant test.

- The session must be on **its tenant's console** application. A bank session
  never reaches the admin API, even if a tenant admin defined an
  ``admin:read`` permission on the bank app.
- An object of another tenant answers exactly like a missing one (404), so ids
  cannot be probed.
- Only a **platform operator** (a user of the platform tenant holding
  ``tenants:read`` on its console) may act on another tenant, by naming it in
  the ``X-RokuSec-Tenant`` header.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from uuid import uuid4

from fastapi import HTTPException
from rba_contracts import (
    Action,
    AddGroupMemberRequest,
    AddGroupRoleRequest,
    AdminUserPublic,
    ApplicationPublic,
    BasePolicy,
    CreateApplicationRequest,
    CreateGroupRequest,
    CreatePermissionRequest,
    CreateRoleRequest,
    CreateTenantRequest,
    CreateUserRequest,
    DecisionListResponse,
    DecisionRecord,
    EngineMode,
    GroupDetail,
    GroupMemberPublic,
    GroupPublic,
    GroupRolePublic,
    LevelToAction,
    PatchApplicationRequest,
    PatchGroupRequest,
    PatchRoleRequest,
    PatchTenantRequest,
    PatchUserRequest,
    PermissionPublic,
    RiskLevel,
    RoleDetail,
    RolePublic,
    ScoreBand,
    SetRolePermissionsRequest,
    TenantBranding,
    TenantPolicy,
    TenantPublic,
)
from sqlalchemy import delete, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from rba_idp.authz import (
    ADMIN_READ,
    ADMIN_WRITE,
    DECISIONS_READ,
    POLICY_WRITE,
    TENANTS_READ,
    TENANTS_WRITE,
    scope,
)
from rba_idp.clients import (
    AuditClient,
    AuditNotFound,
    ControlPlaneUnavailable,
    PolicyClient,
    PolicyNotFound,
    PolicyRejected,
)
from rba_idp.db.models import (
    Application,
    Group,
    GroupMembership,
    GroupRole,
    Permission,
    Role,
    RolePermission,
    Tenant,
    TenantDomain,
    User,
)
from rba_idp.db.session import session_scope
from rba_idp.passwords import hash_password
from rba_idp.seed import bootstrap_console
from rba_idp.services.login import LoginService, _as_utc
from rba_idp.tenancy import TenantPolicyCache

TENANT_HEADER = "X-RokuSec-Tenant"


@dataclass(frozen=True)
class Operator:
    """The caller of one admin request, already authorized for it."""

    user_id: str
    home_tenant_id: str
    # The tenant every query of this request is scoped to.
    tenant_id: str
    permissions: frozenset[str]
    is_platform_operator: bool


# ---------------------------------------------------------------- serialisers


def _user_public(row: User) -> AdminUserPublic:
    return AdminUserPublic(
        tenant_id=row.tenant_id,
        user_id=row.user_id,
        email=row.email,
        enabled=row.enabled,
        is_admin=bool(row.is_admin),
        created_at=_as_utc(row.created_at),
    )


def _app_public(row: Application) -> ApplicationPublic:
    return ApplicationPublic(
        tenant_id=row.tenant_id,
        application_id=row.application_id,
        name=row.name,
        enabled=row.enabled,
        created_at=_as_utc(row.created_at),
        redirect_uri=row.redirect_uri,
    )


def _tenant_public(session: Session, row: Tenant) -> TenantPublic:
    domains = session.scalars(
        select(TenantDomain.domain)
        .where(TenantDomain.tenant_id == row.tenant_id)
        .order_by(TenantDomain.domain)
    ).all()
    return TenantPublic(
        tenant_id=row.tenant_id,
        name=row.name,
        operator_domains=list(domains),
        branding=TenantBranding(
            display_name=row.display_name,
            login_style=row.login_style,  # type: ignore[arg-type]
            logo_url=row.logo_url,
            primary_colour=row.primary_colour,
            accent_colour=row.accent_colour,
        ),
        is_platform=bool(row.is_platform),
        created_at=_as_utc(row.created_at),
    )


def _permission_public(row: Permission) -> PermissionPublic:
    return PermissionPublic(
        permission_id=row.permission_id,
        application_id=row.application_id,
        resource=row.resource,
        operation=row.operation,
        description=row.description,
    )


def _role_permissions(session: Session, role_id: str) -> list[Permission]:
    return list(
        session.scalars(
            select(Permission)
            .join(RolePermission, RolePermission.permission_id == Permission.permission_id)
            .where(RolePermission.role_id == role_id)
            .order_by(Permission.resource, Permission.operation)
        ).all()
    )


def _role_detail(session: Session, row: Role) -> RoleDetail:
    permissions = _role_permissions(session, row.role_id)
    return RoleDetail(
        tenant_id=row.tenant_id,
        role_id=row.role_id,
        application_id=row.application_id,
        name=row.name,
        description=row.description,
        permission_count=len(permissions),
        created_at=_as_utc(row.created_at),
        permissions=[_permission_public(item) for item in permissions],
    )


def _member_counts(session: Session, group_ids: list[str]) -> dict[str, int]:
    if not group_ids:
        return {}
    rows = session.execute(
        select(GroupMembership.group_id, func.count())
        .where(GroupMembership.group_id.in_(group_ids))
        .group_by(GroupMembership.group_id)
    ).all()
    return {group_id: count for group_id, count in rows}


def _group_detail(session: Session, row: Group) -> GroupDetail:
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
        tenant_id=row.tenant_id,
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


# ---------------------------------------------------------------- tenant-scoped lookups
#
# One helper per entity. Each answers 404 for "missing" and for "another
# tenant's" alike — the caller cannot tell the two apart.


def _require_user(session: Session, tenant_id: str, user_id: str) -> User:
    row = session.get(User, user_id)
    if row is None or row.tenant_id != tenant_id:
        raise HTTPException(status_code=404, detail="unknown user")
    return row


def _require_application(session: Session, tenant_id: str, application_id: str) -> Application:
    row = session.get(Application, application_id)
    if row is None or row.tenant_id != tenant_id:
        raise HTTPException(status_code=404, detail="unknown application")
    return row


def _require_group(session: Session, tenant_id: str, group_id: str) -> Group:
    row = session.get(Group, group_id)
    if row is None or row.tenant_id != tenant_id:
        raise HTTPException(status_code=404, detail="unknown group")
    return row


def _require_role(session: Session, tenant_id: str, role_id: str) -> Role:
    row = session.get(Role, role_id)
    if row is None or row.tenant_id != tenant_id:
        raise HTTPException(status_code=404, detail="unknown role")
    return row


def _require_tenant(session: Session, tenant_id: str) -> Tenant:
    row = session.get(Tenant, tenant_id)
    if row is None:
        raise HTTPException(status_code=404, detail="unknown tenant")
    return row


def _sync_admin_flag(session: Session, tenant: Tenant, user_id: str, is_admin: bool) -> None:
    """Keep `User.is_admin` and the tenant's admin group from ever disagreeing.

    `is_admin` is a directory label, not an authorization input (ADR-0029) — but
    an operator who ticks it plainly means "make this person an admin of this
    organisation". So the flag drives membership of the tenant's admin group,
    which is what actually carries the console role.
    """
    group_id = tenant.admin_group_id
    if not group_id or session.get(Group, group_id) is None:
        return
    membership = session.get(GroupMembership, (group_id, user_id))
    if is_admin and membership is None:
        session.add(GroupMembership(group_id=group_id, user_id=user_id))
    elif not is_admin and membership is not None:
        session.delete(membership)


def _set_domains(session: Session, tenant_id: str, domains: list[str]) -> None:
    """Replace a tenant's operator domains. A domain owned elsewhere is a 409."""
    for domain in domains:
        owner = session.get(TenantDomain, domain)
        if owner is not None and owner.tenant_id != tenant_id:
            raise HTTPException(status_code=409, detail=f"domain already registered: {domain}")
    session.execute(delete(TenantDomain).where(TenantDomain.tenant_id == tenant_id))
    session.flush()
    for domain in domains:
        session.add(TenantDomain(domain=domain, tenant_id=tenant_id))


def starter_policy(tenant_id: str) -> TenantPolicy:
    """A new tenant starts the way most organisations already work: password
    only, with the engine watching and enforcing nothing (ADR-0034)."""
    return TenantPolicy(
        tenant_id=tenant_id,
        policy_version="1.0.0",
        base_policy=BasePolicy.PASSWORD_ONLY,
        engine_mode=EngineMode.MONITOR,
        score_to_level=[
            ScoreBand(max=0.30, level=RiskLevel.LOW),
            ScoreBand(max=0.60, level=RiskLevel.MEDIUM),
            ScoreBand(max=0.80, level=RiskLevel.HIGH),
            ScoreBand(max=1.00, level=RiskLevel.CRITICAL),
        ],
        level_to_action=LevelToAction(
            LOW=Action.ALLOW,
            MEDIUM=Action.REQUIRE_MFA,
            HIGH=Action.REAUTHENTICATE,
            CRITICAL=Action.BLOCK,
        ),
        fallback_action=Action.REQUIRE_MFA,
    )


class AdminService:
    def __init__(
        self,
        session_factory: sessionmaker,
        login: LoginService,
        policy: PolicyClient,
        audit: AuditClient,
        policy_cache: TenantPolicyCache,
    ) -> None:
        self._session_factory = session_factory
        self._login = login
        self._policy = policy
        self._audit = audit
        self._policy_cache = policy_cache

    # ---------------------------------------------------------------- guard

    def authorize(
        self,
        authorization: str | None,
        acting_tenant: str | None,
        needs: tuple[str, str] = ADMIN_READ,
    ) -> Operator:
        """Resolve the caller and check one permission on their console.

        ``acting_tenant`` is the ``X-RokuSec-Tenant`` header. Naming one's own
        tenant (or nothing) is always allowed; naming another requires being a
        platform operator. The 403 is the same whatever tenant was named, so
        the header cannot be used to discover tenants either.
        """
        row, user, permissions = self._login.load_session(authorization)
        with session_scope(self._session_factory) as session:
            home = session.get(Tenant, user.tenant_id)
            if home is None or row.application_id != home.console_application_id:
                raise HTTPException(status_code=403, detail="not a console session")
            platform = bool(home.is_platform) and scope(*TENANTS_READ) in permissions
            target = (acting_tenant or "").strip() or home.tenant_id
            if target != home.tenant_id:
                if not platform:
                    raise HTTPException(
                        status_code=403,
                        detail=f"requires permission {scope(*TENANTS_READ)}",
                    )
                _require_tenant(session, target)
        if scope(*needs) not in permissions:
            raise HTTPException(status_code=403, detail=f"requires permission {scope(*needs)}")
        return Operator(
            user_id=user.user_id,
            home_tenant_id=user.tenant_id,
            tenant_id=target,
            permissions=frozenset(permissions),
            is_platform_operator=platform,
        )

    def authorize_platform(
        self, authorization: str | None, needs: tuple[str, str]
    ) -> Operator:
        op = self.authorize(authorization, None, needs)
        if not op.is_platform_operator:
            raise HTTPException(status_code=403, detail=f"requires permission {scope(*TENANTS_READ)}")
        return op

    # ---------------------------------------------------------------- tenants

    def current_tenant(self, op: Operator) -> TenantPublic:
        with session_scope(self._session_factory) as session:
            return _tenant_public(session, _require_tenant(session, op.tenant_id))

    def list_tenants(self) -> list[TenantPublic]:
        with session_scope(self._session_factory) as session:
            rows = session.scalars(select(Tenant).order_by(Tenant.name)).all()
            return [_tenant_public(session, row) for row in rows]

    def create_tenant(self, body: CreateTenantRequest) -> TenantPublic:
        """Create a tenant with its console and a starter policy on the PDP.

        The policy is written first: a tenant the PDP has no policy for would
        have every login degraded to a step-up.
        """
        with session_scope(self._session_factory) as session:
            if session.get(Tenant, body.tenant_id) is not None:
                raise HTTPException(status_code=409, detail="tenant_id already exists")
            for domain in body.operator_domains:
                if session.get(TenantDomain, domain) is not None:
                    raise HTTPException(
                        status_code=409, detail=f"domain already registered: {domain}"
                    )
        try:
            self._policy.put_policy(starter_policy(body.tenant_id))
        except (ControlPlaneUnavailable, PolicyRejected) as exc:
            raise HTTPException(status_code=503, detail="PDP unavailable") from exc
        branding = body.branding or TenantBranding(display_name=body.name)
        with session_scope(self._session_factory) as session:
            row = Tenant(
                tenant_id=body.tenant_id,
                name=body.name,
                is_platform=False,
                display_name=branding.display_name,
                login_style=branding.login_style,
                logo_url=branding.logo_url,
                primary_colour=branding.primary_colour,
                accent_colour=branding.accent_colour,
                created_at=datetime.now(timezone.utc),
            )
            session.add(row)
            try:
                session.flush()
                _set_domains(session, row.tenant_id, body.operator_domains)
                bootstrap_console(session, row)
                session.flush()
            except IntegrityError as exc:
                raise HTTPException(status_code=409, detail="tenant already exists") from exc
            session.refresh(row)
            return _tenant_public(session, row)

    def patch_tenant(self, tenant_id: str, body: PatchTenantRequest) -> TenantPublic:
        with session_scope(self._session_factory) as session:
            row = _require_tenant(session, tenant_id)
            if body.name is not None:
                row.name = body.name
            if body.operator_domains is not None:
                _set_domains(session, tenant_id, body.operator_domains)
            if body.branding is not None:
                row.display_name = body.branding.display_name
                row.login_style = body.branding.login_style
                row.logo_url = body.branding.logo_url
                row.primary_colour = body.branding.primary_colour
                row.accent_colour = body.branding.accent_colour
            session.flush()
            session.refresh(row)
            return _tenant_public(session, row)

    # ---------------------------------------------------------------- users

    def list_users(self, op: Operator) -> list[AdminUserPublic]:
        with session_scope(self._session_factory) as session:
            rows = session.scalars(
                select(User).where(User.tenant_id == op.tenant_id).order_by(User.email)
            ).all()
            return [_user_public(row) for row in rows]

    def create_user(self, op: Operator, body: CreateUserRequest) -> AdminUserPublic:
        email = body.email.strip().lower()
        user_id = f"usr_{uuid4().hex[:12]}"
        with session_scope(self._session_factory) as session:
            tenant = _require_tenant(session, op.tenant_id)
            clash = session.scalar(
                select(User).where(User.tenant_id == op.tenant_id, User.email == email)
            )
            if clash is not None:
                raise HTTPException(status_code=409, detail="email already exists")
            row = User(
                user_id=user_id,
                tenant_id=op.tenant_id,
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
            _sync_admin_flag(session, tenant, user_id, body.is_admin)
            session.flush()
            session.refresh(row)
            return _user_public(row)

    def patch_user(self, op: Operator, user_id: str, body: PatchUserRequest) -> AdminUserPublic:
        with session_scope(self._session_factory) as session:
            row = _require_user(session, op.tenant_id, user_id)
            if body.enabled is not None:
                row.enabled = body.enabled
            if body.is_admin is not None:
                row.is_admin = body.is_admin
                _sync_admin_flag(
                    session, _require_tenant(session, op.tenant_id), user_id, body.is_admin
                )
            if body.password is not None:
                row.password_hash = hash_password(body.password)
            session.flush()
            session.refresh(row)
            return _user_public(row)

    # ---------------------------------------------------------------- applications

    def list_applications(self, op: Operator) -> list[ApplicationPublic]:
        with session_scope(self._session_factory) as session:
            rows = session.scalars(
                select(Application)
                .where(Application.tenant_id == op.tenant_id)
                .order_by(Application.application_id)
            ).all()
            return [_app_public(row) for row in rows]

    def create_application(
        self, op: Operator, body: CreateApplicationRequest
    ) -> ApplicationPublic:
        with session_scope(self._session_factory) as session:
            # Client ids are platform-wide (they route a login to its tenant),
            # so a clash with another tenant's id is still a clash.
            if session.get(Application, body.application_id) is not None:
                raise HTTPException(status_code=409, detail="application_id already exists")
            row = Application(
                application_id=body.application_id,
                tenant_id=op.tenant_id,
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
        self, op: Operator, application_id: str, body: PatchApplicationRequest
    ) -> ApplicationPublic:
        with session_scope(self._session_factory) as session:
            row = _require_application(session, op.tenant_id, application_id)
            tenant = _require_tenant(session, op.tenant_id)
            if body.enabled is False and application_id == tenant.console_application_id:
                # Disabling the console would lock every operator out, with no
                # way back in through the console itself.
                raise HTTPException(status_code=409, detail="the console cannot be disabled")
            if body.name is not None:
                row.name = body.name
            if body.enabled is not None:
                row.enabled = body.enabled
            if body.redirect_uri is not None:
                row.redirect_uri = body.redirect_uri or None
            session.flush()
            session.refresh(row)
            return _app_public(row)

    # ---------------------------------------------------------------- groups

    def list_groups(self, op: Operator) -> list[GroupPublic]:
        with session_scope(self._session_factory) as session:
            rows = session.scalars(
                select(Group).where(Group.tenant_id == op.tenant_id).order_by(Group.name)
            ).all()
            counts = _member_counts(session, [row.group_id for row in rows])
            return [
                GroupPublic(
                    tenant_id=row.tenant_id,
                    group_id=row.group_id,
                    name=row.name,
                    description=row.description,
                    member_count=counts.get(row.group_id, 0),
                    created_at=_as_utc(row.created_at),
                )
                for row in rows
            ]

    def get_group(self, op: Operator, group_id: str) -> GroupDetail:
        with session_scope(self._session_factory) as session:
            return _group_detail(session, _require_group(session, op.tenant_id, group_id))

    def create_group(self, op: Operator, body: CreateGroupRequest) -> GroupDetail:
        group_id = body.group_id or f"grp_{uuid4().hex[:12]}"
        with session_scope(self._session_factory) as session:
            if session.get(Group, group_id) is not None:
                raise HTTPException(status_code=409, detail="group_id already exists")
            existing_name = session.scalar(
                select(Group).where(Group.tenant_id == op.tenant_id, Group.name == body.name)
            )
            if existing_name is not None:
                raise HTTPException(status_code=409, detail="group name already exists")
            row = Group(
                group_id=group_id,
                tenant_id=op.tenant_id,
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

    def patch_group(self, op: Operator, group_id: str, body: PatchGroupRequest) -> GroupDetail:
        with session_scope(self._session_factory) as session:
            row = _require_group(session, op.tenant_id, group_id)
            if body.name is not None:
                clash = session.scalar(
                    select(Group).where(
                        Group.tenant_id == op.tenant_id,
                        Group.name == body.name,
                        Group.group_id != group_id,
                    )
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

    def delete_group(self, op: Operator, group_id: str) -> None:
        with session_scope(self._session_factory) as session:
            _require_group(session, op.tenant_id, group_id)
            if group_id == _require_tenant(session, op.tenant_id).admin_group_id:
                raise HTTPException(status_code=409, detail="the admin group cannot be deleted")
            session.execute(
                delete(GroupMembership).where(GroupMembership.group_id == group_id)
            )
            session.execute(delete(GroupRole).where(GroupRole.group_id == group_id))
            session.execute(delete(Group).where(Group.group_id == group_id))

    def add_member(
        self, op: Operator, group_id: str, body: AddGroupMemberRequest
    ) -> GroupDetail:
        with session_scope(self._session_factory) as session:
            row = _require_group(session, op.tenant_id, group_id)
            _require_user(session, op.tenant_id, body.user_id)
            if session.get(GroupMembership, (group_id, body.user_id)) is not None:
                raise HTTPException(status_code=409, detail="user is already a member")
            session.add(GroupMembership(group_id=group_id, user_id=body.user_id))
            session.flush()
            return _group_detail(session, row)

    def remove_member(self, op: Operator, group_id: str, user_id: str) -> GroupDetail:
        with session_scope(self._session_factory) as session:
            row = _require_group(session, op.tenant_id, group_id)
            membership = session.get(GroupMembership, (group_id, user_id))
            if membership is None:
                raise HTTPException(status_code=404, detail="unknown membership")
            session.delete(membership)
            session.flush()
            return _group_detail(session, row)

    def add_group_role(
        self, op: Operator, group_id: str, body: AddGroupRoleRequest
    ) -> GroupDetail:
        """Assign a role to a group. This is also what grants sign-in to the
        role's application — there is no separate access grant (ADR-0029)."""
        with session_scope(self._session_factory) as session:
            row = _require_group(session, op.tenant_id, group_id)
            _require_role(session, op.tenant_id, body.role_id)
            if session.get(GroupRole, (group_id, body.role_id)) is not None:
                raise HTTPException(status_code=409, detail="role already assigned")
            session.add(GroupRole(group_id=group_id, role_id=body.role_id))
            session.flush()
            return _group_detail(session, row)

    def remove_group_role(self, op: Operator, group_id: str, role_id: str) -> GroupDetail:
        with session_scope(self._session_factory) as session:
            row = _require_group(session, op.tenant_id, group_id)
            assignment = session.get(GroupRole, (group_id, role_id))
            if assignment is None:
                raise HTTPException(status_code=404, detail="unknown role assignment")
            session.delete(assignment)
            session.flush()
            return _group_detail(session, row)

    # ---------------------------------------------------------------- roles

    def list_roles(self, op: Operator, application_id: str | None = None) -> list[RolePublic]:
        with session_scope(self._session_factory) as session:
            stmt = (
                select(Role)
                .where(Role.tenant_id == op.tenant_id)
                .order_by(Role.application_id, Role.name)
            )
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
                    tenant_id=row.tenant_id,
                    role_id=row.role_id,
                    application_id=row.application_id,
                    name=row.name,
                    description=row.description,
                    permission_count=counts.get(row.role_id, 0),
                    created_at=_as_utc(row.created_at),
                )
                for row in rows
            ]

    def get_role(self, op: Operator, role_id: str) -> RoleDetail:
        with session_scope(self._session_factory) as session:
            return _role_detail(session, _require_role(session, op.tenant_id, role_id))

    def create_role(self, op: Operator, body: CreateRoleRequest) -> RoleDetail:
        role_id = body.role_id or f"role_{uuid4().hex[:12]}"
        with session_scope(self._session_factory) as session:
            _require_application(session, op.tenant_id, body.application_id)
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
                tenant_id=op.tenant_id,
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

    def patch_role(self, op: Operator, role_id: str, body: PatchRoleRequest) -> RoleDetail:
        with session_scope(self._session_factory) as session:
            row = _require_role(session, op.tenant_id, role_id)
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

    def delete_role(self, op: Operator, role_id: str) -> None:
        with session_scope(self._session_factory) as session:
            _require_role(session, op.tenant_id, role_id)
            session.execute(
                delete(RolePermission).where(RolePermission.role_id == role_id)
            )
            session.execute(delete(GroupRole).where(GroupRole.role_id == role_id))
            session.execute(delete(Role).where(Role.role_id == role_id))

    def set_role_permissions(
        self, op: Operator, role_id: str, body: SetRolePermissionsRequest
    ) -> RoleDetail:
        """Replace the role's permission set.

        Wholesale replacement rather than add/remove: an operator editing a role
        in the console is answering "what may this role do", and a PUT of the
        whole answer cannot leave a stale permission behind.
        """
        wanted = set(body.permission_ids)
        with session_scope(self._session_factory) as session:
            row = _require_role(session, op.tenant_id, role_id)
            if wanted:
                found = session.scalars(
                    select(Permission).where(Permission.permission_id.in_(wanted))
                ).all()
                by_id = {item.permission_id: item for item in found}
                # Another tenant's permission is reported as unknown, never as
                # "belongs to a different application" — that would confirm it exists.
                own_apps = set(
                    session.scalars(
                        select(Application.application_id).where(
                            Application.tenant_id == op.tenant_id
                        )
                    ).all()
                )
                by_id = {pid: p for pid, p in by_id.items() if p.application_id in own_apps}
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
                    # application's permissions.
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

    # ---------------------------------------------------------------- permissions

    def list_permissions(
        self, op: Operator, application_id: str | None = None
    ) -> list[PermissionPublic]:
        with session_scope(self._session_factory) as session:
            stmt = (
                select(Permission)
                .join(Application, Application.application_id == Permission.application_id)
                .where(Application.tenant_id == op.tenant_id)
                .order_by(Permission.application_id, Permission.resource, Permission.operation)
            )
            if application_id is not None:
                stmt = stmt.where(Permission.application_id == application_id)
            return [_permission_public(row) for row in session.scalars(stmt).all()]

    def create_permission(
        self, op: Operator, body: CreatePermissionRequest
    ) -> PermissionPublic:
        permission_id = (
            f"perm_{body.application_id}_{body.resource}_{body.operation}"
        ).replace("-", "_")
        with session_scope(self._session_factory) as session:
            _require_application(session, op.tenant_id, body.application_id)
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

    # ---------------------------------------------------------------- decisions

    def list_decisions(
        self,
        op: Operator,
        *,
        user_id: str | None = None,
        application_id: str | None = None,
        action: Action | None = None,
        limit: int = 50,
    ) -> DecisionListResponse:
        try:
            return self._audit.list_decisions(
                tenant_id=op.tenant_id,
                user_id=user_id,
                application_id=application_id,
                action=action,
                limit=limit,
            )
        except ControlPlaneUnavailable as exc:
            raise HTTPException(status_code=503, detail="decision store unavailable") from exc

    def get_decision(self, op: Operator, event_id) -> DecisionRecord:
        try:
            return self._audit.get_decision(op.tenant_id, event_id)
        except AuditNotFound as exc:
            raise HTTPException(status_code=404, detail="unknown event") from exc
        except ControlPlaneUnavailable as exc:
            raise HTTPException(status_code=503, detail="decision store unavailable") from exc

    # ---------------------------------------------------------------- policy

    def get_policy(self, op: Operator) -> TenantPolicy:
        try:
            return self._policy.get_policy(op.tenant_id)
        except PolicyNotFound as exc:
            raise HTTPException(status_code=404, detail="no policy for this tenant") from exc
        except ControlPlaneUnavailable as exc:
            raise HTTPException(status_code=503, detail="PDP unavailable") from exc

    def put_policy(self, op: Operator, body: TenantPolicy) -> TenantPolicy:
        if body.tenant_id != op.tenant_id:
            # The tenant is the operator's, never the body's (ADR-0033).
            raise HTTPException(status_code=422, detail="tenant_id differs from the console's tenant")
        try:
            saved = self._policy.put_policy(body)
        except PolicyRejected as exc:
            raise HTTPException(status_code=422, detail=exc.detail) from exc
        except ControlPlaneUnavailable as exc:
            raise HTTPException(status_code=503, detail="PDP unavailable") from exc
        self._policy_cache.invalidate(op.tenant_id)
        return saved


# Re-exported for main.py's route table.
__all__ = [
    "ADMIN_READ",
    "ADMIN_WRITE",
    "AdminService",
    "DECISIONS_READ",
    "Operator",
    "POLICY_WRITE",
    "TENANT_HEADER",
    "TENANTS_READ",
    "TENANTS_WRITE",
]
