"""RBAC resolution: user → group → role → permission (ADR-0029).

One module owns the join, so "what may this user do here" is answered the same
way by the login path, by `GET /session`, and by the admin API's own guard. A
relying party never sees roles or groups — it receives the flattened
``{"account:read", "transfer:create"}`` set and tests membership.

Scoping rule: **every role belongs to exactly one application**, so every query
here takes an ``application_id``. Permissions never leak across applications.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from rba_idp.db.models import (
    GroupMembership,
    GroupRole,
    Permission,
    Role,
    RolePermission,
)

# Permissions on a tenant's console. Held by `tenant-admin`; `support` holds
# only the read pair, which is exactly the actor the thesis calls the
# "operador de soporte" (HU-10) — able to explain a decision, unable to change
# who can log in.
ADMIN_READ = ("admin", "read")
ADMIN_WRITE = ("admin", "write")
DECISIONS_READ = ("decisions", "read")
POLICY_WRITE = ("policy", "write")
# Platform operator only (ADR-0033). Effective only on the platform tenant's
# console: a tenant admin can name a permission `tenants:read` on their own
# console, and it still grants nothing.
TENANTS_READ = ("tenants", "read")
TENANTS_WRITE = ("tenants", "write")


def scope(resource: str, operation: str) -> str:
    """Wire form of a permission: ``("transfer", "create") → "transfer:create"``."""
    return f"{resource}:{operation}"


def effective_permissions(
    session: Session, user_id: str, application_id: str
) -> set[str]:
    """Every permission this user holds on this application, as scope strings.

    The union over all of the user's groups. Empty set means either "no roles
    here" or "roles with no permissions" — callers that need to tell those apart
    use `has_application_access`.
    """
    rows = session.execute(
        select(Permission.resource, Permission.operation)
        .join(RolePermission, RolePermission.permission_id == Permission.permission_id)
        .join(Role, Role.role_id == RolePermission.role_id)
        .join(GroupRole, GroupRole.role_id == Role.role_id)
        .join(GroupMembership, GroupMembership.group_id == GroupRole.group_id)
        .where(
            GroupMembership.user_id == user_id,
            Role.application_id == application_id,
            Permission.application_id == application_id,
        )
        .distinct()
    ).all()
    return {scope(resource, operation) for resource, operation in rows}


def has_application_access(
    session: Session, user_id: str, application_id: str
) -> bool:
    """True if the user holds **any** role on this application.

    Holding a role is what grants sign-in. There is no separate ``access``
    permission to forget to grant, and a role with an empty permission set is
    still a valid "may sign in, may do nothing else" assignment.
    """
    found = session.scalar(
        select(Role.role_id)
        .join(GroupRole, GroupRole.role_id == Role.role_id)
        .join(GroupMembership, GroupMembership.group_id == GroupRole.group_id)
        .where(
            GroupMembership.user_id == user_id,
            Role.application_id == application_id,
        )
        .limit(1)
    )
    return found is not None


def has_permission(
    session: Session, user_id: str, application_id: str, resource: str, operation: str
) -> bool:
    return scope(resource, operation) in effective_permissions(
        session, user_id, application_id
    )


def role_ids_for_user(
    session: Session, user_id: str, application_id: str | None = None
) -> set[str]:
    """Roles held through group membership. Used by the admin directory view."""
    stmt = (
        select(Role.role_id)
        .join(GroupRole, GroupRole.role_id == Role.role_id)
        .join(GroupMembership, GroupMembership.group_id == GroupRole.group_id)
        .where(GroupMembership.user_id == user_id)
    )
    if application_id is not None:
        stmt = stmt.where(Role.application_id == application_id)
    return set(session.scalars(stmt.distinct()).all())
