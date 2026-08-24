"""Idempotent seed: applications, permissions, roles, groups, users (ADR-0029).

The seed is the worked example of the RBAC chain, and it is deliberately built
around the four actors the thesis defines in §3.2.1:

| Actor              | User                   | Group             | Role               |
|--------------------|------------------------|-------------------|--------------------|
| usuario final      | `demo@example.com`     | Banking customers | `customer`         |
| usuario final      | `viewer@example.com`   | Banking viewers   | `viewer`           |
| operador de soporte| `support@example.com`  | Support operators | `support-operator` |
| administrador      | `admin@example.com`    | Platform admins   | `platform-admin`   |

The two bank users matter most on stage: identical login, identical risk
handling, and one of them gets 403 on a transfer. That is RF-21 — authorization
over *operations*, not just sign-in — visible in ten seconds.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from rba_idp.config import Settings
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
from rba_idp.passwords import hash_password

SEED_BANKING_GROUP_ID = "grp_banking"
SEED_VIEWERS_GROUP_ID = "grp_bank_viewers"
SEED_OPERATORS_GROUP_ID = "grp_operators"
SEED_SUPPORT_GROUP_ID = "grp_support"

ROLE_CUSTOMER = "role_bank_customer"
ROLE_VIEWER = "role_bank_viewer"
ROLE_PLATFORM_ADMIN = "role_platform_admin"
ROLE_SUPPORT_OPERATOR = "role_support_operator"

# (resource, operation, description) per application. Kept small on purpose: a
# permission nobody checks is decoration.
BANK_PERMISSIONS: tuple[tuple[str, str, str], ...] = (
    ("account", "read", "See balances and account details"),
    ("transaction", "read", "See the transaction history"),
    ("transfer", "create", "Move money out of an account"),
)

ADMIN_PERMISSIONS: tuple[tuple[str, str, str], ...] = (
    ("admin", "read", "Open the admin console and read the directory"),
    ("admin", "write", "Create and modify users, groups, roles and applications"),
    ("decisions", "read", "Read scored logins and their per-signal reasons"),
    ("policy", "write", "Change risk thresholds, actions and monitor mode"),
)


def _permission_id(application_id: str, resource: str, operation: str) -> str:
    return f"perm_{application_id}_{resource}_{operation}".replace("-", "_")


def _ensure_application(
    session: Session,
    application_id: str,
    name: str,
    *,
    redirect_uri: str | None = None,
) -> None:
    row = session.get(Application, application_id)
    if row is None:
        session.add(
            Application(
                application_id=application_id,
                name=name,
                enabled=True,
                redirect_uri=redirect_uri,
            )
        )
        return
    if redirect_uri is not None:
        row.redirect_uri = redirect_uri


def _ensure_user(
    session: Session,
    *,
    user_id: str,
    email: str,
    password: str,
    is_admin: bool,
) -> None:
    email = email.strip().lower()
    exists = session.scalar(select(User).where(User.email == email))
    if exists is None:
        session.add(
            User(
                user_id=user_id,
                email=email,
                password_hash=hash_password(password),
                enabled=True,
                is_admin=is_admin,
            )
        )
        return
    if exists.user_id == user_id:
        exists.is_admin = is_admin


def _ensure_group(session: Session, group_id: str, name: str, description: str) -> None:
    if session.get(Group, group_id) is None:
        session.add(Group(group_id=group_id, name=name, description=description))


def _ensure_membership(session: Session, group_id: str, user_id: str) -> None:
    if session.get(GroupMembership, (group_id, user_id)) is None:
        session.add(GroupMembership(group_id=group_id, user_id=user_id))


def _ensure_permissions(
    session: Session,
    application_id: str,
    rows: tuple[tuple[str, str, str], ...],
) -> None:
    for resource, operation, description in rows:
        permission_id = _permission_id(application_id, resource, operation)
        if session.get(Permission, permission_id) is None:
            session.add(
                Permission(
                    permission_id=permission_id,
                    application_id=application_id,
                    resource=resource,
                    operation=operation,
                    description=description,
                )
            )


def _ensure_role(
    session: Session,
    role_id: str,
    application_id: str,
    name: str,
    description: str,
) -> None:
    if session.get(Role, role_id) is None:
        session.add(
            Role(
                role_id=role_id,
                application_id=application_id,
                name=name,
                description=description,
            )
        )


def _ensure_role_permissions(
    session: Session,
    role_id: str,
    application_id: str,
    scopes: tuple[tuple[str, str], ...],
) -> None:
    for resource, operation in scopes:
        permission_id = _permission_id(application_id, resource, operation)
        if session.get(RolePermission, (role_id, permission_id)) is None:
            session.add(
                RolePermission(role_id=role_id, permission_id=permission_id)
            )


def _ensure_group_role(session: Session, group_id: str, role_id: str) -> None:
    if session.get(GroupRole, (group_id, role_id)) is None:
        session.add(GroupRole(group_id=group_id, role_id=role_id))


def seed_identity(session: Session, settings: Settings) -> None:
    bank = settings.seed_application_id
    console = settings.seed_admin_application_id

    # --- applications
    _ensure_application(
        session,
        bank,
        settings.seed_application_name,
        redirect_uri=settings.seed_application_redirect_uri or None,
    )
    _ensure_application(session, console, settings.seed_admin_application_name)

    # --- permissions (must exist before roles reference them)
    _ensure_permissions(session, bank, BANK_PERMISSIONS)
    _ensure_permissions(session, console, ADMIN_PERMISSIONS)
    session.flush()

    # --- roles
    _ensure_role(
        session,
        ROLE_CUSTOMER,
        bank,
        "customer",
        "Full retail banking: view accounts and move money",
    )
    _ensure_role(
        session,
        ROLE_VIEWER,
        bank,
        "viewer",
        "Read-only banking: may see balances, may not transfer",
    )
    _ensure_role(
        session,
        ROLE_PLATFORM_ADMIN,
        console,
        "platform-admin",
        "Operate the platform: identity, applications, roles and risk policy",
    )
    _ensure_role(
        session,
        ROLE_SUPPORT_OPERATOR,
        console,
        "support-operator",
        "Explain a login: read decisions and reasons, change nothing",
    )
    session.flush()

    _ensure_role_permissions(
        session,
        ROLE_CUSTOMER,
        bank,
        (("account", "read"), ("transaction", "read"), ("transfer", "create")),
    )
    # The whole point of the viewer: same app, one permission short.
    _ensure_role_permissions(
        session,
        ROLE_VIEWER,
        bank,
        (("account", "read"), ("transaction", "read")),
    )
    _ensure_role_permissions(
        session,
        ROLE_PLATFORM_ADMIN,
        console,
        (
            ("admin", "read"),
            ("admin", "write"),
            ("decisions", "read"),
            ("policy", "write"),
        ),
    )
    # Read a decision, read the directory to identify the user — nothing else.
    _ensure_role_permissions(
        session,
        ROLE_SUPPORT_OPERATOR,
        console,
        (("admin", "read"), ("decisions", "read")),
    )

    # --- users
    _ensure_user(
        session,
        user_id=settings.seed_user_id,
        email=settings.seed_email,
        password=settings.seed_password,
        is_admin=False,
    )
    _ensure_user(
        session,
        user_id=settings.seed_viewer_user_id,
        email=settings.seed_viewer_email,
        password=settings.seed_viewer_password,
        is_admin=False,
    )
    _ensure_user(
        session,
        user_id=settings.seed_operator_user_id,
        email=settings.seed_operator_email,
        password=settings.seed_operator_password,
        is_admin=False,
    )
    _ensure_user(
        session,
        user_id=settings.seed_admin_user_id,
        email=settings.seed_admin_email,
        password=settings.seed_admin_password,
        is_admin=True,
    )

    # --- groups
    _ensure_group(
        session,
        SEED_BANKING_GROUP_ID,
        "Banking customers",
        "Retail customers of the demo bank",
    )
    _ensure_group(
        session,
        SEED_VIEWERS_GROUP_ID,
        "Banking viewers",
        "Read-only access to the demo bank",
    )
    _ensure_group(
        session,
        SEED_SUPPORT_GROUP_ID,
        "Support operators",
        "May explain a login decision; may not change anything",
    )
    _ensure_group(
        session,
        SEED_OPERATORS_GROUP_ID,
        "Platform admins",
        "Full control of the platform and the demo bank",
    )
    session.flush()

    _ensure_membership(session, SEED_BANKING_GROUP_ID, settings.seed_user_id)
    _ensure_membership(session, SEED_VIEWERS_GROUP_ID, settings.seed_viewer_user_id)
    _ensure_membership(session, SEED_SUPPORT_GROUP_ID, settings.seed_operator_user_id)
    _ensure_membership(session, SEED_OPERATORS_GROUP_ID, settings.seed_admin_user_id)

    # --- role assignments
    _ensure_group_role(session, SEED_BANKING_GROUP_ID, ROLE_CUSTOMER)
    _ensure_group_role(session, SEED_VIEWERS_GROUP_ID, ROLE_VIEWER)
    _ensure_group_role(session, SEED_SUPPORT_GROUP_ID, ROLE_SUPPORT_OPERATOR)
    _ensure_group_role(session, SEED_OPERATORS_GROUP_ID, ROLE_PLATFORM_ADMIN)
    # Admins also bank, so the walkthrough can be driven from one account.
    _ensure_group_role(session, SEED_OPERATORS_GROUP_ID, ROLE_CUSTOMER)

    session.commit()
