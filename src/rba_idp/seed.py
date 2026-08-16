"""Idempotent demo user, admin user, registered applications, and groups."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from rba_idp.config import Settings
from rba_idp.db.models import Application, Group, GroupAppGrant, GroupMembership, User
from rba_idp.passwords import hash_password

SEED_BANKING_GROUP_ID = "grp_banking"
SEED_OPERATORS_GROUP_ID = "grp_operators"


def _ensure_application(session: Session, application_id: str, name: str) -> None:
    if session.get(Application, application_id) is None:
        session.add(
            Application(
                application_id=application_id,
                name=name,
                enabled=True,
            )
        )


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


def _ensure_group(
    session: Session, group_id: str, name: str, description: str
) -> None:
    if session.get(Group, group_id) is None:
        session.add(
            Group(group_id=group_id, name=name, description=description)
        )


def _ensure_membership(session: Session, group_id: str, user_id: str) -> None:
    if session.get(GroupMembership, (group_id, user_id)) is None:
        session.add(GroupMembership(group_id=group_id, user_id=user_id))


def _ensure_grant(
    session: Session, group_id: str, application_id: str, permission: str = "access"
) -> None:
    key = (group_id, application_id, permission)
    if session.get(GroupAppGrant, key) is None:
        session.add(
            GroupAppGrant(
                group_id=group_id,
                application_id=application_id,
                permission=permission,
            )
        )


def seed_identity(session: Session, settings: Settings) -> None:
    _ensure_application(
        session, settings.seed_application_id, settings.seed_application_name
    )
    _ensure_application(
        session,
        settings.seed_admin_application_id,
        settings.seed_admin_application_name,
    )
    _ensure_user(
        session,
        user_id=settings.seed_user_id,
        email=settings.seed_email,
        password=settings.seed_password,
        is_admin=False,
    )
    _ensure_user(
        session,
        user_id=settings.seed_admin_user_id,
        email=settings.seed_admin_email,
        password=settings.seed_admin_password,
        is_admin=True,
    )
    _ensure_group(
        session,
        SEED_BANKING_GROUP_ID,
        "Banking users",
        "May sign in to the demo banking app",
    )
    _ensure_group(
        session,
        SEED_OPERATORS_GROUP_ID,
        "Operators",
        "May sign in to the admin console and demo apps",
    )
    _ensure_membership(session, SEED_BANKING_GROUP_ID, settings.seed_user_id)
    _ensure_membership(session, SEED_OPERATORS_GROUP_ID, settings.seed_admin_user_id)
    _ensure_grant(
        session, SEED_BANKING_GROUP_ID, settings.seed_application_id
    )
    _ensure_grant(
        session, SEED_OPERATORS_GROUP_ID, settings.seed_admin_application_id
    )
    _ensure_grant(
        session, SEED_OPERATORS_GROUP_ID, settings.seed_application_id
    )
    session.commit()
