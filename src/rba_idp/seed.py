"""Idempotent demo user, admin user, and registered applications."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from rba_idp.config import Settings
from rba_idp.db.models import Application, User
from rba_idp.passwords import hash_password


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
    session.commit()
