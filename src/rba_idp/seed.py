"""Idempotent demo user + registered application (contract examples)."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from rba_idp.config import Settings
from rba_idp.db.models import Application, User
from rba_idp.passwords import hash_password


def seed_identity(session: Session, settings: Settings) -> None:
    app_id = settings.seed_application_id
    if session.get(Application, app_id) is None:
        session.add(
            Application(
                application_id=app_id,
                name=settings.seed_application_name,
                enabled=True,
            )
        )

    email = settings.seed_email.strip().lower()
    exists = session.scalar(select(User).where(User.email == email))
    if exists is None:
        session.add(
            User(
                user_id=settings.seed_user_id,
                email=email,
                password_hash=hash_password(settings.seed_password),
                enabled=True,
            )
        )
    session.commit()
