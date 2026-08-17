"""DB engine / session helpers."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from rba_idp.db.models import Base


def make_engine(url: str, *, echo: bool = False, memory: bool = False) -> Engine:
    if memory or url.startswith("sqlite"):
        return create_engine(
            "sqlite+pysqlite://",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
            echo=echo,
            future=True,
        )
    return create_engine(url, echo=echo, future=True)


def create_tables(engine: Engine) -> None:
    Base.metadata.create_all(engine)
    _ensure_is_admin_column(engine)
    _ensure_redirect_uri_column(engine)
    _ensure_webauthn_challenge_columns(engine)


def _ensure_is_admin_column(engine: Engine) -> None:
    """Additive IdP-6 column; create_all does not ALTER existing Postgres tables."""
    inspector = inspect(engine)
    if "users" not in inspector.get_table_names():
        return
    cols = {c["name"] for c in inspector.get_columns("users")}
    if "is_admin" in cols:
        return
    default = "FALSE" if engine.dialect.name == "postgresql" else "0"
    with engine.begin() as conn:
        conn.execute(
            text(f"ALTER TABLE users ADD COLUMN is_admin BOOLEAN NOT NULL DEFAULT {default}")
        )


def _ensure_redirect_uri_column(engine: Engine) -> None:
    """Additive Demo-2 column; create_all does not ALTER existing Postgres tables."""
    inspector = inspect(engine)
    if "applications" not in inspector.get_table_names():
        return
    cols = {c["name"] for c in inspector.get_columns("applications")}
    if "redirect_uri" in cols:
        return
    with engine.begin() as conn:
        conn.execute(text("ALTER TABLE applications ADD COLUMN redirect_uri VARCHAR(512)"))


def _ensure_webauthn_challenge_columns(engine: Engine) -> None:
    """Additive Demo-4 columns; create_all does not ALTER existing Postgres tables."""
    inspector = inspect(engine)
    if "mfa_challenges" not in inspector.get_table_names():
        return
    cols = {c["name"] for c in inspector.get_columns("mfa_challenges")}
    blob = "BYTEA" if engine.dialect.name == "postgresql" else "BLOB"
    with engine.begin() as conn:
        if "webauthn_challenge" not in cols:
            conn.execute(
                text(f"ALTER TABLE mfa_challenges ADD COLUMN webauthn_challenge {blob}")
            )
        if "webauthn_mode" not in cols:
            conn.execute(
                text("ALTER TABLE mfa_challenges ADD COLUMN webauthn_mode VARCHAR(16)")
            )


def make_session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, expire_on_commit=False, future=True)


@contextmanager
def session_scope(factory: sessionmaker[Session]) -> Iterator[Session]:
    session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
