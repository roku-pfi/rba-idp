"""DB engine / session helpers."""

from __future__ import annotations

import threading
from collections.abc import Iterator
from contextlib import contextmanager, nullcontext

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


class SchemaPredatesTenancy(RuntimeError):
    """The database was created before ADR-0033 and has no ``tenant_id`` columns."""


def create_tables(engine: Engine) -> None:
    _refuse_pre_tenancy_schema(engine)
    Base.metadata.create_all(engine)
    _add_nullable_columns(engine)


def _add_nullable_columns(engine: Engine) -> None:
    """Add columns that are new and nullable to tables that already exist.

    The one schema change ``create_all`` cannot make and a kept database (k3d)
    still needs. Anything else, such as a NOT NULL column or a type change, is
    still "reset the database".
    """
    inspector = inspect(engine)
    existing = set(inspector.get_table_names())
    with engine.begin() as conn:
        for table in Base.metadata.sorted_tables:
            if table.name not in existing:
                continue
            have = {c["name"] for c in inspector.get_columns(table.name)}
            for column in table.columns:
                if column.name in have or not column.nullable:
                    continue
                kind = column.type.compile(dialect=engine.dialect)
                conn.execute(text(f'ALTER TABLE "{table.name}" ADD COLUMN "{column.name}" {kind}'))


def _refuse_pre_tenancy_schema(engine: Engine) -> None:
    """Fail loudly on a database created before tenancy.

    ``create_all`` never ALTERs an existing table, so an old ``users`` table
    would survive without ``tenant_id`` and every query would fail later, far
    from the cause. There are no migrations (ADR-0033): the cloud databases are
    created fresh on every ``up`` and local ones are reset.
    """
    inspector = inspect(engine)
    if "users" not in inspector.get_table_names():
        return
    cols = {c["name"] for c in inspector.get_columns("users")}
    if "tenant_id" not in cols:
        raise SchemaPredatesTenancy(
            "rba_idp database predates multi-tenancy (no users.tenant_id); "
            "drop it and start again (k3d-down.sh + k3d-up.sh)"
        )


def make_session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, expire_on_commit=False, future=True)


# The in-memory database is one SQLite connection shared by every thread
# (StaticPool). Two requests using it at once interleave their transactions, so
# there, and only there, sessions take turns.
_MEMORY_LOCK = threading.RLock()


def _shares_one_connection(factory: sessionmaker[Session]) -> bool:
    bind = factory.kw.get("bind")
    return isinstance(getattr(bind, "pool", None), StaticPool)


@contextmanager
def session_scope(factory: sessionmaker[Session]) -> Iterator[Session]:
    with _MEMORY_LOCK if _shares_one_connection(factory) else nullcontext():
        session = factory()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()
