"""C-4: schema + seed run once, outside the serving pods."""

from __future__ import annotations

from sqlalchemy import func, select

from rba_idp.db.models import Tenant, User
from rba_idp.db.session import make_engine, make_session_factory
from rba_idp.init import initialise
from tests.helpers import LOGIN, StubPdp, client_for
from tests.helpers import test_settings as make_settings


def test_init_is_idempotent() -> None:
    settings = make_settings()
    engine = make_engine("", memory=True)
    initialise(settings, engine)
    initialise(settings, engine)  # a re-run Job, or a second upgrade
    with make_session_factory(engine)() as session:
        assert session.scalar(select(func.count()).select_from(Tenant)) == 3
        assert session.scalar(select(func.count()).select_from(User)) == 8


def test_with_init_off_the_server_does_not_create_the_schema() -> None:
    """The serving pod leaves schema work to the Job; on an empty database it
    fails loudly instead of racing its siblings."""
    with client_for(StubPdp(), settings=make_settings(init_on_startup=False)) as client:
        assert client.post("/login", json=LOGIN).status_code == 500


def test_a_kept_database_gets_new_nullable_columns() -> None:
    """k3d keeps its database across deploys; a new optional column is added
    in place instead of asking for a reset."""
    from sqlalchemy import inspect, text

    from rba_idp.db.session import create_tables

    engine = make_engine("", memory=True)
    create_tables(engine)
    with engine.begin() as conn:
        conn.execute(text("ALTER TABLE users DROP COLUMN last_login_at"))
    create_tables(engine)
    assert "last_login_at" in {c["name"] for c in inspect(engine).get_columns("users")}
