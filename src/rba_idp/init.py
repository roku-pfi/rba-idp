"""Create the schema and seed the directory, once (C-4).

    python -m rba_idp.init

Run as a Kubernetes Job before the IdP's replicas start (Helm `init.mode: job`),
so several pods never race to create tables or insert the same seed rows. Safe
to re-run: `create_all` and the seed are both idempotent. Locally the IdP still
does this at startup (`INIT_ON_STARTUP=true`).
"""

from __future__ import annotations

import logging

from rba_idp.config import Settings, get_settings
from rba_idp.db.session import create_tables, make_engine, make_session_factory
from rba_idp.seed import seed_identity

logger = logging.getLogger(__name__)


def initialise(settings: Settings, engine=None) -> None:
    engine = engine or make_engine(settings.database_url, memory=settings.use_memory_db)
    create_tables(engine)
    with make_session_factory(engine)() as session:
        seed_identity(session, settings)
    logger.info("rba_idp schema and seed are in place")


def main() -> int:
    logging.basicConfig(level=logging.INFO)
    initialise(get_settings())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
