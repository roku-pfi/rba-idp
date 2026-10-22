"""Break-glass: issue an activation code from the command line (ADR-0037).

Every cloud session starts with empty databases, so nobody has a passkey — and
the platform tenant asks for one on every login. The first code therefore has
to come from someone with access to the cluster, not from the console:

    kubectl exec deploy/idp -- python -m rba_idp.activation juan@rokusec.example --tenant rokusec

From there the platform operator issues codes from the console. Uses the same
DATABASE_URL as the IdP.
"""

from __future__ import annotations

import argparse
import sys

from sqlalchemy import select

from rba_idp.config import get_settings
from rba_idp.db.models import User
from rba_idp.db.session import make_engine, make_session_factory, session_scope
from rba_idp.services.enrollment import issue_activation_code


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m rba_idp.activation", description=__doc__.split("\n")[0])
    parser.add_argument("email")
    parser.add_argument("--tenant", required=True, help="tenant_id, e.g. rokusec")
    args = parser.parse_args(argv)

    settings = get_settings()
    factory = make_session_factory(make_engine(settings.database_url, memory=settings.use_memory_db))
    with session_scope(factory) as session:
        user = session.scalar(
            select(User).where(
                User.tenant_id == args.tenant, User.email == args.email.strip().lower()
            )
        )
        if user is None or not user.enabled:
            print(f"no enabled user {args.email} in tenant {args.tenant}", file=sys.stderr)
            return 1
        issued = issue_activation_code(session, settings, user, issued_by="cli")
    print(f"{issued.code}  (user {issued.user_id}, valid until {issued.expires_at:%H:%M} UTC)")
    print("Enroll at /activate with this code and the user's password.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
