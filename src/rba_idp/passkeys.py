"""Carry enrolled passkeys across a cloud teardown.

`make aws-down` destroys the database, but not the passkeys on people's devices:
those are bound to the WebAuthn RP ID, the IdP's CloudFront host, which lives in
the permanent stack. What is lost is only the server's copy of each public key.
`aws-down` exports it and `aws-up` imports it after the users are seeded again,
so nobody has to enroll after every session:

    kubectl exec deploy/idp -c idp -- python -m rba_idp.passkeys export > passkeys.json
    kubectl exec -i deploy/idp -c idp -- python -m rba_idp.passkeys import < passkeys.json

The export holds credential ids, user ids, public keys and signature counters:
nothing that signs in by itself. A credential whose user no longer exists is
skipped; one already present keeps the higher counter.
"""

from __future__ import annotations

import argparse
import base64
import json
import sys

from sqlalchemy import select

from rba_idp.config import get_settings
from rba_idp.db.models import User, WebAuthnCredential
from rba_idp.db.session import make_engine, make_session_factory, session_scope


def export_passkeys(factory) -> list[dict]:
    with session_scope(factory) as session:
        rows = session.scalars(select(WebAuthnCredential).order_by(WebAuthnCredential.created_at))
        return [
            {
                "credential_id": row.credential_id,
                "user_id": row.user_id,
                "public_key": base64.b64encode(row.public_key).decode(),
                "sign_count": row.sign_count,
            }
            for row in rows
        ]


def import_passkeys(factory, items: list[dict]) -> dict[str, int]:
    added = updated = skipped = 0
    with session_scope(factory) as session:
        users = set(session.scalars(select(User.user_id)))
        for item in items:
            if item["user_id"] not in users:
                skipped += 1
                continue
            row = session.get(WebAuthnCredential, item["credential_id"])
            if row is None:
                session.add(
                    WebAuthnCredential(
                        credential_id=item["credential_id"],
                        user_id=item["user_id"],
                        public_key=base64.b64decode(item["public_key"]),
                        sign_count=int(item["sign_count"]),
                    )
                )
                added += 1
            elif int(item["sign_count"]) > row.sign_count:
                row.sign_count = int(item["sign_count"])
                updated += 1
    return {"added": added, "updated": updated, "skipped": skipped}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m rba_idp.passkeys", description=__doc__.split("\n")[0])
    parser.add_argument("action", choices=["export", "import"])
    args = parser.parse_args(argv)
    settings = get_settings()
    factory = make_session_factory(make_engine(settings.database_url, memory=settings.use_memory_db))
    if args.action == "export":
        json.dump(export_passkeys(factory), sys.stdout)
    else:
        result = import_passkeys(factory, json.load(sys.stdin))
        print(f"passkeys: {result['added']} added, {result['updated']} updated, {result['skipped']} skipped", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
