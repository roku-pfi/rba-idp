"""bcrypt helpers. Dummy hash keeps missing-user verifies on a similar path."""

from __future__ import annotations

import bcrypt

# Precomputed once per process so unknown-user /login still runs checkpw.
_DUMMY_HASH = bcrypt.hashpw(b"idp-2-dummy-not-a-real-password", bcrypt.gensalt()).decode("ascii")


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("ascii")


def verify_password(password: str, password_hash: str | None) -> bool:
    digest = password_hash if password_hash else _DUMMY_HASH
    try:
        return bcrypt.checkpw(password.encode("utf-8"), digest.encode("ascii"))
    except ValueError:
        return False
