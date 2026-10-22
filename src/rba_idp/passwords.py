"""bcrypt helpers. Dummy hash keeps missing-user verifies on a similar path."""

from __future__ import annotations

import os

import bcrypt

# Cost factor. 12 (bcrypt's default) everywhere that matters; the test suite
# lowers it, since every app start hashes the whole seeded directory.
ROUNDS = int(os.environ.get("BCRYPT_ROUNDS", "12"))

# Precomputed once per process so unknown-user /login still runs checkpw — at
# the same cost as a real hash, or the timing would tell the two apart.
_DUMMY_HASH = bcrypt.hashpw(
    b"idp-2-dummy-not-a-real-password", bcrypt.gensalt(ROUNDS)
).decode("ascii")


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(ROUNDS)).decode("ascii")


def verify_password(password: str, password_hash: str | None) -> bool:
    digest = password_hash if password_hash else _DUMMY_HASH
    try:
        return bcrypt.checkpw(password.encode("utf-8"), digest.encode("ascii"))
    except ValueError:
        return False
