"""Public client ids: what an application puts in login URLs.

The internal ``application_id`` ("roku-bank-web") names the application in
roles, permissions and decisions, and never changes. What a browser sees is a
separate, opaque ``client_id`` ("rk_Bk7mQ2xVn9PwR4tL"), as Auth0 and Okta do: it
says nothing about how a tenant names its apps, cannot be guessed from another
tenant's, and could be rotated without touching anything that refers to the app.
It is public, not a secret: the registered redirect_uri is what binds a login
to an application's callback.
"""

from __future__ import annotations

import secrets
import string

PREFIX = "rk_"
_ALPHABET = string.ascii_letters + string.digits

# The demo applications' ids are fixed so their configuration can name them.
SEEDED: dict[str, str] = {
    "roku-bank-web": "rk_Bk7mQ2xVn9PwR4tL",
    "kaze-portal": "rk_Kz3sH8dYc5JfW1qN",
}


def new_client_id() -> str:
    return PREFIX + "".join(secrets.choice(_ALPHABET) for _ in range(16))
