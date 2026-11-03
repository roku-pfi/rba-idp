"""A browser's stable device identifier (RF-02, ADR-0047).

The IdP sets one long-lived random cookie on its own origin. The cookie never
leaves the browser and the IdP; the PDP and every store see only a hash salted
with the tenant, so one browser is a different device to each organization and
the stored id cannot be replayed as the cookie.
"""

from __future__ import annotations

import hashlib
import re
import secrets

from fastapi import Request, Response

from rba_idp.config import Settings

COOKIE = "rokusec_device"
# Browsers cap cookie lifetime near 400 days; the id is renewed on each login.
MAX_AGE_SECONDS = 400 * 24 * 3600
_VALID = re.compile(r"^[A-Za-z0-9_-]{32,64}$")


def device_cookie(request: Request, response: Response, settings: Settings) -> str:
    """The browser's device cookie, issued (or renewed) on this response."""
    raw = request.cookies.get(COOKIE)
    if raw is None or not _VALID.match(raw):
        raw = secrets.token_urlsafe(32)
    response.set_cookie(
        COOKIE,
        raw,
        max_age=MAX_AGE_SECONDS,
        httponly=True,
        samesite="lax",
        secure=settings.deployment == "cloud",
        path="/",
    )
    return raw


def device_id(tenant_id: str, raw: str | None) -> str | None:
    """What the PDP sees: sha256(tenant ':' cookie), 32 hex characters."""
    if not raw:
        return None
    return hashlib.sha256(f"{tenant_id}:{raw}".encode()).hexdigest()[:32]
