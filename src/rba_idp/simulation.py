"""Signed simulation tickets: the only way to override login signals in the cloud.

ADR-0032 keeps the presenter's country/ASN override for the one scene the cloud
cannot produce honestly (impossible travel). Taken from the request as is, the
same override would let anyone claim the victim's home country. So where client
signals are not trusted, an override must arrive inside a ticket: HMAC-SHA256
over the values and an expiry, minted by ``POST /simulation/ticket`` for a
caller holding ``SIMULATION_SECRET`` (the presenter panel, D-1). The decision is
recorded as ``simulated``.

Format: ``base64url(json payload) + "." + base64url(hmac)``.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from dataclasses import dataclass


@dataclass(frozen=True)
class SimulatedSignals:
    country: str | None
    asn: str | None


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _sign(secret: str, payload: str) -> str:
    return _b64(hmac.new(secret.encode(), payload.encode(), hashlib.sha256).digest())


def issue_ticket(
    secret: str, *, country: str | None, asn: str | None, ttl_seconds: int, now: float | None = None
) -> tuple[str, float]:
    expires = int((now if now is not None else time.time()) + ttl_seconds)
    payload = _b64(json.dumps({"c": country, "a": asn, "exp": expires}, separators=(",", ":")).encode())
    return f"{payload}.{_sign(secret, payload)}", float(expires)


def verify_ticket(secret: str, ticket: str | None, *, now: float | None = None) -> SimulatedSignals | None:
    """The ticket's signals, or ``None`` if absent, forged, malformed or expired."""
    if not secret or not ticket or "." not in ticket:
        return None
    payload, _, signature = ticket.partition(".")
    if not hmac.compare_digest(signature, _sign(secret, payload)):
        return None
    try:
        data = json.loads(_unb64(payload))
        expires = int(data["exp"])
    except (ValueError, KeyError, TypeError):
        return None
    if expires <= (now if now is not None else time.time()):
        return None
    return SimulatedSignals(country=data.get("c"), asn=data.get("a"))
