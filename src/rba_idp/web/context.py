"""Request-derived signals for the hosted login page."""

from __future__ import annotations

from fastapi import Request

from rba_idp.config import Settings
from rba_idp.db.models import Application
from rba_idp.db.session import session_scope
from rba_idp.geo import resolve_login_signals


def client_ip(request: Request) -> str:
    """First X-Forwarded-For hop, else the peer address."""
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        first = forwarded.split(",", 1)[0].strip()
        if first:
            return first
    if request.client and request.client.host:
        return request.client.host
    return "0.0.0.0"


def hosted_boot(
    request: Request,
    settings: Settings,
    application_id: str | None,
) -> dict:
    """JSON blob the login page uses to call POST /login."""
    app_id = (application_id or settings.seed_application_id).strip()
    name: str | None = None
    unknown = True
    factory = request.app.state.session_factory
    with session_scope(factory) as session:
        row = session.get(Application, app_id)
        if row is not None and row.enabled:
            name = row.name
            unknown = False
    ip = client_ip(request)
    signals = resolve_login_signals(
        ip,
        country=request.query_params.get("country"),
        asn=request.query_params.get("asn"),
    )
    return {
        "application_id": app_id,
        "application_name": name,
        "unknown_application": unknown,
        "ip_address": ip,
        "country": signals.country,
        "asn": signals.asn,
        "next": _safe_next(request.query_params.get("next")),
    }


def _safe_next(value: str | None) -> str | None:
    if value and value.startswith("/admin"):
        return value
    return None
