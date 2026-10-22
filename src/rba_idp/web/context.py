"""Request-derived signals for the hosted login page."""

from __future__ import annotations

from fastapi import Request

from rba_idp.db.models import Application, Tenant
from rba_idp.db.session import session_scope
from rba_idp.geo import resolve_login_signals, scored_ip


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
    application_id: str | None,
    *,
    console: bool = False,
) -> dict:
    """JSON blob the login page uses to call POST /login or POST /console/login.

    An app login names its application, which names its tenant; the page shows
    that tenant's name. The console login names nothing (ADR-0033): which
    tenant the operator belongs to is decided by the server from the email.
    """
    app_id = (application_id or "").strip()
    name: str | None = None
    tenant_name: str | None = None
    unknown = not console
    registered: str | None = None
    if not console and app_id:
        factory = request.app.state.session_factory
        with session_scope(factory) as session:
            row = session.get(Application, app_id)
            if row is not None and row.enabled:
                tenant = session.get(Tenant, row.tenant_id)
                name = row.name
                tenant_name = tenant.display_name if tenant is not None else None
                unknown = False
                registered = row.redirect_uri
    ip = scored_ip(client_ip(request))
    signals = resolve_login_signals(
        ip,
        country=request.query_params.get("country"),
        asn=request.query_params.get("asn"),
    )
    requested = request.query_params.get("redirect_uri")
    if registered and (not requested or requested == registered):
        redirect_uri = registered
    else:
        redirect_uri = None
    next_path = _safe_next(request.query_params.get("next"))
    return {
        "console": console,
        "application_id": None if console else app_id,
        "application_name": "Consola RokuSec" if console else name,
        "tenant_name": tenant_name,
        "unknown_application": unknown,
        "ip_address": ip,
        "country": signals.country,
        "asn": signals.asn,
        "next": next_path or ("/admin" if console else None),
        "redirect_uri": redirect_uri,
    }


def _safe_next(value: str | None) -> str | None:
    if value and value.startswith("/admin"):
        return value
    return None
