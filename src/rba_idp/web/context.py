"""Request-derived signals for the hosted login page."""

from __future__ import annotations

import ipaddress

from fastapi import Request

from rba_idp.config import Settings
from rba_idp.db.models import Application, Tenant
from rba_idp.db.session import session_scope
from rba_idp.geo import resolve_login_signals, scored_ip
from rba_idp.simulation import verify_ticket


def _parse_ip(value: str) -> str | None:
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None


def _viewer_address(header: str) -> str | None:
    """``CloudFront-Viewer-Address``: ``"198.51.100.10:46532"`` or
    ``"2001:db8::1:46532"`` — the address, then ``:port``, IPv6 unbracketed."""
    host, sep, port = header.strip().rpartition(":")
    if not sep or not port.isdigit():
        return None
    return _parse_ip(host.strip("[]"))


def client_ip(request: Request, settings: Settings) -> str:
    """The client's address (ADR-0032).

    Headers are believed only when the direct peer is a trusted proxy — a
    client talking to the IdP directly can send any X-Forwarded-For it likes.
    Behind CloudFront the viewer address comes from CloudFront's own header
    (CloudFront overwrites it; the ALB only accepts CloudFront). Otherwise the
    right-most X-Forwarded-For hop that is not itself a trusted proxy.
    """
    peer = (request.client.host if request.client else None) or "0.0.0.0"
    proxies = settings.trusted_proxies()
    peer_ip = _parse_ip(peer)

    def trusted(ip: str | None) -> bool:
        return ip is not None and any(ipaddress.ip_address(ip) in net for net in proxies)

    if not trusted(peer_ip):
        return peer_ip or peer
    if settings.client_ip_header == "cloudfront-viewer-address":
        viewer = _viewer_address(request.headers.get("cloudfront-viewer-address", ""))
        return viewer or peer_ip
    hops = [
        hop
        for hop in (
            _parse_ip(part) for part in request.headers.get("x-forwarded-for", "").split(",")
        )
        if hop is not None
    ]
    for hop in reversed(hops):
        if not trusted(hop):
            return hop
    return peer_ip


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
    settings: Settings = request.app.state.settings
    ip = scored_ip(client_ip(request, settings), private_is_home=settings.private_ip_is_home)
    ticket_text = request.query_params.get("simulation_ticket")
    if settings.trust_client_reported_ip:
        country, asn = request.query_params.get("country"), request.query_params.get("asn")
        ticket_text = None
    else:
        # ADR-0032: `?country=` from the URL is ignored here; only a signed
        # ticket can change the signals, and it travels on to POST /login.
        ticket = verify_ticket(settings.simulation_secret, ticket_text)
        country, asn = (ticket.country, ticket.asn) if ticket else (None, None)
        if ticket is None:
            ticket_text = None
    signals = resolve_login_signals(ip, country=country, asn=asn)
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
        "simulated": signals.simulated,
        "simulation_ticket": ticket_text,
    }


def _safe_next(value: str | None) -> str | None:
    if value and value.startswith("/admin"):
        return value
    return None
