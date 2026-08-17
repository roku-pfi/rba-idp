"""Local IP → country/ASN for the hosted login path (Demo-1).

Not MaxMind and not city GeoIP (ADR-0022). Documentation prefixes plus an
explicit query override so a presenter can set country without a GeoIP product.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

# RFC 5737 TEST-NETs — mapped to demo home / far / EU so travel can be exercised.
_PREFIXES: tuple[tuple[ipaddress.IPv4Network, str, str], ...] = (
    (ipaddress.ip_network("203.0.113.0/24"), "AR", "7303"),  # TEST-NET-3, home
    (ipaddress.ip_network("192.0.2.0/24"), "JP", "2516"),  # TEST-NET-1, far
    (ipaddress.ip_network("198.51.100.0/24"), "DE", "3320"),  # TEST-NET-2
)

HOME_IP = "203.0.113.10"


@dataclass(frozen=True)
class LoginSignals:
    country: str | None
    asn: str | None


def normalize_country(value: str | None) -> str | None:
    if not value:
        return None
    text = value.strip().upper()
    if len(text) != 2 or not text.isalpha():
        return None
    return text


def normalize_asn(value: str | None) -> str | None:
    if not value:
        return None
    text = value.strip().upper()
    if text.startswith("AS"):
        text = text[2:]
    text = text.strip()
    return text if text.isdigit() else None


def lookup_ip(ip: str) -> LoginSignals:
    try:
        addr = ipaddress.ip_address(ip.strip())
    except ValueError:
        return LoginSignals(country=None, asn=None)
    if not isinstance(addr, ipaddress.IPv4Address):
        return LoginSignals(country=None, asn=None)
    for network, country, asn in _PREFIXES:
        if addr in network:
            return LoginSignals(country=country, asn=asn)
    return LoginSignals(country=None, asn=None)


def is_unroutable(ip: str) -> bool:
    """True for loopback / RFC1918 / link-local — a laptop or cluster peer.

    Do not use ``IPv4Address.is_private``: it includes RFC 5737 TEST-NETs,
    which this module uses as demo geo stand-ins.
    """
    try:
        addr = ipaddress.ip_address(ip.strip())
    except ValueError:
        return True
    if not isinstance(addr, ipaddress.IPv4Address):
        return True
    return bool(
        addr.is_loopback
        or addr.is_link_local
        or addr in ipaddress.ip_network("10.0.0.0/8")
        or addr in ipaddress.ip_network("172.16.0.0/12")
        or addr in ipaddress.ip_network("192.168.0.0/16")
    )


def scored_ip(ip: str) -> str:
    """Private peers score as the demo home TEST-NET so a usual laptop login can ALLOW."""
    return HOME_IP if is_unroutable(ip) else ip.strip()


def resolve_login_signals(
    ip: str,
    *,
    country: str | None = None,
    asn: str | None = None,
) -> LoginSignals:
    """Explicit override wins; otherwise the local prefix table; else missing."""
    looked = lookup_ip(ip)
    return LoginSignals(
        country=normalize_country(country) or looked.country,
        asn=normalize_asn(asn) or looked.asn,
    )
