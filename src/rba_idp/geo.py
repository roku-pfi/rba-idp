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


_ULA = ipaddress.ip_network("fc00::/7")


def is_unroutable(ip: str) -> bool:
    """True for loopback / RFC1918 / link-local / IPv6 ULA — a laptop or cluster peer.

    Do not use ``IPv4Address.is_private``: it includes RFC 5737 TEST-NETs,
    which this module uses as demo geo stand-ins. A global IPv6 address is
    routable (it was treated as unroutable before C-2, so every IPv6 login
    scored as the demo home).
    """
    try:
        addr = ipaddress.ip_address(ip.strip())
    except ValueError:
        return True
    if isinstance(addr, ipaddress.IPv6Address):
        if addr.ipv4_mapped is not None:
            return is_unroutable(str(addr.ipv4_mapped))
        return bool(addr.is_loopback or addr.is_link_local or addr in _ULA or addr.is_unspecified)
    return bool(
        addr.is_loopback
        or addr.is_link_local
        or addr.is_unspecified
        or addr in ipaddress.ip_network("10.0.0.0/8")
        or addr in ipaddress.ip_network("172.16.0.0/12")
        or addr in ipaddress.ip_network("192.168.0.0/16")
    )


def scored_ip(ip: str, *, private_is_home: bool = True) -> str:
    """The address sent to the PDP.

    Locally, private peers score as the demo home TEST-NET so a usual laptop
    login can ALLOW. With ``private_is_home=False`` (cloud) the address goes
    through as it is: a private one then carries no country or ASN, which the
    features treat as not-seen — never as home.
    """
    if private_is_home and is_unroutable(ip):
        return HOME_IP
    return ip.strip()


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
