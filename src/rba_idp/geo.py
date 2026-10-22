"""Client IP → country/ASN for the login path (ADR-0022, ADR-0032).

Three sources, in order:

1. The RFC 5737 TEST-NET table — demo and test stand-ins for home / far / EU.
2. **DB-IP Lite** (country + ASN, IPv4 and IPv6, CC BY 4.0), two MMDB files
   baked into the image. An in-memory read: no network call inside the login.
3. Nothing: a missing country/ASN, which the features treat as not-seen.

An explicit override (presenter) beats all three, and marks the login
``simulated`` when it changes what the address says.

IP geolocation by DB-IP (https://db-ip.com), licensed CC BY 4.0.
"""

from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)

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
    # An override changed the country or ASN the address resolves to.
    simulated: bool = False


class GeoDatabase:
    """DB-IP Lite country + ASN readers. Either file may be absent (local dev,
    tests): lookups then fall back to the TEST-NET table alone."""

    def __init__(self, country_path: str = "", asn_path: str = "") -> None:
        self._country = _open(country_path)
        self._asn = _open(asn_path)

    @property
    def loaded(self) -> bool:
        return self._country is not None and self._asn is not None

    def lookup(self, addr: str) -> LoginSignals:
        country = asn = None
        if self._country is not None:
            record = self._country.get(addr) or {}
            country = normalize_country((record.get("country") or {}).get("iso_code"))
        if self._asn is not None:
            record = self._asn.get(addr) or {}
            number = record.get("autonomous_system_number")
            asn = str(number) if number else None
        return LoginSignals(country=country, asn=asn)


def _open(path: str):
    if not path:
        return None
    if not Path(path).is_file():
        logger.warning("GeoIP database not found: %s", path)
        return None
    import maxminddb

    return maxminddb.open_database(path, maxminddb.MODE_MEMORY)


_db = GeoDatabase()


def configure_geoip(country_path: str, asn_path: str) -> GeoDatabase:
    """Load the DB-IP files once at startup; the login path only reads."""
    global _db
    _db = GeoDatabase(country_path, asn_path)
    return _db


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
    if isinstance(addr, ipaddress.IPv4Address):
        for network, country, asn in _PREFIXES:
            if addr in network:
                return LoginSignals(country=country, asn=asn)
    if is_unroutable(str(addr)):
        return LoginSignals(country=None, asn=None)
    return _db.lookup(str(addr))


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
    """Explicit override wins; otherwise the address's own signals; else missing.

    ``simulated`` is set only when an override actually changes something: the
    local bank pins the home country on every login, which equals what the
    home address resolves to and is not a simulation.
    """
    looked = lookup_ip(ip)
    final_country = normalize_country(country) or looked.country
    final_asn = normalize_asn(asn) or looked.asn
    return LoginSignals(
        country=final_country,
        asn=final_asn,
        simulated=(final_country, final_asn) != (looked.country, looked.asn),
    )
