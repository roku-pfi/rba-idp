"""C-3 / ADR-0032: DB-IP Lite behind the TEST-NET table, IPv4 and IPv6."""

from __future__ import annotations

from pathlib import Path

import pytest

from rba_idp import geo
from rba_idp.geo import GeoDatabase, configure_geoip, lookup_ip, resolve_login_signals

GEOIP = Path(__file__).resolve().parents[1] / ".geoip"
COUNTRY = GEOIP / "dbip-country-lite.mmdb"
ASN = GEOIP / "dbip-asn-lite.mmdb"


class _Reader:
    def __init__(self, table: dict) -> None:
        self.table = table

    def get(self, addr: str):
        return self.table.get(addr)


@pytest.fixture
def fake_db(monkeypatch):
    db = GeoDatabase()
    db._country = _Reader({
        "181.47.1.1": {"country": {"iso_code": "AR"}},
        "2800:810:4c2::1": {"country": {"iso_code": "AR"}},
        "54.239.28.85": {"country": {"iso_code": "US"}},
    })
    db._asn = _Reader({
        "181.47.1.1": {"autonomous_system_number": 27747},
        "2800:810:4c2::1": {"autonomous_system_number": 27747},
        "54.239.28.85": {"autonomous_system_number": 16509},
    })
    monkeypatch.setattr(geo, "_db", db)
    return db


def test_a_real_address_gets_country_and_asn(fake_db) -> None:
    assert lookup_ip("181.47.1.1") == geo.LoginSignals("AR", "27747")


def test_ipv6_gets_signals_too(fake_db) -> None:
    """Phones on mobile data are often IPv6-only; before C-3 they had none."""
    assert lookup_ip("2800:810:4c2::1") == geo.LoginSignals("AR", "27747")


def test_test_nets_still_win_and_private_addresses_get_nothing(fake_db) -> None:
    assert lookup_ip("203.0.113.10") == geo.LoginSignals("AR", "7303")
    assert lookup_ip("10.0.3.17") == geo.LoginSignals(None, None)


def test_unknown_address_is_missing_not_guessed(fake_db) -> None:
    assert lookup_ip("8.8.4.4") == geo.LoginSignals(None, None)


def test_without_database_files_only_the_table_answers(monkeypatch) -> None:
    monkeypatch.setattr(geo, "_db", GeoDatabase("", ""))
    assert lookup_ip("181.47.1.1") == geo.LoginSignals(None, None)
    assert GeoDatabase("/nonexistent.mmdb", "").loaded is False


def test_an_override_is_simulated_only_when_it_changes_something(fake_db) -> None:
    real = resolve_login_signals("181.47.1.1")
    assert real.simulated is False
    # The local bank pins the home country on every login: not a simulation.
    assert resolve_login_signals("181.47.1.1", country="AR").simulated is False
    tokyo = resolve_login_signals("181.47.1.1", country="JP")
    assert (tokyo.country, tokyo.asn, tokyo.simulated) == ("JP", "27747", True)


@pytest.mark.skipif(not (COUNTRY.is_file() and ASN.is_file()),
                    reason="run scripts/fetch_geoip.py .geoip for the real-database check")
def test_the_real_db_ip_files(monkeypatch) -> None:
    monkeypatch.setattr(geo, "_db", geo._db)
    db = configure_geoip(str(COUNTRY), str(ASN))
    assert db.loaded
    assert lookup_ip("181.47.1.1").country == "AR"
    assert lookup_ip("2800:810:4c2::1").country == "AR"
    # An AWS address: the attacker Lambdas will look like this (AS16509).
    assert lookup_ip("54.239.28.85").asn == "16509"
    configure_geoip("", "")
