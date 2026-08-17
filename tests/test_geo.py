"""Local prefix GeoIP + query overrides (Demo-1)."""

from rba_idp.geo import HOME_IP, lookup_ip, resolve_login_signals, scored_ip


def test_testnets_map_to_demo_countries() -> None:
    ar = lookup_ip("203.0.113.10")
    assert ar.country == "AR" and ar.asn == "7303"
    jp = lookup_ip("192.0.2.1")
    assert jp.country == "JP" and jp.asn == "2516"
    de = lookup_ip("198.51.100.20")
    assert de.country == "DE" and de.asn == "3320"


def test_loopback_and_junk_are_missing() -> None:
    assert lookup_ip("127.0.0.1").country is None
    assert lookup_ip("not-an-ip").country is None
    assert lookup_ip("::1").country is None


def test_private_peers_score_as_home_testnet() -> None:
    assert scored_ip("127.0.0.1") == HOME_IP
    assert scored_ip("10.0.0.4") == HOME_IP
    assert scored_ip("192.168.1.9") == HOME_IP
    assert scored_ip("203.0.113.10") == "203.0.113.10"
    assert scored_ip("192.0.2.1") == "192.0.2.1"


def test_override_wins_over_prefix() -> None:
    sig = resolve_login_signals("203.0.113.10", country="jp", asn="AS2516")
    assert sig.country == "JP"
    assert sig.asn == "2516"


def test_invalid_override_falls_back() -> None:
    sig = resolve_login_signals("203.0.113.10", country="Argentina", asn="nope")
    assert sig.country == "AR"
    assert sig.asn == "7303"
