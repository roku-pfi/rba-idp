"""C-1: a cloud IdP refuses to start on any default that is only safe locally."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest
from pydantic import ValidationError

from rba_idp.config import Settings

AUTH = "d1fg623tjiucw7.cloudfront.net"

# Cloud mode checks the GeoIP files exist; their contents do not matter here.
_GEO = Path(tempfile.mkdtemp())
for _name in ("country.mmdb", "asn.mmdb"):
    (_GEO / _name).write_bytes(b"")

CLOUD = {
    "deployment": "cloud",
    "database_url": "postgresql+psycopg://idp:generated@rba.abc123.us-east-1.rds.amazonaws.com:5432/rba_idp?sslmode=require",
    "pdp_base_url": "http://decision-service:8000",
    "audit_base_url": "http://decision-service:8000",
    "public_url": f"https://{AUTH}",
    "webauthn_rp_id": AUTH,
    "webauthn_origin": f"https://{AUTH}",
    "seed_password_suffix": "Zq8v2LmT4xRw",
    "trusted_proxy_cidrs": "10.0.0.0/20,10.0.16.0/20",
    "client_ip_header": "cloudfront-viewer-address",
    "trust_client_reported_ip": False,
    "private_ip_is_home": False,
    "init_on_startup": False,
    "geoip_country_db": str(_GEO / "country.mmdb"),
    "geoip_asn_db": str(_GEO / "asn.mmdb"),
    "seed_bank_redirect_uri": "https://d3m6kfm1gma0g6.cloudfront.net/callback",
    "seed_kaze_redirect_uri": "https://d14wc5kuicqxf6.cloudfront.net/callback",
}


def test_a_complete_cloud_configuration_starts() -> None:
    settings = Settings(_env_file=None, **CLOUD)
    assert settings.webauthn_origins() == [f"https://{AUTH}"]
    assert settings.mock_otp_enabled is False


def test_local_is_the_default_and_accepts_the_defaults() -> None:
    assert Settings(_env_file=None).deployment == "local"


@pytest.mark.parametrize(
    ("override", "complaint"),
    [
        ({"mock_otp_enabled": True}, "MOCK_OTP_ENABLED"),
        ({"use_memory_db": True}, "USE_MEMORY_DB"),
        ({"database_url": "postgresql+psycopg://rba:rba@postgres:5432/rba_idp"}, "DATABASE_URL"),
        ({"pdp_base_url": "http://localhost:8000"}, "PDP_BASE_URL"),
        ({"public_url": f"http://{AUTH}"}, "PUBLIC_URL"),
        ({"webauthn_rp_id": "localhost"}, "WEBAUTHN_RP_ID"),
        ({"webauthn_origin": f"http://{AUTH}"}, "https:// origins"),
        ({"webauthn_origin": "https://evil.example"}, "subdomain"),
        ({"seed_password_suffix": "demo"}, "SEED_PASSWORD_SUFFIX"),
        ({"trust_client_reported_ip": True}, "TRUST_CLIENT_REPORTED_IP"),
        ({"private_ip_is_home": True}, "PRIVATE_IP_IS_HOME"),
        ({"trusted_proxy_cidrs": ""}, "TRUSTED_PROXY_CIDRS"),
        ({"init_on_startup": True}, "INIT_ON_STARTUP"),
        ({"geoip_asn_db": "/nonexistent/asn.mmdb"}, "GEOIP_ASN_DB"),
        ({"simulation_secret": "short"}, "SIMULATION_SECRET"),
        ({"seed_bank_redirect_uri": "http://localhost:8002/callback"}, "SEED_BANK_REDIRECT_URI"),
    ],
)
def test_each_local_default_is_refused_in_the_cloud(override: dict, complaint: str) -> None:
    with pytest.raises(ValidationError, match=complaint):
        Settings(_env_file=None, **{**CLOUD, **override})


def test_every_problem_is_listed_at_once() -> None:
    """One failed rollout should show the whole list, not one item per retry."""
    with pytest.raises(ValidationError) as info:
        Settings(_env_file=None, deployment="cloud")
    assert str(info.value).count("\n  - ") >= 6
