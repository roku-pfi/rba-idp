"""Runtime settings (env / .env)."""

from __future__ import annotations

import ipaddress
from functools import lru_cache
from pathlib import Path
from typing import Literal
from urllib.parse import urlparse

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

LOCAL_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0", "::1"}


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_name: str = "rba-idp"
    host: str = "0.0.0.0"
    port: int = 8001

    # C-1. "local" (compose, k3d, tests) accepts the defaults below. "cloud"
    # refuses to start while any of them is still in place — every default
    # here works, which is exactly why one left behind would go unnoticed.
    deployment: Literal["local", "cloud"] = "local"
    # C-4: create the schema and seed at startup. On in compose/k3d/tests; off
    # where `python -m rba_idp.init` runs as a Job before the replicas.
    init_on_startup: bool = True

    # This IdP's browser-facing origin (CloudFront in the cloud).
    public_url: str = "http://localhost:8001"

    # C-2 / ADR-0032: where the client's address comes from. Forwarding headers
    # are believed only when the direct peer is in TRUSTED_PROXY_CIDRS (the
    # ALB's subnets); empty means "the socket peer, always".
    trusted_proxy_cidrs: str = ""
    # Behind CloudFront the right-most X-Forwarded-For hop is the edge, not the
    # viewer, so the cloud reads CloudFront's own header instead.
    client_ip_header: Literal["x-forwarded-for", "cloudfront-viewer-address"] = (
        "x-forwarded-for"
    )
    # Accept `ip_address` from the POST body. Locally the hosted page and the
    # bank walkthrough's stand-in attacker rely on it; in the cloud it would let
    # anyone claim the victim's usual address.
    trust_client_reported_ip: bool = True
    # Score loopback/private peers as the demo home address, so a laptop login
    # looks usual. In the cloud a private address means the client IP was not
    # resolved, and must not look like home.
    private_ip_is_home: bool = True

    # C-3 / ADR-0032: DB-IP Lite MMDB files (baked into the image). Empty or
    # missing → the TEST-NET table only, as in tests.
    geoip_country_db: str = ""
    geoip_asn_db: str = ""
    # Signs simulation tickets (presenter override). Empty: no simulation
    # where client signals are not trusted.
    simulation_secret: str = ""
    simulation_ttl_seconds: int = 10 * 60

    database_url: str = "postgresql+psycopg://rba:rba@localhost:5432/rba_idp"
    # When true, use in-memory SQLite (unit tests / no Docker).
    use_memory_db: bool = False

    pdp_base_url: str = "http://localhost:8000"
    pdp_timeout_seconds: float = 2.0
    # Report wrong-password attempts to the PDP so `failed_logins_last_24h` is
    # real (ADR-0027). Off = the feature is permanently 0 in production.
    report_failed_logins: bool = True

    # RF-10 / RNF-03. When the PDP does not answer at all, the IdP still has to
    # decide. Returning 503 would lock out every legitimate user for the length
    # of the outage — the "bloqueo masivo" the requirement forbids — and letting
    # everyone in is the other thing it forbids. So we degrade to a step-up.
    #
    # The type is the guarantee: ALLOW and BLOCK are not expressible here, so no
    # configuration mistake can turn an outage into open access or a mass
    # lockout.
    pdp_unavailable_action: Literal["REQUIRE_MFA", "REAUTHENTICATE"] = "REQUIRE_MFA"

    session_ttl_seconds: int = 8 * 3600
    challenge_ttl_seconds: int = 5 * 60
    callback_ttl_seconds: int = 2 * 60
    # POST /mfa/verify accepts this fixed code as a second factor. Test-only:
    # with it on, anyone holding a password passes any step-up, so it is off
    # unless explicitly enabled (and the endpoint answers 404 when off).
    mock_otp_enabled: bool = False
    mock_otp_code: str = "000000"
    # ADR-0037: how long after a low-risk login the session may enroll a
    # passkey, and how long an operator-issued activation code lives.
    enroll_window_seconds: int = 10 * 60
    activation_ttl_seconds: int = 15 * 60

    webauthn_rp_id: str = "localhost"
    webauthn_rp_name: str = "RokuSec"
    # Comma-separated origins. Compose uses :8001; k3d Ingress uses :8080.
    webauthn_origin: str = "http://localhost:8001,http://localhost:8080"

    # How long the login path trusts a tenant's policy before re-reading it
    # from the PDP. Only `engine_mode == OFF` is decided from it here; every
    # other decision is the PDP's own, made with the PDP's current policy.
    policy_cache_seconds: float = 5.0

    # Seed (ADR-0033): three tenants. Only the values that differ between
    # environments are settings; the directory itself lives in `seed.py`.
    seed_bank_redirect_uri: str = "http://localhost:8002/callback"
    seed_kaze_redirect_uri: str = "http://localhost:8003/callback"
    # Every seeded user's password is f"{local part}-{suffix}", e.g.
    # martin@correo.example → "martin-demo". Overridable so a cloud session
    # does not run on a password printed in the repository.
    seed_password_suffix: str = "demo"

    audit_base_url: str = "http://localhost:8000"
    audit_timeout_seconds: float = 2.0

    def trusted_proxies(self) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
        return [
            ipaddress.ip_network(part.strip(), strict=False)
            for part in self.trusted_proxy_cidrs.split(",")
            if part.strip()
        ]

    def webauthn_origins(self) -> list[str]:
        return [part.strip() for part in self.webauthn_origin.split(",") if part.strip()]

    @model_validator(mode="after")
    def _cloud_is_explicit(self) -> "Settings":
        if self.deployment == "cloud":
            problems = cloud_problems(self)
            if problems:
                raise ValueError(
                    "DEPLOYMENT=cloud refuses to start:\n  - " + "\n  - ".join(problems)
                )
        return self


def _is_local(url: str) -> bool:
    return (urlparse(url).hostname or "") in LOCAL_HOSTS


def cloud_problems(s: Settings) -> list[str]:
    """Everything that would make a cloud IdP insecure or silently wrong."""
    problems: list[str] = []
    if s.use_memory_db:
        problems.append("USE_MEMORY_DB is on: the directory would vanish with the pod")
    if s.init_on_startup:
        problems.append("INIT_ON_STARTUP is on: replicas would race to create the schema (run python -m rba_idp.init as a Job)")
    if s.trust_client_reported_ip:
        problems.append("TRUST_CLIENT_REPORTED_IP is on: a client could claim any address")
    if s.private_ip_is_home:
        problems.append("PRIVATE_IP_IS_HOME is on: an unresolved address would score as home")
    if not s.trusted_proxy_cidrs.strip():
        problems.append("TRUSTED_PROXY_CIDRS is empty: every login would carry the ALB's address")
    for name in ("geoip_country_db", "geoip_asn_db"):
        path = getattr(s, name)
        if not path or not Path(path).is_file():
            problems.append(f"{name.upper()} is not a readable file: real logins would carry no country/ASN")
    if s.simulation_secret and len(s.simulation_secret) < 32:
        problems.append("SIMULATION_SECRET must be a generated secret (≥ 32 chars) or empty")
    if s.mock_otp_enabled:
        problems.append("MOCK_OTP_ENABLED is on: a fixed code would pass every step-up")
    if "rba:rba@" in s.database_url or _is_local(s.database_url):
        problems.append("DATABASE_URL is the local default")
    for name in ("pdp_base_url", "audit_base_url"):
        if _is_local(getattr(s, name)):
            problems.append(f"{name.upper()} points at localhost")
    if not s.public_url.startswith("https://") or _is_local(s.public_url):
        problems.append("PUBLIC_URL must be the https:// origin browsers use")
    # WebAuthn: passkeys are bound to the RP ID; one registered against
    # "localhost" is useless anywhere else, and browsers require https.
    if s.webauthn_rp_id in LOCAL_HOSTS:
        problems.append("WEBAUTHN_RP_ID is localhost")
    origins = s.webauthn_origins()
    if not origins or any(not o.startswith("https://") for o in origins):
        problems.append("WEBAUTHN_ORIGIN must list only https:// origins")
    elif any((urlparse(o).hostname or "") != s.webauthn_rp_id
             and not (urlparse(o).hostname or "").endswith("." + s.webauthn_rp_id)
             for o in origins):
        problems.append("every WEBAUTHN_ORIGIN must be WEBAUTHN_RP_ID or a subdomain of it")
    # Seeded passwords are "<name>-<suffix>"; the default suffix is in git.
    if s.seed_password_suffix == "demo" or len(s.seed_password_suffix) < 12:
        problems.append("SEED_PASSWORD_SUFFIX must be a generated secret (≥ 12 chars)")
    for name in ("seed_bank_redirect_uri", "seed_kaze_redirect_uri"):
        value = getattr(s, name)
        if not value.startswith("https://") or _is_local(value):
            problems.append(f"{name.upper()} must be an https:// URL")
    return problems


@lru_cache
def get_settings() -> Settings:
    return Settings()
