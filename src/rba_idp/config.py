"""Runtime settings (env / .env)."""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_name: str = "rba-idp"
    host: str = "0.0.0.0"
    port: int = 8001

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
    webauthn_rp_name: str = "RBA Identity"
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


@lru_cache
def get_settings() -> Settings:
    return Settings()
