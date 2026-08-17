"""WebAuthn passkey ceremonies for MFA step-up (Demo-4)."""

from __future__ import annotations

import json

from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import base64url_to_bytes
from webauthn.helpers.structs import (
    AuthenticatorAttachment,
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    PublicKeyCredentialHint,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from rba_idp.config import Settings


def _origins(settings: Settings) -> list[str]:
    return [part.strip() for part in settings.webauthn_origin.split(",") if part.strip()]


def creation_options(settings: Settings, *, user_id: str, email: str) -> tuple[bytes, dict]:
    options = generate_registration_options(
        rp_id=settings.webauthn_rp_id,
        rp_name=settings.webauthn_rp_name,
        user_id=user_id.encode("utf-8"),
        user_name=email,
        user_display_name=email,
        authenticator_selection=AuthenticatorSelectionCriteria(
            authenticator_attachment=AuthenticatorAttachment.PLATFORM,
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.REQUIRED,
        ),
        hints=[PublicKeyCredentialHint.CLIENT_DEVICE],
    )
    return options.challenge, json.loads(options_to_json(options))


def request_options(settings: Settings, credential_ids: list[str]) -> tuple[bytes, dict]:
    options = generate_authentication_options(
        rp_id=settings.webauthn_rp_id,
        allow_credentials=[
            PublicKeyCredentialDescriptor(id=base64url_to_bytes(cid))
            for cid in credential_ids
        ],
        user_verification=UserVerificationRequirement.REQUIRED,
    )
    return options.challenge, json.loads(options_to_json(options))


def verify_create(settings: Settings, *, credential: dict, expected_challenge: bytes):
    return verify_registration_response(
        credential=credential,
        expected_challenge=expected_challenge,
        expected_rp_id=settings.webauthn_rp_id,
        expected_origin=_origins(settings),
        require_user_verification=True,
    )


def verify_get(
    settings: Settings,
    *,
    credential: dict,
    expected_challenge: bytes,
    public_key: bytes,
    sign_count: int,
):
    return verify_authentication_response(
        credential=credential,
        expected_challenge=expected_challenge,
        expected_rp_id=settings.webauthn_rp_id,
        expected_origin=_origins(settings),
        credential_public_key=public_key,
        credential_current_sign_count=sign_count,
        require_user_verification=True,
    )
