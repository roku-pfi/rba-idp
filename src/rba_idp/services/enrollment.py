"""Passkey enrollment, only from a trusted context (ADR-0037).

Two doors, and no third:

1. **After a low-risk login.** The login path marks the session (``enroll_until``)
   when the engine's own verdict was ALLOW and the user had no passkey. That
   session may enroll one passkey, once, for a few minutes.
2. **With an activation code** an operator issued: single use, short-lived,
   stored hashed, bound to one user — and the user's password is checked too,
   so neither a leaked code nor a leaked password enrolls anything alone.

A step-up is never a door: the login path refuses it instead (``login.py``).
"""

from __future__ import annotations

import hashlib
import logging
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException
from rba_contracts import (
    ActivationCodeResponse,
    ActivationOptionsRequest,
    ActivationVerifyRequest,
    PasskeyOptionsResponse,
    PasskeyVerifyRequest,
)
from sqlalchemy import select, update
from sqlalchemy.orm import Session, sessionmaker
from webauthn.helpers import bytes_to_base64url
from webauthn.helpers.exceptions import WebAuthnException

from rba_idp.config import Settings
from rba_idp.db.models import ActivationCode, IdpSession, User, WebAuthnCredential
from rba_idp.db.session import session_scope
from rba_idp.passwords import verify_password
from rba_idp.tokens import bearer_token, hash_session_token
from rba_idp.webauthn import creation_options, verify_create

logger = logging.getLogger(__name__)

# No 0/O, 1/I/L: the code is read aloud or typed from a support ticket.
CODE_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
CODE_LENGTH = 12  # ≈ 59 bits; brute force is moot within a 15-minute life

INVALID_CODE = "invalid or expired code"
NO_ENROLLMENT = "this session may not enroll a passkey"


def _as_utc(dt: datetime) -> datetime:
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


def new_activation_code() -> str:
    raw = "".join(secrets.choice(CODE_ALPHABET) for _ in range(CODE_LENGTH))
    return "-".join(raw[i : i + 4] for i in range(0, CODE_LENGTH, 4))


def normalise_code(code: str) -> str:
    """``"k7qf 3mzp-9txa"`` → ``"K7QF3MZP9TXA"``: how it was typed must not matter."""
    return "".join(ch for ch in code.upper() if ch.isalnum())


def hash_code(code: str) -> str:
    return hashlib.sha256(normalise_code(code).encode("ascii", "ignore")).hexdigest()


def issue_activation_code(
    session: Session, settings: Settings, user: User, *, issued_by: str
) -> ActivationCodeResponse:
    """Issue a code for ``user``; any earlier unused code of theirs stops working."""
    now = datetime.now(timezone.utc)
    session.execute(
        update(ActivationCode)
        .where(ActivationCode.user_id == user.user_id, ActivationCode.consumed_at.is_(None))
        .values(consumed_at=now)
    )
    code = new_activation_code()
    expires_at = now + timedelta(seconds=settings.activation_ttl_seconds)
    session.add(
        ActivationCode(
            code_hash=hash_code(code),
            user_id=user.user_id,
            issued_by=issued_by,
            expires_at=expires_at,
        )
    )
    logger.info(
        "activation code issued tenant_id=%s user_id=%s by=%s",
        user.tenant_id,
        user.user_id,
        issued_by,
    )
    return ActivationCodeResponse(user_id=user.user_id, code=code, expires_at=expires_at)


class EnrollmentService:
    def __init__(self, session_factory: sessionmaker, settings: Settings) -> None:
        self._session_factory = session_factory
        self._settings = settings

    # ------------------------------------------------------------ after a low-risk login

    def _enrolling_session(self, session: Session, authorization: str | None) -> IdpSession:
        raw = bearer_token(authorization)
        if raw is None:
            raise HTTPException(status_code=401, detail="missing or expired session")
        now = datetime.now(timezone.utc)
        row = session.get(IdpSession, hash_session_token(raw))
        if row is None or _as_utc(row.expires_at) <= now:
            raise HTTPException(status_code=401, detail="missing or expired session")
        if row.enroll_until is None or _as_utc(row.enroll_until) <= now:
            raise HTTPException(status_code=403, detail=NO_ENROLLMENT)
        return row

    def session_options(self, authorization: str | None) -> PasskeyOptionsResponse:
        with session_scope(self._session_factory) as session:
            row = self._enrolling_session(session, authorization)
            user = session.get(User, row.user_id)
            if user is None or not user.enabled:
                raise HTTPException(status_code=401, detail="missing or expired session")
            if _has_passkey(session, user.user_id):
                # Enrolled meanwhile (another tab, an activation code): the
                # offer was for a user with no passkey, so it lapses.
                row.enroll_until = None
                raise HTTPException(status_code=403, detail=NO_ENROLLMENT)
            nonce, public_key = creation_options(
                self._settings, user_id=user.user_id, email=user.email
            )
            row.webauthn_challenge = nonce
            return PasskeyOptionsResponse(public_key=public_key)

    def session_verify(self, authorization: str | None, body: PasskeyVerifyRequest) -> None:
        with session_scope(self._session_factory) as session:
            row = self._enrolling_session(session, authorization)
            if row.webauthn_challenge is None:
                raise HTTPException(status_code=400, detail="no enrollment in progress")
            _store_credential(session, self._settings, row.user_id, row.webauthn_challenge, body.credential)
            row.enroll_until = None
            row.webauthn_challenge = None
            logger.info("passkey enrolled after low-risk login user_id=%s", row.user_id)

    # ------------------------------------------------------------ with an activation code

    def _open_code(self, session: Session, code: str) -> ActivationCode | None:
        row = session.get(ActivationCode, hash_code(code))
        now = datetime.now(timezone.utc)
        if row is None or row.consumed_at is not None or _as_utc(row.expires_at) <= now:
            return None
        return row

    def activation_options(self, body: ActivationOptionsRequest) -> PasskeyOptionsResponse:
        with session_scope(self._session_factory) as session:
            row = self._open_code(session, body.code)
            user = session.get(User, row.user_id) if row is not None else None
            # Same answer, same bcrypt, for a bad code and a bad password.
            if user is None or not user.enabled:
                verify_password(body.password, None)
                raise HTTPException(status_code=400, detail=INVALID_CODE)
            if not verify_password(body.password, user.password_hash):
                raise HTTPException(status_code=400, detail=INVALID_CODE)
            nonce, public_key = creation_options(
                self._settings, user_id=user.user_id, email=user.email
            )
            row.webauthn_challenge = nonce
            return PasskeyOptionsResponse(public_key=public_key)

    def activation_verify(self, body: ActivationVerifyRequest) -> None:
        with session_scope(self._session_factory) as session:
            row = self._open_code(session, body.code)
            if row is None or row.webauthn_challenge is None:
                raise HTTPException(status_code=400, detail=INVALID_CODE)
            _store_credential(session, self._settings, row.user_id, row.webauthn_challenge, body.credential)
            row.consumed_at = datetime.now(timezone.utc)
            logger.info("passkey enrolled with activation code user_id=%s", row.user_id)


def _has_passkey(session: Session, user_id: str) -> bool:
    return (
        session.scalar(
            select(WebAuthnCredential.credential_id)
            .where(WebAuthnCredential.user_id == user_id)
            .limit(1)
        )
        is not None
    )


def _store_credential(
    session: Session, settings: Settings, user_id: str, nonce: bytes, credential: dict
) -> None:
    try:
        verified = verify_create(settings, credential=credential, expected_challenge=nonce)
    except (WebAuthnException, ValueError, TypeError, KeyError) as exc:
        raise HTTPException(status_code=400, detail="passkey could not be verified") from exc
    credential_id = bytes_to_base64url(verified.credential_id)
    if session.get(WebAuthnCredential, credential_id) is not None:
        raise HTTPException(status_code=409, detail="passkey already registered")
    session.add(
        WebAuthnCredential(
            credential_id=credential_id,
            user_id=user_id,
            public_key=verified.credential_public_key,
            sign_count=verified.sign_count,
        )
    )
