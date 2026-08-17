"""Password verify, PDP enforce, session on ALLOW, WebAuthn MFA, mock OTP for tests."""

from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse
from uuid import UUID, uuid4

from fastapi import HTTPException
from rba_contracts import (
    Action,
    CallbackTokenRequest,
    CallbackTokenResponse,
    LoginOutcome,
    LoginRequest,
    LoginResponse,
    MfaVerifyRequest,
    MfaWebAuthnOptionsRequest,
    MfaWebAuthnOptionsResponse,
    MfaWebAuthnVerifyRequest,
    Reason,
    RiskEvaluateRequest,
    RiskEvaluateResponse,
    RiskLevel,
    SessionResponse,
    SessionToken,
    UserPublic,
    WebAuthnCeremonyMode,
    outcome_from_action,
)
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker
from webauthn.helpers import bytes_to_base64url
from webauthn.helpers.exceptions import WebAuthnException

from rba_idp.config import Settings
from rba_idp.db.models import (
    Application,
    AuthCode,
    GroupAppGrant,
    GroupMembership,
    IdpSession,
    MfaChallenge,
    User,
    WebAuthnCredential,
)
from rba_idp.db.session import session_scope
from rba_idp.geo import resolve_login_signals, scored_ip
from rba_idp.passwords import verify_password
from rba_idp.pdp import PdpClient, PdpUnavailable
from rba_idp.tokens import (
    bearer_token,
    hash_session_token,
    new_session_token,
    otp_matches,
)
from rba_idp.webauthn import creation_options, request_options, verify_create, verify_get


ACCESS_DENIED_DETAIL = "user is not granted access to this application"


def _as_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def match_redirect_uri(registered: str | None, requested: str | None) -> str | None:
    """Exact match against the registered URI. No registered URI → no off-IdP redirect."""
    if not registered:
        return None
    if requested is None or requested == "":
        return registered
    return registered if requested == registered else None


def append_query(uri: str, **params: str) -> str:
    parts = urlparse(uri)
    query = dict(parse_qsl(parts.query, keep_blank_values=True))
    query.update(params)
    return urlunparse(parts._replace(query=urlencode(query)))


def user_has_app_access(session: Session, user_id: str, application_id: str) -> bool:
    """True if any of the user's groups grants ``access`` on this application."""
    grant = session.scalar(
        select(GroupAppGrant.group_id)
        .join(
            GroupMembership,
            GroupMembership.group_id == GroupAppGrant.group_id,
        )
        .where(
            GroupMembership.user_id == user_id,
            GroupAppGrant.application_id == application_id,
            GroupAppGrant.permission == "access",
        )
        .limit(1)
    )
    return grant is not None


class LoginService:
    def __init__(
        self,
        session_factory: sessionmaker,
        pdp: PdpClient,
        settings: Settings,
    ) -> None:
        self._session_factory = session_factory
        self._pdp = pdp
        self._settings = settings

    def login(self, body: LoginRequest) -> LoginResponse:
        email = body.email.strip().lower()
        with session_scope(self._session_factory) as session:
            app = session.get(Application, body.application_id)
            if app is None or not app.enabled:
                raise HTTPException(status_code=400, detail="unknown application")
            registered_redirect = app.redirect_uri

            user = session.scalar(select(User).where(User.email == email))
            if user is None or not user.enabled:
                verify_password(body.password, None)
                return LoginResponse(outcome=LoginOutcome.INVALID_CREDENTIALS)

            if not verify_password(body.password, user.password_hash):
                return LoginResponse(outcome=LoginOutcome.INVALID_CREDENTIALS)

            user_id = user.user_id
            if not user_has_app_access(session, user_id, body.application_id):
                return LoginResponse(
                    outcome=LoginOutcome.ACCESS_DENIED,
                    user_id=user_id,
                    detail=ACCESS_DENIED_DETAIL,
                )

        ip = scored_ip(body.ip_address)
        signals = resolve_login_signals(ip, country=body.country, asn=body.asn)
        request = RiskEvaluateRequest(
            event_id=uuid4(),
            application_id=body.application_id,
            user_id=user_id,
            timestamp=datetime.now(timezone.utc),
            ip_address=ip,
            asn=signals.asn,
            country=signals.country,
            device_type=body.device_type,
            os=body.os,
            browser=body.browser,
            login_successful=True,
            user_agent=body.user_agent,
        )
        try:
            decision = self._pdp.evaluate(request)
        except PdpUnavailable as exc:
            raise HTTPException(status_code=503, detail="PDP unavailable") from exc

        return self._enforce(
            user_id,
            body.application_id,
            decision,
            requested_redirect=body.redirect_uri,
            registered_redirect=registered_redirect,
        )

    def verify_mfa(self, body: MfaVerifyRequest) -> LoginResponse:
        now = datetime.now(timezone.utc)
        with session_scope(self._session_factory) as session:
            challenge = self._open_challenge(session, body.challenge_id, now)
            if not otp_matches(body.code, self._settings.mock_otp_code):
                return LoginResponse(outcome=LoginOutcome.INVALID_CREDENTIALS)
            return self._finish_challenge(
                session, challenge, now, redirect_uri=body.redirect_uri
            )

    def webauthn_options(
        self, body: MfaWebAuthnOptionsRequest
    ) -> MfaWebAuthnOptionsResponse:
        now = datetime.now(timezone.utc)
        with session_scope(self._session_factory) as session:
            challenge = self._open_challenge(session, body.challenge_id, now)
            cred_ids = list(
                session.scalars(
                    select(WebAuthnCredential.credential_id).where(
                        WebAuthnCredential.user_id == challenge.user_id
                    )
                )
            )
            if cred_ids:
                mode = WebAuthnCeremonyMode.GET
                nonce, public_key = request_options(self._settings, cred_ids)
            else:
                user = session.get(User, challenge.user_id)
                if user is None or not user.enabled:
                    raise HTTPException(
                        status_code=400, detail="unknown or expired challenge"
                    )
                mode = WebAuthnCeremonyMode.CREATE
                nonce, public_key = creation_options(
                    self._settings, user_id=user.user_id, email=user.email
                )
            challenge.webauthn_challenge = nonce
            challenge.webauthn_mode = mode.value
            return MfaWebAuthnOptionsResponse(
                challenge_id=body.challenge_id,
                mode=mode,
                public_key=public_key,
            )

    def verify_webauthn(self, body: MfaWebAuthnVerifyRequest) -> LoginResponse:
        now = datetime.now(timezone.utc)
        with session_scope(self._session_factory) as session:
            challenge = self._open_challenge(session, body.challenge_id, now)
            if not challenge.webauthn_challenge or not challenge.webauthn_mode:
                raise HTTPException(
                    status_code=400, detail="unknown or expired challenge"
                )
            try:
                if challenge.webauthn_mode == WebAuthnCeremonyMode.CREATE.value:
                    verified = verify_create(
                        self._settings,
                        credential=body.credential,
                        expected_challenge=challenge.webauthn_challenge,
                    )
                    session.add(
                        WebAuthnCredential(
                            credential_id=bytes_to_base64url(verified.credential_id),
                            user_id=challenge.user_id,
                            public_key=verified.credential_public_key,
                            sign_count=verified.sign_count,
                        )
                    )
                else:
                    cred_id = body.credential.get("id")
                    if not isinstance(cred_id, str):
                        return LoginResponse(
                            outcome=LoginOutcome.INVALID_CREDENTIALS
                        )
                    stored = session.get(WebAuthnCredential, cred_id)
                    if stored is None or stored.user_id != challenge.user_id:
                        return LoginResponse(
                            outcome=LoginOutcome.INVALID_CREDENTIALS
                        )
                    verified = verify_get(
                        self._settings,
                        credential=body.credential,
                        expected_challenge=challenge.webauthn_challenge,
                        public_key=stored.public_key,
                        sign_count=stored.sign_count,
                    )
                    stored.sign_count = verified.new_sign_count
            except (WebAuthnException, ValueError, TypeError, KeyError):
                return LoginResponse(outcome=LoginOutcome.INVALID_CREDENTIALS)
            return self._finish_challenge(
                session, challenge, now, redirect_uri=body.redirect_uri
            )

    def exchange_code(self, body: CallbackTokenRequest) -> CallbackTokenResponse:
        now = datetime.now(timezone.utc)
        with session_scope(self._session_factory) as session:
            row = session.get(AuthCode, hash_session_token(body.code))
            if (
                row is None
                or row.consumed_at is not None
                or _as_utc(row.expires_at) <= now
            ):
                raise HTTPException(status_code=400, detail="unknown or expired code")
            stored = session.get(IdpSession, hash_session_token(row.session_token))
            user = session.get(User, row.user_id)
            if stored is None or _as_utc(stored.expires_at) <= now:
                raise HTTPException(status_code=400, detail="unknown or expired code")
            if user is None or not user.enabled:
                raise HTTPException(status_code=400, detail="unknown or expired code")
            row.consumed_at = now
            return CallbackTokenResponse(
                session=SessionToken(
                    token=row.session_token, expires_at=_as_utc(stored.expires_at)
                ),
                user=UserPublic(
                    user_id=user.user_id,
                    email=user.email,
                    created_at=_as_utc(user.created_at),
                    is_admin=bool(user.is_admin),
                ),
            )

    def get_session(self, authorization: str | None) -> SessionResponse:
        row, user = self._load_session(authorization)
        return SessionResponse(
            user=UserPublic(
                user_id=user.user_id,
                email=user.email,
                created_at=_as_utc(user.created_at),
                is_admin=bool(user.is_admin),
            ),
            expires_at=_as_utc(row.expires_at),
        )

    def logout(self, authorization: str | None) -> None:
        raw = bearer_token(authorization)
        if raw is None:
            return
        with session_scope(self._session_factory) as session:
            row = session.get(IdpSession, hash_session_token(raw))
            if row is not None:
                session.delete(row)

    def _enforce(
        self,
        user_id: str,
        application_id: str,
        decision: RiskEvaluateResponse,
        *,
        requested_redirect: str | None,
        registered_redirect: str | None,
    ) -> LoginResponse:
        session_token: SessionToken | None = None
        challenge_id: UUID | None = None
        redirect_to: str | None = None
        if decision.action == Action.ALLOW:
            session_token, redirect_to = self._create_session_with_callback(
                user_id,
                application_id,
                requested_redirect=requested_redirect,
                registered_redirect=registered_redirect,
            )
        elif decision.action in (Action.REQUIRE_MFA, Action.REAUTHENTICATE):
            challenge_id = self._create_challenge(user_id, application_id, decision)

        return LoginResponse(
            outcome=outcome_from_action(decision.action),
            user_id=user_id,
            event_id=decision.event_id,
            action=decision.action,
            risk_score=decision.risk_score,
            risk_level=decision.risk_level,
            reasons=decision.reasons,
            session=session_token,
            challenge_id=challenge_id,
            redirect_to=redirect_to,
        )

    def _create_session_with_callback(
        self,
        user_id: str,
        application_id: str,
        *,
        requested_redirect: str | None,
        registered_redirect: str | None,
    ) -> tuple[SessionToken, str | None]:
        now = datetime.now(timezone.utc)
        with session_scope(self._session_factory) as session:
            token = self._persist_session(session, user_id, application_id, now)
            redirect_to = self._persist_callback(
                session,
                user_id=user_id,
                application_id=application_id,
                raw_token=token.token,
                requested_redirect=requested_redirect,
                registered_redirect=registered_redirect,
            )
            return token, redirect_to

    def _persist_session(
        self,
        session,
        user_id: str,
        application_id: str,
        now: datetime,
    ) -> SessionToken:
        raw = new_session_token()
        expires_at = now + timedelta(seconds=self._settings.session_ttl_seconds)
        session.add(
            IdpSession(
                token_hash=hash_session_token(raw),
                user_id=user_id,
                application_id=application_id,
                expires_at=expires_at,
            )
        )
        return SessionToken(token=raw, expires_at=expires_at)

    def _persist_callback(
        self,
        session,
        *,
        user_id: str,
        application_id: str,
        raw_token: str,
        requested_redirect: str | None,
        registered_redirect: str | None,
    ) -> str | None:
        target = match_redirect_uri(registered_redirect, requested_redirect)
        if target is None:
            return None
        code = secrets.token_urlsafe(32)
        now = datetime.now(timezone.utc)
        session.add(
            AuthCode(
                code_hash=hash_session_token(code),
                session_token=raw_token,
                user_id=user_id,
                application_id=application_id,
                redirect_uri=target,
                expires_at=now + timedelta(seconds=self._settings.callback_ttl_seconds),
            )
        )
        return append_query(target, code=code)

    def _create_challenge(
        self,
        user_id: str,
        application_id: str,
        decision: RiskEvaluateResponse,
    ) -> UUID:
        challenge_id = uuid4()
        now = datetime.now(timezone.utc)
        with session_scope(self._session_factory) as session:
            session.add(
                MfaChallenge(
                    challenge_id=str(challenge_id),
                    user_id=user_id,
                    application_id=application_id,
                    event_id=str(decision.event_id),
                    action=decision.action.value,
                    risk_score=decision.risk_score,
                    risk_level=decision.risk_level.value,
                    reasons=[item.model_dump(mode="json") for item in decision.reasons],
                    expires_at=now
                    + timedelta(seconds=self._settings.challenge_ttl_seconds),
                )
            )
        return challenge_id

    def _open_challenge(
        self, session: Session, challenge_id: UUID, now: datetime
    ) -> MfaChallenge:
        challenge = session.get(MfaChallenge, str(challenge_id))
        if (
            challenge is None
            or challenge.consumed_at is not None
            or _as_utc(challenge.expires_at) <= now
        ):
            raise HTTPException(
                status_code=400, detail="unknown or expired challenge"
            )
        return challenge

    def _finish_challenge(
        self,
        session: Session,
        challenge: MfaChallenge,
        now: datetime,
        *,
        redirect_uri: str | None,
    ) -> LoginResponse:
        if not user_has_app_access(
            session, challenge.user_id, challenge.application_id
        ):
            return LoginResponse(
                outcome=LoginOutcome.ACCESS_DENIED,
                user_id=challenge.user_id,
                event_id=UUID(challenge.event_id),
                action=Action(challenge.action),
                risk_score=challenge.risk_score,
                risk_level=RiskLevel(challenge.risk_level),
                reasons=[Reason.model_validate(item) for item in challenge.reasons],
                detail=ACCESS_DENIED_DETAIL,
            )

        app = session.get(Application, challenge.application_id)
        registered_redirect = app.redirect_uri if app is not None else None
        challenge.consumed_at = now
        token = self._persist_session(
            session, challenge.user_id, challenge.application_id, now
        )
        redirect_to = self._persist_callback(
            session,
            user_id=challenge.user_id,
            application_id=challenge.application_id,
            raw_token=token.token,
            requested_redirect=redirect_uri,
            registered_redirect=registered_redirect,
        )
        return LoginResponse(
            outcome=LoginOutcome.AUTHENTICATED,
            user_id=challenge.user_id,
            event_id=UUID(challenge.event_id),
            action=Action(challenge.action),
            risk_score=challenge.risk_score,
            risk_level=RiskLevel(challenge.risk_level),
            reasons=[Reason.model_validate(item) for item in challenge.reasons],
            session=token,
            redirect_to=redirect_to,
        )

    def _load_session(self, authorization: str | None) -> tuple[IdpSession, User]:
        raw = bearer_token(authorization)
        if raw is None:
            raise HTTPException(status_code=401, detail="missing or expired session")
        now = datetime.now(timezone.utc)
        with session_scope(self._session_factory) as session:
            row = session.get(IdpSession, hash_session_token(raw))
            if row is None or _as_utc(row.expires_at) <= now:
                raise HTTPException(status_code=401, detail="missing or expired session")
            user = session.get(User, row.user_id)
            if user is None or not user.enabled:
                raise HTTPException(status_code=401, detail="missing or expired session")
            return row, user

    def require_admin(self, authorization: str | None) -> User:
        _row, user = self._load_session(authorization)
        if not user.is_admin:
            raise HTTPException(status_code=403, detail="admin required")
        return user
