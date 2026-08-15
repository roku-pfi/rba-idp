"""Password verify, PDP enforce, session on ALLOW, mock MFA/reauth (IdP-4)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

from fastapi import HTTPException
from rba_contracts import (
    Action,
    LoginOutcome,
    LoginRequest,
    LoginResponse,
    MfaVerifyRequest,
    Reason,
    RiskEvaluateRequest,
    RiskEvaluateResponse,
    RiskLevel,
    SessionResponse,
    SessionToken,
    UserPublic,
    outcome_from_action,
)
from sqlalchemy import select
from sqlalchemy.orm import sessionmaker

from rba_idp.config import Settings
from rba_idp.db.models import Application, IdpSession, MfaChallenge, User
from rba_idp.db.session import session_scope
from rba_idp.passwords import verify_password
from rba_idp.pdp import PdpClient, PdpUnavailable
from rba_idp.tokens import (
    bearer_token,
    hash_session_token,
    new_session_token,
    otp_matches,
)


def _as_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


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

            user = session.scalar(select(User).where(User.email == email))
            if user is None or not user.enabled:
                verify_password(body.password, None)
                return LoginResponse(outcome=LoginOutcome.INVALID_CREDENTIALS)

            if not verify_password(body.password, user.password_hash):
                return LoginResponse(outcome=LoginOutcome.INVALID_CREDENTIALS)

            user_id = user.user_id

        request = RiskEvaluateRequest(
            event_id=uuid4(),
            application_id=body.application_id,
            user_id=user_id,
            timestamp=datetime.now(timezone.utc),
            ip_address=body.ip_address,
            asn=body.asn,
            country=body.country,
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

        return self._enforce(user_id, body.application_id, decision)

    def verify_mfa(self, body: MfaVerifyRequest) -> LoginResponse:
        now = datetime.now(timezone.utc)
        with session_scope(self._session_factory) as session:
            challenge = session.get(MfaChallenge, str(body.challenge_id))
            if (
                challenge is None
                or challenge.consumed_at is not None
                or _as_utc(challenge.expires_at) <= now
            ):
                raise HTTPException(
                    status_code=400, detail="unknown or expired challenge"
                )

            if not otp_matches(body.code, self._settings.mock_otp_code):
                return LoginResponse(outcome=LoginOutcome.INVALID_CREDENTIALS)

            challenge.consumed_at = now
            token = self._persist_session(
                session, challenge.user_id, challenge.application_id, now
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
            )

    def get_session(self, authorization: str | None) -> SessionResponse:
        row, user = self._load_session(authorization)
        return SessionResponse(
            user=UserPublic(
                user_id=user.user_id,
                email=user.email,
                created_at=_as_utc(user.created_at),
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
    ) -> LoginResponse:
        session_token: SessionToken | None = None
        challenge_id: UUID | None = None
        if decision.action == Action.ALLOW:
            session_token = self._create_session(user_id, application_id)
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
        )

    def _create_session(self, user_id: str, application_id: str) -> SessionToken:
        now = datetime.now(timezone.utc)
        with session_scope(self._session_factory) as session:
            return self._persist_session(session, user_id, application_id, now)

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
