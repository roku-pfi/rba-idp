"""Password verify, PDP enforce, session on ALLOW, WebAuthn MFA, mock OTP for tests.

Tenancy (ADR-0033): an app login takes its tenant from the application; a
console login takes it from the operator's email domain. Either way the email
is looked up only inside that tenant, and the PDP scores under that tenant's
policy. What the IdP applies is the PDP's ``enforced_action``, never the bare
verdict (ADR-0034).
"""

from __future__ import annotations

import logging
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse
from uuid import UUID, uuid4

from fastapi import HTTPException
from rba_contracts import (
    FEATURE_SCHEMA_VERSION,
    Action,
    CallbackTokenRequest,
    CallbackTokenResponse,
    ConsoleLoginRequest,
    EngineMode,
    LoginConfirmRequest,
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
    base_action,
    outcome_from_action,
)
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker
from webauthn.helpers.exceptions import WebAuthnException

from rba_idp.authz import effective_permissions, has_application_access
from rba_idp.config import Settings
from rba_idp.db.models import (
    Application,
    AuthCode,
    GroupMembership,
    IdpSession,
    MfaChallenge,
    Tenant,
    User,
    WebAuthnCredential,
)
from rba_idp.db.session import session_scope
from rba_idp.geo import resolve_login_signals, scored_ip
from rba_idp.passwords import verify_password
from rba_idp.pdp import PdpClient, PdpUnavailable
from rba_idp.tenancy import TenantPolicyCache, tenant_for_operator_email
from rba_idp.tokens import (
    bearer_token,
    hash_session_token,
    new_session_token,
    otp_matches,
)
from rba_idp.webauthn import request_options, verify_get


logger = logging.getLogger(__name__)

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
    """True if any of the user's groups holds a role on this application.

    Sign-in is not a permission of its own (ADR-0029) — holding a role *is* the
    grant. That removes the class of bug where someone is given a role and still
    cannot log in because a separate `access` row was forgotten.
    """
    return has_application_access(session, user_id, application_id)


def _challenge_risk(challenge: MfaChallenge) -> dict:
    """The decision a challenge was opened for, as LoginResponse fields.

    A challenge opened with the engine off has no event and no score.
    """
    return {
        "event_id": UUID(challenge.event_id) if challenge.event_id else None,
        "action": Action(challenge.action),
        "risk_score": challenge.risk_score,
        "risk_level": RiskLevel(challenge.risk_level) if challenge.risk_level else None,
        "reasons": [Reason.model_validate(item) for item in challenge.reasons],
    }


@dataclass(frozen=True)
class _Attempt:
    """One credential check, whichever door it came through."""

    tenant_id: str
    application_id: str
    email: str
    password: str
    ip_address: str
    asn: str | None
    country: str | None
    device_type: str | None
    os: str | None
    browser: str | None
    user_agent: str | None
    requested_redirect: str | None
    registered_redirect: str | None
    # Console logins answer every failure with INVALID_CREDENTIALS, including
    # "no console role", so the form cannot be used to map tenants or users.
    uniform_failures: bool


class LoginService:
    def __init__(
        self,
        session_factory: sessionmaker,
        pdp: PdpClient,
        settings: Settings,
        policies: TenantPolicyCache,
    ) -> None:
        self._session_factory = session_factory
        self._pdp = pdp
        self._settings = settings
        self._policies = policies

    def login(self, body: LoginRequest) -> LoginResponse:
        """App login: the application names the tenant (ADR-0033)."""
        with session_scope(self._session_factory) as session:
            app = session.get(Application, body.application_id)
            if app is None or not app.enabled:
                raise HTTPException(status_code=400, detail="unknown application")
            tenant_id = app.tenant_id
            registered_redirect = app.redirect_uri
        return self._authenticate(
            _Attempt(
                tenant_id=tenant_id,
                application_id=body.application_id,
                email=body.email,
                password=body.password,
                ip_address=body.ip_address,
                asn=body.asn,
                country=body.country,
                device_type=body.device_type,
                os=body.os,
                browser=body.browser,
                user_agent=body.user_agent,
                requested_redirect=body.redirect_uri,
                registered_redirect=registered_redirect,
                uniform_failures=False,
            )
        )

    def console_login(self, body: ConsoleLoginRequest) -> LoginResponse:
        """Operator login: the email's domain names the tenant (ADR-0033).

        An unknown domain costs the same bcrypt as a wrong password and answers
        the same way, so ``x@kazelabs.example`` teaches Diego nothing.
        """
        with session_scope(self._session_factory) as session:
            tenant = tenant_for_operator_email(session, body.email)
            console = self._console_of(session, tenant)
            tenant_id = tenant.tenant_id if tenant is not None else None
        if tenant_id is None or console is None:
            verify_password(body.password, None)
            return LoginResponse(outcome=LoginOutcome.INVALID_CREDENTIALS)
        return self._authenticate(
            _Attempt(
                tenant_id=tenant_id,
                application_id=console,
                email=body.email,
                password=body.password,
                ip_address=body.ip_address,
                asn=body.asn,
                country=body.country,
                device_type=body.device_type,
                os=body.os,
                browser=body.browser,
                user_agent=body.user_agent,
                requested_redirect=None,
                registered_redirect=None,
                uniform_failures=True,
            )
        )

    @staticmethod
    def _console_of(session: Session, tenant: Tenant | None) -> str | None:
        if tenant is None or not tenant.console_application_id:
            return None
        app = session.get(Application, tenant.console_application_id)
        if app is None or not app.enabled or app.tenant_id != tenant.tenant_id:
            return None
        return app.application_id

    def _authenticate(self, attempt: _Attempt) -> LoginResponse:
        email = attempt.email.strip().lower()
        wrong_password_for: str | None = None
        with session_scope(self._session_factory) as session:
            user = session.scalar(
                select(User).where(
                    User.tenant_id == attempt.tenant_id, User.email == email
                )
            )
            if user is None or not user.enabled:
                verify_password(attempt.password, None)
                return LoginResponse(outcome=LoginOutcome.INVALID_CREDENTIALS)

            if not verify_password(attempt.password, user.password_hash):
                # Report it outside the DB session, then answer exactly as before.
                wrong_password_for = user.user_id
            else:
                user_id = user.user_id
                if not user_has_app_access(session, user_id, attempt.application_id):
                    if attempt.uniform_failures:
                        return LoginResponse(outcome=LoginOutcome.INVALID_CREDENTIALS)
                    return LoginResponse(
                        outcome=LoginOutcome.ACCESS_DENIED,
                        user_id=user_id,
                        detail=ACCESS_DENIED_DETAIL,
                    )

        ip = scored_ip(attempt.ip_address, private_is_home=self._settings.private_ip_is_home)
        signals = resolve_login_signals(ip, country=attempt.country, asn=attempt.asn)
        policy = self._policies.get(attempt.tenant_id)
        engine_off = policy is not None and policy.engine_mode is EngineMode.OFF

        if wrong_password_for is not None:
            if not engine_off:
                self._report_failed_login(wrong_password_for, attempt, ip, signals)
            return LoginResponse(outcome=LoginOutcome.INVALID_CREDENTIALS)

        if engine_off:
            # ADR-0034: the engine is not consulted at all. Nothing is scored
            # or recorded; the tenant's base policy decides.
            return self._enforce(
                user_id,
                attempt,
                base_action(policy.base_policy),
                decision=None,
            )

        request = RiskEvaluateRequest(
            event_id=uuid4(),
            tenant_id=attempt.tenant_id,
            application_id=attempt.application_id,
            user_id=user_id,
            timestamp=datetime.now(timezone.utc),
            ip_address=ip,
            asn=signals.asn,
            country=signals.country,
            device_type=attempt.device_type,
            os=attempt.os,
            browser=attempt.browser,
            login_successful=True,
            user_agent=attempt.user_agent,
            simulated=signals.simulated,
        )
        try:
            decision = self._pdp.evaluate(request)
        except PdpUnavailable as exc:
            logger.warning(
                "PDP unavailable, degrading to %s for tenant_id=%s user_id=%s: %s",
                self._settings.pdp_unavailable_action,
                attempt.tenant_id,
                user_id,
                exc,
            )
            decision = self._degraded_decision(
                request.event_id,
                policy.engine_mode if policy is not None else EngineMode.ACTIVE,
            )

        return self._enforce(user_id, attempt, decision.enforced_action, decision=decision)

    def _degraded_decision(
        self, event_id: UUID, engine_mode: EngineMode
    ) -> RiskEvaluateResponse:
        """Stand in for the PDP when it does not answer at all (RF-10 / RNF-03).

        The PDP degrades to ``fallback_action`` when *its own* dependencies fail.
        This is the case one level up: the PDP itself is unreachable, so there is
        no score, no policy and no reasons to be had. Refusing the login would
        lock out every legitimate user for the length of the outage; allowing it
        would drop the control entirely. Both are named in RNF-03 as the wrong
        answers, so we ask for a step-up instead.

        ``fallback=True`` marks ``risk_score`` as non-informative — the number is
        a placeholder, not a measurement — and is what the admin decision browser
        keys on to show the login was not scored.

        Note this decision is *not* written to the decision store: the store
        lives behind the service that just failed to answer. It survives in the
        IdP log and, when a challenge is issued, on the challenge row. The
        step-up is enforced whatever the tenant's engine mode: monitor mode
        would mean "apply the base policy", and the base policy cannot be read
        from a PDP that is not answering — a step-up is never weaker than it.
        """
        action = Action(self._settings.pdp_unavailable_action)
        return RiskEvaluateResponse(
            event_id=event_id,
            risk_score=0.0,
            risk_level=RiskLevel.HIGH,
            action=action,
            enforced_action=action,
            engine_mode=engine_mode,
            reasons=[
                Reason(
                    code="pdp_unavailable",
                    signal="system",
                    detail=(
                        "risk engine did not respond; degraded to "
                        f"{action.value} without a score"
                    ),
                )
            ],
            model_version="unavailable",
            policy_version="unavailable",
            feature_schema_version=FEATURE_SCHEMA_VERSION,
            fallback=True,
            scored_at=datetime.now(timezone.utc),
        )

    def _report_failed_login(
        self,
        user_id: str,
        attempt: _Attempt,
        ip: str,
        signals,
    ) -> None:
        """Tell the PDP about a wrong password (ADR-0027). Best effort, never enforcing.

        Without this the PDP only ever sees successes, so `failed_logins_last_24h`
        is structurally 0 and credential stuffing is invisible to the decision —
        the threat the project leads with. The returned decision is *discarded*:
        a failed attempt is not an authentication, so there is nothing to enforce.
        The recording is what matters, and it reaches the profile through the
        normal journal → profile-service path (ADR-0044).

        A PDP outage must not turn a wrong password into a 503, so failures here
        are swallowed. That is the opposite of the enforcing call above, which
        fails closed on purpose.
        """
        if not self._settings.report_failed_logins:
            return
        try:
            self._pdp.evaluate(
                RiskEvaluateRequest(
                    event_id=uuid4(),
                    tenant_id=attempt.tenant_id,
                    application_id=attempt.application_id,
                    user_id=user_id,
                    timestamp=datetime.now(timezone.utc),
                    ip_address=ip,
                    asn=signals.asn,
                    country=signals.country,
                    device_type=attempt.device_type,
                    os=attempt.os,
                    browser=attempt.browser,
                    login_successful=False,
                    user_agent=attempt.user_agent,
                    simulated=signals.simulated,
                )
            )
        except Exception:
            logger.warning("failed-login report dropped for user_id=%s", user_id)

    def _confirm_step_up(self, result: LoginResponse, tenant_id: str | None) -> None:
        """Tell the PDP the step-up was passed, so the profile learns this login.

        ADR-0042: the profile learns a challenged login only once it is
        completed. Best effort, after the session is committed: the user is
        already in, and a missed confirmation only means one login is not
        learned, which the next usual login makes up for.
        """
        if (
            result.outcome is not LoginOutcome.AUTHENTICATED
            or result.event_id is None
            or tenant_id is None
        ):
            return
        try:
            self._pdp.confirm(LoginConfirmRequest(event_id=result.event_id, tenant_id=tenant_id))
        except Exception:
            logger.warning("step-up confirmation dropped for event_id=%s", result.event_id)

    def verify_mfa(self, body: MfaVerifyRequest) -> LoginResponse:
        if not self._settings.mock_otp_enabled:
            # A fixed code that passes any step-up must not exist in a deployment.
            raise HTTPException(status_code=404, detail="not found")
        now = datetime.now(timezone.utc)
        with session_scope(self._session_factory) as session:
            challenge = self._open_challenge(session, body.challenge_id, now)
            if not otp_matches(body.code, self._settings.mock_otp_code):
                return LoginResponse(outcome=LoginOutcome.INVALID_CREDENTIALS)
            result = self._finish_challenge(
                session, challenge, now, redirect_uri=body.redirect_uri
            )
            app = session.get(Application, challenge.application_id)
            tenant_id = app.tenant_id if app is not None else None
        self._confirm_step_up(result, tenant_id)
        return result

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
            if not cred_ids:
                # ADR-0037: a step-up is never turned into an enrollment. The
                # login path already refuses such challenges; this covers a
                # passkey removed while the challenge was open.
                raise HTTPException(status_code=400, detail="no passkey for this user")
            mode = WebAuthnCeremonyMode.GET
            nonce, public_key = request_options(self._settings, cred_ids)
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
            if challenge.webauthn_mode != WebAuthnCeremonyMode.GET.value:
                raise HTTPException(
                    status_code=400, detail="unknown or expired challenge"
                )
            try:
                cred_id = body.credential.get("id")
                if not isinstance(cred_id, str):
                    return LoginResponse(outcome=LoginOutcome.INVALID_CREDENTIALS)
                stored = session.get(WebAuthnCredential, cred_id)
                if stored is None or stored.user_id != challenge.user_id:
                    return LoginResponse(outcome=LoginOutcome.INVALID_CREDENTIALS)
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
            result = self._finish_challenge(
                session, challenge, now, redirect_uri=body.redirect_uri
            )
            app = session.get(Application, challenge.application_id)
            tenant_id = app.tenant_id if app is not None else None
        self._confirm_step_up(result, tenant_id)
        return result

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
                    tenant_id=user.tenant_id,
                    user_id=user.user_id,
                    email=user.email,
                    created_at=_as_utc(user.created_at),
                    is_admin=bool(user.is_admin),
                ),
            )

    def get_session(self, authorization: str | None) -> SessionResponse:
        row, user, permissions = self.load_session(authorization)
        return SessionResponse(
            user=UserPublic(
                tenant_id=user.tenant_id,
                user_id=user.user_id,
                email=user.email,
                created_at=_as_utc(user.created_at),
                is_admin=bool(user.is_admin),
            ),
            expires_at=_as_utc(row.expires_at),
            application_id=row.application_id,
            permissions=sorted(permissions),
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
        attempt: _Attempt,
        action: Action,
        *,
        decision: RiskEvaluateResponse | None,
    ) -> LoginResponse:
        """Apply ``action`` — the PDP's ``enforced_action``, or the base policy
        when the engine is off (``decision`` is then ``None``)."""
        session_token: SessionToken | None = None
        challenge_id: UUID | None = None
        redirect_to: str | None = None
        passkey_offer = False
        if action == Action.ALLOW:
            # ADR-0037: only a login the engine itself judged usual is a
            # trusted context to enroll from — not a monitor-mode ALLOW of a
            # risky verdict, not a fallback, not an engine that is off.
            passkey_offer = (
                decision is not None
                and decision.action == Action.ALLOW
                and not decision.fallback
                and not self._has_passkey(user_id)
            )
            session_token, redirect_to = self._create_session_with_callback(
                user_id,
                attempt.application_id,
                requested_redirect=attempt.requested_redirect,
                registered_redirect=attempt.registered_redirect,
                may_enroll=passkey_offer,
            )
        elif action in (Action.REQUIRE_MFA, Action.REAUTHENTICATE):
            if not self._has_second_factor(user_id):
                # ADR-0037: never an enrollment. The PDP has already recorded
                # its verdict; the refusal is kept on the challenge row.
                self._create_challenge(
                    user_id, attempt.application_id, action, decision,
                    denied_reason="no_second_factor",
                )
                logger.warning(
                    "step-up denied: no_second_factor tenant_id=%s user_id=%s",
                    attempt.tenant_id,
                    user_id,
                )
                return LoginResponse(
                    outcome=LoginOutcome.SECOND_FACTOR_MISSING,
                    user_id=user_id,
                    event_id=decision.event_id if decision is not None else None,
                    action=action,
                )
            challenge_id = self._create_challenge(
                user_id, attempt.application_id, action, decision
            )

        return LoginResponse(
            outcome=outcome_from_action(action),
            user_id=user_id,
            event_id=decision.event_id if decision is not None else None,
            action=action,
            risk_score=decision.risk_score if decision is not None else None,
            risk_level=decision.risk_level if decision is not None else None,
            reasons=decision.reasons if decision is not None else [],
            session=session_token,
            challenge_id=challenge_id,
            redirect_to=redirect_to,
            passkey_offer=passkey_offer,
        )

    def _has_passkey(self, user_id: str) -> bool:
        with session_scope(self._session_factory) as session:
            return (
                session.scalar(
                    select(WebAuthnCredential.credential_id)
                    .where(WebAuthnCredential.user_id == user_id)
                    .limit(1)
                )
                is not None
            )

    def _has_second_factor(self, user_id: str) -> bool:
        """A passkey — or, in the test suite only, the mock OTP."""
        return self._settings.mock_otp_enabled or self._has_passkey(user_id)

    def _create_session_with_callback(
        self,
        user_id: str,
        application_id: str,
        *,
        requested_redirect: str | None,
        registered_redirect: str | None,
        may_enroll: bool = False,
    ) -> tuple[SessionToken, str | None]:
        now = datetime.now(timezone.utc)
        with session_scope(self._session_factory) as session:
            token = self._persist_session(
                session, user_id, application_id, now, may_enroll=may_enroll
            )
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
        *,
        may_enroll: bool = False,
    ) -> SessionToken:
        raw = new_session_token()
        expires_at = now + timedelta(seconds=self._settings.session_ttl_seconds)
        user = session.get(User, user_id)
        if user is not None:
            user.last_login_at = now
        session.add(
            IdpSession(
                token_hash=hash_session_token(raw),
                user_id=user_id,
                application_id=application_id,
                expires_at=expires_at,
                enroll_until=now + timedelta(seconds=self._settings.enroll_window_seconds)
                if may_enroll
                else None,
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
        action: Action,
        decision: RiskEvaluateResponse | None,
        *,
        denied_reason: str | None = None,
    ) -> UUID:
        challenge_id = uuid4()
        now = datetime.now(timezone.utc)
        with session_scope(self._session_factory) as session:
            session.add(
                MfaChallenge(
                    challenge_id=str(challenge_id),
                    user_id=user_id,
                    application_id=application_id,
                    event_id=str(decision.event_id) if decision is not None else None,
                    action=action.value,
                    risk_score=decision.risk_score if decision is not None else None,
                    risk_level=decision.risk_level.value if decision is not None else None,
                    reasons=[item.model_dump(mode="json") for item in decision.reasons]
                    if decision is not None
                    else [],
                    expires_at=now
                    + timedelta(seconds=self._settings.challenge_ttl_seconds),
                    denied_reason=denied_reason,
                    consumed_at=now if denied_reason else None,
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
                **_challenge_risk(challenge),
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
            **_challenge_risk(challenge),
            session=token,
            redirect_to=redirect_to,
        )

    def load_session(
        self, authorization: str | None
    ) -> tuple[IdpSession, User, set[str]]:
        """Resolve a bearer token to (session, user, effective permissions).

        Permissions are read inside the same transaction as the session, so a
        role revoked a moment ago cannot be used by a token issued before it.
        """
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
            permissions = effective_permissions(session, user.user_id, row.application_id)
            return row, user, permissions
