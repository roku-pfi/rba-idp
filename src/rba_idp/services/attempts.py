"""Tell the owner when someone got their password right and was stopped.

The engine stops an attacker who has the password: a step-up they cannot
pass, or a refusal. The attacker is kept out, but the password is known to
someone, and only its owner can change it. So the owner is told on their next
sign-in, once, with where, when and from what device, and offered a password
change.

A step-up counts only once it is clearly not the owner's: if the passkey is
then passed the row is removed (it was them), and an open one is not shown
for a minute (GRACE_SECONDS) while its challenge is still open. "Passkey siempre" step-ups are not recorded:
they say nothing about who typed the password. Nor is anything shown to a
user without a passkey: the change it leads to needs one.
"""

from __future__ import annotations

from datetime import datetime, timezone

from rba_contracts import StoppedAttempt
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from rba_idp.db.models import MfaChallenge, StoppedAttemptRow, WebAuthnCredential


def _utc(dt: datetime) -> datetime:
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


def record(
    session: Session,
    *,
    user_id: str,
    country: str | None,
    stopped_by: str,
    challenge_id: str | None = None,
    now: datetime | None = None,
    ip_address: str | None = None,
    device_type: str | None = None,
    os: str | None = None,
    browser: str | None = None,
) -> None:
    session.add(
        StoppedAttemptRow(
            user_id=user_id,
            occurred_at=now or datetime.now(timezone.utc),
            country=(country or None) and country[:2].upper(),
            stopped_by=stopped_by,
            challenge_id=challenge_id,
            ip_address=(ip_address or None) and ip_address[:64],
            device_type=(device_type or None) and device_type[:16],
            os=(os or None) and os[:64],
            browser=(browser or None) and browser[:64],
        )
    )


def passed(session: Session, challenge_id: str) -> None:
    """The step-up was passed: whoever typed the password holds the passkey."""
    session.execute(delete(StoppedAttemptRow).where(StoppedAttemptRow.challenge_id == challenge_id))


# A step-up left unanswered this long is not the owner finishing on another
# device: a passkey prompt takes seconds. Refusals are shown at once.
GRACE_SECONDS = 60


def _visible(session: Session, user_id: str, now: datetime) -> list[StoppedAttemptRow]:
    # The notice leads to a password change, which needs the passkey. A
    # customer without one has not finished their first sign-in: nothing to show.
    if session.scalar(select(WebAuthnCredential.credential_id).where(WebAuthnCredential.user_id == user_id).limit(1)) is None:
        return []
    rows = session.scalars(
        select(StoppedAttemptRow)
        .where(StoppedAttemptRow.user_id == user_id, StoppedAttemptRow.shown_at.is_(None))
        .order_by(StoppedAttemptRow.occurred_at.desc())
    ).all()
    out = []
    for row in rows:
        if row.challenge_id is not None:
            challenge = session.get(MfaChallenge, row.challenge_id)
            still_open = challenge is not None and challenge.consumed_at is None and _utc(challenge.expires_at) > now
            if still_open and (now - _utc(row.occurred_at)).total_seconds() < GRACE_SECONDS:
                continue
        out.append(row)
    return out


def _public(row: StoppedAttemptRow) -> StoppedAttempt:
    return StoppedAttempt(
        occurred_at=_utc(row.occurred_at),
        country=row.country,
        stopped_by=row.stopped_by,  # type: ignore[arg-type]
        ip_address=row.ip_address,
        device_type=row.device_type,
        os=row.os,
        browser=row.browser,
    )


def unseen(session: Session, user_id: str, now: datetime) -> list[StoppedAttempt]:
    """What a signed-in app shows in its banner; stays until dismissed."""
    return [_public(row) for row in _visible(session, user_id, now)]


def mark_seen(session: Session, user_id: str, up_to: datetime, now: datetime) -> None:
    """Dismissed up to ``up_to`` (the newest the person saw; later ones stay)."""
    for row in _visible(session, user_id, now):
        if _utc(row.occurred_at) <= _utc(up_to):
            row.shown_at = now


def take_unseen(session: Session, user_id: str, now: datetime) -> list[StoppedAttempt]:
    """On sign-in: the attempts not yet told, marked as told (shown once)."""
    rows = _visible(session, user_id, now)
    for row in rows:
        row.shown_at = now
    return [_public(row) for row in rows]
