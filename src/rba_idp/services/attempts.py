"""Tell the owner when someone got their password right and was stopped.

The engine stops an attacker who has the password: a step-up they cannot
pass, or a refusal. The attacker is kept out, but the password is known to
someone, and only its owner can change it. So the owner is told on their next
sign-in, once, with where and when, and offered a password change.

A step-up counts only once it is clearly not the owner's: if the passkey is
then passed the row is removed (it was them), and an open one is not shown
until its challenge has expired. "Passkey siempre" step-ups are not recorded:
they say nothing about who typed the password.
"""

from __future__ import annotations

from datetime import datetime, timezone

from rba_contracts import StoppedAttempt
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from rba_idp.db.models import MfaChallenge, StoppedAttemptRow


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
) -> None:
    session.add(
        StoppedAttemptRow(
            user_id=user_id,
            occurred_at=now or datetime.now(timezone.utc),
            country=(country or None) and country[:2].upper(),
            stopped_by=stopped_by,
            challenge_id=challenge_id,
        )
    )


def passed(session: Session, challenge_id: str) -> None:
    """The step-up was passed: whoever typed the password holds the passkey."""
    session.execute(delete(StoppedAttemptRow).where(StoppedAttemptRow.challenge_id == challenge_id))


def take_unseen(session: Session, user_id: str, now: datetime) -> list[StoppedAttempt]:
    """The attempts the owner has not been told about, marked as told."""
    rows = session.scalars(
        select(StoppedAttemptRow)
        .where(StoppedAttemptRow.user_id == user_id, StoppedAttemptRow.shown_at.is_(None))
        .order_by(StoppedAttemptRow.occurred_at.desc())
    ).all()
    out: list[StoppedAttempt] = []
    for row in rows:
        if row.challenge_id is not None:
            challenge = session.get(MfaChallenge, row.challenge_id)
            # Still open: it may be the owner, on another tab or device.
            if challenge is not None and challenge.consumed_at is None and _utc(challenge.expires_at) > now:
                continue
        row.shown_at = now
        out.append(
            StoppedAttempt(
                occurred_at=_utc(row.occurred_at),
                country=row.country,
                stopped_by=row.stopped_by,  # type: ignore[arg-type]
            )
        )
    return out
