"""Tenant resolution and the login path's view of tenant policy (ADR-0033/0034).

Two questions the IdP has to answer before it can score a login:

- *Which tenant?* From the application for an app login, from the email's
  domain for a console login. Never from anything the user chooses.
- *Is the engine on?* A tenant in ``OFF`` is never sent to the PDP. The IdP
  learns the mode by reading the tenant's policy, cached for a few seconds so a
  login does not cost two PDP round trips.
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable

from rba_contracts import TenantPolicy
from sqlalchemy.orm import Session

from rba_idp.clients import ControlPlaneUnavailable, PolicyClient, PolicyNotFound
from rba_idp.db.models import Tenant, TenantDomain

logger = logging.getLogger(__name__)


def email_domain(email: str) -> str:
    """``"Diego@RokuBank.example"`` → ``"rokubank.example"``; ``""`` if malformed."""
    local, at, domain = email.strip().lower().rpartition("@")
    if not at or not local:
        return ""
    return domain


def tenant_for_operator_email(session: Session, email: str) -> Tenant | None:
    """Home realm discovery: the tenant that registered this email's domain."""
    domain = email_domain(email)
    if not domain:
        return None
    row = session.get(TenantDomain, domain)
    if row is None:
        return None
    return session.get(Tenant, row.tenant_id)


class TenantPolicyCache:
    """Per-tenant policy, re-read from the PDP at most every ``ttl`` seconds.

    The PDP stays the owner of policy; this is only a read-through cache so the
    IdP can skip the PDP for ``OFF`` tenants. A failed read returns the last
    known policy if there is one, else ``None`` — the caller then calls the PDP
    anyway, and the PDP-unavailable path decides.
    """

    def __init__(
        self,
        client: PolicyClient,
        ttl: float = 5.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._client = client
        self._ttl = ttl
        self._clock = clock
        self._lock = threading.Lock()
        self._entries: dict[str, tuple[float, TenantPolicy]] = {}

    def get(self, tenant_id: str) -> TenantPolicy | None:
        now = self._clock()
        with self._lock:
            entry = self._entries.get(tenant_id)
        if entry is not None and now - entry[0] < self._ttl:
            return entry[1]
        try:
            policy = self._client.get_policy(tenant_id)
        except (ControlPlaneUnavailable, PolicyNotFound) as exc:
            logger.warning("policy read failed for tenant_id=%s: %s", tenant_id, exc)
            return entry[1] if entry is not None else None
        with self._lock:
            self._entries[tenant_id] = (now, policy)
        return policy

    def invalidate(self, tenant_id: str) -> None:
        """Forget a tenant's policy, e.g. right after this IdP saved a new one."""
        with self._lock:
            self._entries.pop(tenant_id, None)
