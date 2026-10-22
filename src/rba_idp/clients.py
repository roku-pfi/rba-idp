"""HTTP clients for control-plane reads (policy on PDP, decisions on audit).

Every call names a tenant (ADR-0033). The services filter by it; the IdP's job
is to pass the operator's tenant, never one taken from the request body.
"""

from __future__ import annotations

from typing import Protocol
from uuid import UUID

import httpx
from rba_contracts import (
    Action,
    DecisionListResponse,
    DecisionRecord,
    TenantPolicy,
)


class ControlPlaneUnavailable(Exception):
    """Policy or audit HTTP call failed (transport / 5xx / invalid body)."""


class PolicyRejected(Exception):
    """PDP rejected the TenantPolicy (422)."""

    def __init__(self, detail: object) -> None:
        super().__init__("invalid policy")
        self.detail = detail


class PolicyNotFound(Exception):
    """The PDP holds no policy for this tenant (404)."""


class AuditNotFound(Exception):
    """Unknown event_id on the audit store (or another tenant's)."""


class PolicyClient(Protocol):
    def get_policy(self, tenant_id: str) -> TenantPolicy: ...
    def put_policy(self, policy: TenantPolicy) -> TenantPolicy: ...


class AuditClient(Protocol):
    def list_decisions(
        self,
        *,
        tenant_id: str,
        user_id: str | None = None,
        application_id: str | None = None,
        action: Action | None = None,
        limit: int = 50,
    ) -> DecisionListResponse: ...

    def get_decision(self, tenant_id: str, event_id: UUID) -> DecisionRecord: ...


class HttpPolicyClient:
    def __init__(
        self,
        base_url: str,
        timeout: float = 2.0,
        client: httpx.Client | None = None,
    ) -> None:
        self._owns_client = client is None
        self._client = client or httpx.Client(
            base_url=base_url.rstrip("/"),
            timeout=timeout,
        )

    def get_policy(self, tenant_id: str) -> TenantPolicy:
        try:
            response = self._client.get(f"/tenants/{tenant_id}/policy")
        except httpx.HTTPError as exc:
            raise ControlPlaneUnavailable(str(exc)) from exc
        if response.status_code == 404:
            raise PolicyNotFound(tenant_id)
        try:
            response.raise_for_status()
            return TenantPolicy.model_validate(response.json())
        except Exception as exc:
            raise ControlPlaneUnavailable("invalid policy response") from exc

    def put_policy(self, policy: TenantPolicy) -> TenantPolicy:
        try:
            response = self._client.put(
                f"/tenants/{policy.tenant_id}/policy",
                json=policy.model_dump(mode="json"),
            )
        except httpx.HTTPError as exc:
            raise ControlPlaneUnavailable(str(exc)) from exc
        if response.status_code == 422:
            try:
                detail = response.json()
            except Exception:
                detail = response.text
            raise PolicyRejected(detail)
        try:
            response.raise_for_status()
            return TenantPolicy.model_validate(response.json())
        except PolicyRejected:
            raise
        except Exception as exc:
            raise ControlPlaneUnavailable("invalid policy response") from exc

    def close(self) -> None:
        if self._owns_client:
            self._client.close()


class HttpAuditClient:
    def __init__(
        self,
        base_url: str,
        timeout: float = 2.0,
        client: httpx.Client | None = None,
    ) -> None:
        self._owns_client = client is None
        self._client = client or httpx.Client(
            base_url=base_url.rstrip("/"),
            timeout=timeout,
        )

    def list_decisions(
        self,
        *,
        tenant_id: str,
        user_id: str | None = None,
        application_id: str | None = None,
        action: Action | None = None,
        limit: int = 50,
    ) -> DecisionListResponse:
        params: dict[str, str | int] = {"tenant_id": tenant_id, "limit": limit}
        if user_id:
            params["user_id"] = user_id
        if application_id:
            params["application_id"] = application_id
        if action is not None:
            params["action"] = action.value
        try:
            response = self._client.get("/decisions", params=params)
            response.raise_for_status()
        except httpx.HTTPError as exc:
            raise ControlPlaneUnavailable(str(exc)) from exc
        try:
            return DecisionListResponse.model_validate(response.json())
        except Exception as exc:
            raise ControlPlaneUnavailable("invalid audit response") from exc

    def get_decision(self, tenant_id: str, event_id: UUID) -> DecisionRecord:
        try:
            response = self._client.get(
                f"/decisions/{event_id}", params={"tenant_id": tenant_id}
            )
        except httpx.HTTPError as exc:
            raise ControlPlaneUnavailable(str(exc)) from exc
        if response.status_code == 404:
            raise AuditNotFound(str(event_id))
        try:
            response.raise_for_status()
            return DecisionRecord.model_validate(response.json())
        except AuditNotFound:
            raise
        except Exception as exc:
            raise ControlPlaneUnavailable("invalid audit response") from exc

    def close(self) -> None:
        if self._owns_client:
            self._client.close()
