"""HTTP clients for IdP-6 control-plane reads (policy on PDP, decisions on audit)."""

from __future__ import annotations

from typing import Protocol
from uuid import UUID

import httpx
from rba_contracts import (
    Action,
    DecisionListResponse,
    DecisionRecord,
    PolicyConfig,
)


class ControlPlaneUnavailable(Exception):
    """Policy or audit HTTP call failed (transport / 5xx / invalid body)."""


class PolicyRejected(Exception):
    """PDP rejected the PolicyConfig (422)."""

    def __init__(self, detail: object) -> None:
        super().__init__("invalid policy")
        self.detail = detail


class AuditNotFound(Exception):
    """Unknown event_id on the audit store."""


class PolicyClient(Protocol):
    def get_policy(self) -> PolicyConfig: ...
    def put_policy(self, config: PolicyConfig) -> PolicyConfig: ...


class AuditClient(Protocol):
    def list_decisions(
        self,
        *,
        user_id: str | None = None,
        application_id: str | None = None,
        action: Action | None = None,
        limit: int = 50,
    ) -> DecisionListResponse: ...

    def get_decision(self, event_id: UUID) -> DecisionRecord: ...


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

    def get_policy(self) -> PolicyConfig:
        try:
            response = self._client.get("/policy")
            response.raise_for_status()
        except httpx.HTTPError as exc:
            raise ControlPlaneUnavailable(str(exc)) from exc
        try:
            return PolicyConfig.model_validate(response.json())
        except Exception as exc:
            raise ControlPlaneUnavailable("invalid policy response") from exc

    def put_policy(self, config: PolicyConfig) -> PolicyConfig:
        try:
            response = self._client.put(
                "/policy",
                json=config.model_dump(mode="json"),
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
            return PolicyConfig.model_validate(response.json())
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
        user_id: str | None = None,
        application_id: str | None = None,
        action: Action | None = None,
        limit: int = 50,
    ) -> DecisionListResponse:
        params: dict[str, str | int] = {"limit": limit}
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

    def get_decision(self, event_id: UUID) -> DecisionRecord:
        try:
            response = self._client.get(f"/decisions/{event_id}")
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
