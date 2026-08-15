"""PDP client: POST /risk/evaluate. Identity never leaves rba-idp."""

from __future__ import annotations

from typing import Protocol

import httpx
from rba_contracts import RiskEvaluateRequest, RiskEvaluateResponse


class PdpUnavailable(Exception):
    """PDP did not return a usable decision (transport / HTTP / body)."""


class PdpClient(Protocol):
    def evaluate(self, request: RiskEvaluateRequest) -> RiskEvaluateResponse: ...


class HttpPdpClient:
    """Synchronous httpx client against rba-decision-service."""

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

    def evaluate(self, request: RiskEvaluateRequest) -> RiskEvaluateResponse:
        try:
            response = self._client.post(
                "/risk/evaluate",
                json=request.model_dump(mode="json"),
            )
            response.raise_for_status()
        except httpx.HTTPError as exc:
            raise PdpUnavailable(str(exc)) from exc
        try:
            return RiskEvaluateResponse.model_validate(response.json())
        except Exception as exc:
            raise PdpUnavailable("invalid PDP response") from exc

    def close(self) -> None:
        if self._owns_client:
            self._client.close()
