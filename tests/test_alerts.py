"""The console's alarms (RF-16): firing alerts from Prometheus, scoped to the tenant."""

from __future__ import annotations

from types import SimpleNamespace

import httpx

from rba_idp.config import Settings
from rba_idp.services.admin import AdminService

FIRING = {"data": {"alerts": [
    {"state": "firing", "labels": {"alertname": "SourceBlocked", "tenant": "roku-bank", "severity": "warning"},
     "annotations": {"summary": "Una IP quedó bloqueada"}, "activeAt": "2026-10-23T20:00:00Z"},
    {"state": "firing", "labels": {"alertname": "CredentialStuffing", "tenant": "kaze-labs", "severity": "warning"},
     "annotations": {"summary": "otra organización"}},
    {"state": "firing", "labels": {"alertname": "EngineUnavailable", "severity": "critical"},
     "annotations": {"summary": "plataforma"}},
    {"state": "pending", "labels": {"alertname": "HighBlockRate", "tenant": "roku-bank"}, "annotations": {}},
]}}


def _service(url: str) -> AdminService:
    service = AdminService.__new__(AdminService)
    service._settings = Settings(prometheus_url=url, use_memory_db=True)
    return service


def test_only_the_tenants_and_platform_alarms_firing_now(monkeypatch) -> None:
    monkeypatch.setattr(httpx, "get", lambda *a, **k: httpx.Response(200, json=FIRING, request=httpx.Request("GET", "http://p")))
    alerts = _service("http://prometheus:9090").alerts(SimpleNamespace(tenant_id="roku-bank"))
    assert [a.name for a in alerts] == ["EngineUnavailable", "SourceBlocked"]  # critical first


def test_no_prometheus_means_no_alarms_not_an_error(monkeypatch) -> None:
    def down(*a, **k):
        raise httpx.ConnectError("refused")

    monkeypatch.setattr(httpx, "get", down)
    assert _service("http://prometheus:9090").alerts(SimpleNamespace(tenant_id="roku-bank")) == []
    assert _service("").alerts(SimpleNamespace(tenant_id="roku-bank")) == []
