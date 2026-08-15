"""Shared IdP test fixtures."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from rba_idp.config import Settings
from rba_idp.main import create_app
from tests.helpers import StubAudit, StubPdp, StubPolicy


@pytest.fixture
def pdp() -> StubPdp:
    return StubPdp()


@pytest.fixture
def client(pdp: StubPdp) -> TestClient:
    settings = Settings(use_memory_db=True)
    app = create_app(
        settings,
        pdp_client=pdp,
        policy_client=StubPolicy(),
        audit_client=StubAudit(),
    )
    with TestClient(app) as test_client:
        yield test_client
