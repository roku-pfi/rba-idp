"""Shared IdP test fixtures."""

from __future__ import annotations

import os

# Before rba_idp is imported: the module reads it once.
os.environ.setdefault("BCRYPT_ROUNDS", "4")

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from rba_idp.main import create_app  # noqa: E402
from tests.helpers import StubAudit, StubPdp, StubPolicy, test_settings  # noqa: E402


@pytest.fixture
def pdp() -> StubPdp:
    return StubPdp()


@pytest.fixture
def client(pdp: StubPdp) -> TestClient:
    settings = test_settings()
    app = create_app(
        settings,
        pdp_client=pdp,
        policy_client=StubPolicy(),
        audit_client=StubAudit(),
    )
    with TestClient(app) as test_client:
        yield test_client
