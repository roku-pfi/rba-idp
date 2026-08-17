"""Demo-4: WebAuthn passkey for REQUIRE_MFA. Mock OTP stays on /mfa/verify."""

from __future__ import annotations

import hashlib
import json
import secrets
import struct

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient
from rba_contracts import Action, LoginOutcome, RiskLevel
from webauthn.helpers import bytes_to_base64url

from tests.helpers import LOGIN, REASON, StubPdp, client_for

RP_ID = "testserver"
ORIGIN = "http://testserver"


class SoftPasskey:
    """Software platform authenticator for tests (ES256, none attestation)."""

    def __init__(self, *, rp_id: str = RP_ID, origin: str = ORIGIN) -> None:
        self.rp_id = rp_id
        self.origin = origin
        self._private = ec.generate_private_key(ec.SECP256R1())
        nums = self._private.public_key().public_numbers()
        self._x = nums.x.to_bytes(32, "big")
        self._y = nums.y.to_bytes(32, "big")
        self.credential_id = secrets.token_bytes(32)
        self.sign_count = 0

    def _client_data(self, typ: str, challenge: bytes) -> bytes:
        return json.dumps(
            {
                "type": typ,
                "challenge": bytes_to_base64url(challenge),
                "origin": self.origin,
                "crossOrigin": False,
            },
            separators=(",", ":"),
        ).encode()

    def _auth_data(self, *, attested: bool) -> bytes:
        flags = 0x01 | 0x04  # UP | UV
        if attested:
            flags |= 0x40  # AT
        body = (
            hashlib.sha256(self.rp_id.encode()).digest()
            + bytes([flags])
            + struct.pack(">I", self.sign_count)
        )
        if attested:
            cose = cbor2.dumps({1: 2, 3: -7, -1: 1, -2: self._x, -3: self._y})
            body += (
                bytes(16)
                + struct.pack(">H", len(self.credential_id))
                + self.credential_id
                + cose
            )
        return body

    def create(self, challenge_b64url: str) -> dict:
        from webauthn.helpers import base64url_to_bytes

        challenge = base64url_to_bytes(challenge_b64url)
        self.sign_count = 0
        client = self._client_data("webauthn.create", challenge)
        auth = self._auth_data(attested=True)
        att = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth})
        cid = bytes_to_base64url(self.credential_id)
        return {
            "id": cid,
            "rawId": cid,
            "type": "public-key",
            "authenticatorAttachment": "platform",
            "response": {
                "clientDataJSON": bytes_to_base64url(client),
                "attestationObject": bytes_to_base64url(att),
                "transports": ["internal"],
            },
        }

    def get(self, challenge_b64url: str) -> dict:
        from webauthn.helpers import base64url_to_bytes

        challenge = base64url_to_bytes(challenge_b64url)
        self.sign_count += 1
        client = self._client_data("webauthn.get", challenge)
        auth = self._auth_data(attested=False)
        signed = auth + hashlib.sha256(client).digest()
        sig = self._private.sign(signed, ec.ECDSA(hashes.SHA256()))
        cid = bytes_to_base64url(self.credential_id)
        return {
            "id": cid,
            "rawId": cid,
            "type": "public-key",
            "authenticatorAttachment": "platform",
            "response": {
                "clientDataJSON": bytes_to_base64url(client),
                "authenticatorData": bytes_to_base64url(auth),
                "signature": bytes_to_base64url(sig),
                "userHandle": bytes_to_base64url(b"usr_demo"),
            },
        }


def test_webauthn_create_issues_session_without_rescoring() -> None:
    pdp = StubPdp(
        action=Action.REQUIRE_MFA, risk_score=0.61, risk_level=RiskLevel.MEDIUM
    )
    passkey = SoftPasskey()
    with client_for(pdp) as client:
        challenge_id = client.post("/login", json=LOGIN).json()["challenge_id"]
        opts = client.post(
            "/mfa/webauthn/options", json={"challenge_id": challenge_id}
        ).json()
        assert opts["mode"] == "create"
        assert opts["public_key"]["rp"]["id"] == RP_ID
        assert len(pdp.calls) == 1

        resp = client.post(
            "/mfa/webauthn/verify",
            json={
                "challenge_id": challenge_id,
                "credential": passkey.create(opts["public_key"]["challenge"]),
            },
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["outcome"] == LoginOutcome.AUTHENTICATED.value
        assert body["action"] == Action.REQUIRE_MFA.value
        assert body["risk_score"] == 0.61
        assert body["reasons"] == [REASON.model_dump(mode="json")]
        token = body["session"]["token"]
        assert client.get(
            "/session", headers={"Authorization": f"Bearer {token}"}
        ).status_code == 200
        assert len(pdp.calls) == 1


def test_webauthn_get_uses_stored_passkey() -> None:
    pdp = StubPdp(
        action=Action.REQUIRE_MFA, risk_score=0.61, risk_level=RiskLevel.MEDIUM
    )
    passkey = SoftPasskey()
    with client_for(pdp) as client:
        first = client.post("/login", json=LOGIN).json()["challenge_id"]
        create_opts = client.post(
            "/mfa/webauthn/options", json={"challenge_id": first}
        ).json()
        created = client.post(
            "/mfa/webauthn/verify",
            json={
                "challenge_id": first,
                "credential": passkey.create(create_opts["public_key"]["challenge"]),
            },
        )
        assert created.status_code == 200
        client.post(
            "/logout",
            headers={"Authorization": f"Bearer {created.json()['session']['token']}"},
        )

        second = client.post("/login", json=LOGIN).json()["challenge_id"]
        get_opts = client.post(
            "/mfa/webauthn/options", json={"challenge_id": second}
        ).json()
        assert get_opts["mode"] == "get"
        resp = client.post(
            "/mfa/webauthn/verify",
            json={
                "challenge_id": second,
                "credential": passkey.get(get_opts["public_key"]["challenge"]),
            },
        )
        assert resp.status_code == 200
        assert resp.json()["outcome"] == LoginOutcome.AUTHENTICATED.value
        assert len(pdp.calls) == 2


def test_webauthn_bad_assertion_keeps_challenge_open() -> None:
    pdp = StubPdp(
        action=Action.REQUIRE_MFA, risk_score=0.61, risk_level=RiskLevel.MEDIUM
    )
    with client_for(pdp) as client:
        challenge_id = client.post("/login", json=LOGIN).json()["challenge_id"]
        client.post("/mfa/webauthn/options", json={"challenge_id": challenge_id})
        bad = client.post(
            "/mfa/webauthn/verify",
            json={
                "challenge_id": challenge_id,
                "credential": {
                    "id": "not-a-credential",
                    "rawId": "not-a-credential",
                    "type": "public-key",
                    "response": {
                        "clientDataJSON": "e30",
                        "authenticatorData": "AA",
                        "signature": "AA",
                    },
                },
            },
        )
        assert bad.status_code == 200
        assert bad.json() == {"outcome": LoginOutcome.INVALID_CREDENTIALS.value}
        retry = client.post(
            "/mfa/verify",
            json={"challenge_id": challenge_id, "code": "000000"},
        )
        assert retry.status_code == 200
        assert retry.json()["outcome"] == LoginOutcome.AUTHENTICATED.value
        assert len(pdp.calls) == 1


def test_webauthn_verify_without_options_is_400() -> None:
    pdp = StubPdp(action=Action.REQUIRE_MFA, risk_score=0.61, risk_level=RiskLevel.MEDIUM)
    with client_for(pdp) as client:
        challenge_id = client.post("/login", json=LOGIN).json()["challenge_id"]
        resp = client.post(
            "/mfa/webauthn/verify",
            json={
                "challenge_id": challenge_id,
                "credential": {"id": "x", "rawId": "x", "type": "public-key", "response": {}},
            },
        )
        assert resp.status_code == 400


def test_webauthn_unknown_challenge_is_400(client: TestClient) -> None:
    resp = client.post(
        "/mfa/webauthn/options",
        json={"challenge_id": "7c2e1b3d-4a6f-9c8e-2d1b-3a6f9c8e4f9a"},
    )
    assert resp.status_code == 400
    assert resp.json()["detail"] == "unknown or expired challenge"
