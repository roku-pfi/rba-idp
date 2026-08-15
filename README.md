# rba-idp

Thesis-scale **IdP** (Authentik/Auth0-shaped shell). The thesis core is RBA
(`rba-decision-service`); this service is the PEP that calls it.

**IdP-4 (this slice):** after password verify + PDP, issue a session on `ALLOW`
or a mock-OTP challenge on MFA/REAUTH. `BLOCK` stays rejected. No hosted UI.

## Request path (IdP-4)

```
client → POST /login
           → lookup application (rba_idp)
           → verify password (bcrypt)
           → POST /risk/evaluate (rba-decision-service)
           → ALLOW  → session token
           → MFA / REAUTH → challenge_id (POST /mfa/verify with 000000)
           → BLOCK → rejected (no session)
```

| PDP action | Login outcome | What the IdP issues |
|---|---|---|
| `ALLOW` | `AUTHENTICATED` | `session.token` (Bearer) |
| `REQUIRE_MFA` | `MFA_REQUIRED` | `challenge_id` |
| `REAUTHENTICATE` | `REAUTH_REQUIRED` | `challenge_id` |
| `BLOCK` | `BLOCKED` | nothing |

Wrong password / unknown user → `INVALID_CREDENTIALS` (HTTP 200, **no** PDP
call). Unknown `application_id` → HTTP 400. PDP down / invalid response →
HTTP 503 (fail closed; not a fake `BLOCK`).

Mock OTP is always `000000` (thesis stand-in, not TOTP/WebAuthn). Wrong code →
`INVALID_CREDENTIALS` (challenge stays open until expiry). Success → session,
same `LoginResponse` shape. `GET /session` with `Authorization: Bearer …`.
`POST /logout` returns 204 (idempotent).

Contracts: `rba-contracts` v0.2.0. Session tokens are opaque and stored
hashed. No HTML UI (IdP-5).

## Setup

```bash
# Shared Postgres (and Redis for the PDP) live in rba-infra:
cd ../rba-infra && docker compose up -d && cd -

# from this repo
python3.12 -m venv .venv && source .venv/bin/activate
pip install -U pip
pip install -e ../rba-contracts -e ".[dev]"

pytest -q

# PDP (separate terminal, from rba-decision-service):
# uvicorn rba_decision_service.main:app --reload --port 8000

DATABASE_URL=postgresql+psycopg://rba:rba@localhost:5432/rba_idp \
PDP_BASE_URL=http://localhost:8000 \
uvicorn rba_idp.main:app --reload --port 8001
```

If Postgres was already initialized before `rba_idp` existed:

```bash
docker compose -f ../rba-infra/docker-compose.yml exec postgres \
  psql -U rba -d postgres -c "CREATE DATABASE rba_idp;"
```

## Seeded identity

| | |
|---|---|
| Application | `demo-banking-app` (Demo banking app) |
| User | `demo@example.com` / `demo-password` (`usr_demo`) |
| Mock OTP | `000000` |

Matches `rba-contracts` IdP login examples. Password is hashed with bcrypt at
seed time; it is never stored, echoed, or sent to the PDP.

## Example

```bash
# ALLOW (typical low-risk) → session token
TOKEN=$(curl -s localhost:8001/login -H 'content-type: application/json' -d '{
  "email": "demo@example.com",
  "password": "demo-password",
  "application_id": "demo-banking-app",
  "ip_address": "203.0.113.10",
  "asn": "13335",
  "country": "AR",
  "device_type": "mobile",
  "os": "Android",
  "browser": "Chrome"
}' | python3 -c 'import json,sys; print(json.load(sys.stdin)["session"]["token"])')

curl -s localhost:8001/session -H "Authorization: Bearer $TOKEN"
curl -s -o /dev/null -w '%{http_code}\n' -X POST localhost:8001/logout \
  -H "Authorization: Bearer $TOKEN"
```

MFA path: login returns `challenge_id`; then

```bash
curl -s localhost:8001/mfa/verify -H 'content-type: application/json' -d '{
  "challenge_id": "<from login>",
  "code": "000000"
}'
```

Wrong password / unknown user: `{"outcome":"INVALID_CREDENTIALS"}` (HTTP 200).

## Env

| Variable | Default | Notes |
|---|---|---|
| `DATABASE_URL` | `postgresql+psycopg://rba:rba@localhost:5432/rba_idp` | DB created by `rba-infra` init |
| `USE_MEMORY_DB` | `false` | sqlite StaticPool for tests |
| `PDP_BASE_URL` | `http://localhost:8000` | `rba-decision-service` |
| `PDP_TIMEOUT_SECONDS` | `2.0` | fail closed on timeout |
| `SESSION_TTL_SECONDS` | `28800` | 8h bearer session |
| `CHALLENGE_TTL_SECONDS` | `300` | 5m MFA/reauth challenge |
| `MOCK_OTP_CODE` | `000000` | thesis mock, not a real factor |

## Status

IdP-4 session + mock MFA. Next: IdP-5 (hosted login UI). Roadmap:
`../docs/plans/status.md`.
