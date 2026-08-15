# rba-idp

Thesis-scale **IdP** (Authentik/Auth0-shaped **shell**). The thesis core is RBA
(`rba-decision-service`); this service is the **PEP** that calls it and
enforces the action.

**IdP-4 (this slice):** after password verify + PDP, issue a session on `ALLOW`
or a mock-OTP challenge on MFA/REAUTH. `BLOCK` stays rejected. No hosted HTML
(that is **IdP-5**). No admin console (**IdP-6**). No OIDC/SAML/SCIM
([ADR-0014](../docs/decisions/0014-thesis-scale-idp-platform.md)).

Package version: **0.1.0**. Pins `rba-contracts` ≥ 0.2.0.

> Status: [`../docs/plans/status.md`](../docs/plans/status.md).
> ADRs: 0012–0015. AI: [`AGENTS.md`](AGENTS.md).

## Request path (IdP-4)

```
client → POST /login
           → lookup application (rba_idp)
           → verify password (bcrypt)
           → POST /risk/evaluate (rba-decision-service)
           → ALLOW          → session token
           → MFA / REAUTH   → challenge_id  (POST /mfa/verify with 000000)
           → BLOCK          → rejected (no session)
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

Mock OTP is always `000000` (thesis stand-in, not TOTP/WebAuthn). Completing
MFA does **not** re-score. Wrong code → `INVALID_CREDENTIALS` (challenge stays
open until expiry). Success → same `LoginResponse` shape with a session.
`GET /session` with `Authorization: Bearer …`. `POST /logout` returns 204
(idempotent).

Password never leaves this service (not logged, not returned, not sent to the
PDP). Session tokens are opaque random strings, stored **hashed** (sha256).

## Layout

```
src/rba_idp/
├── main.py              # FastAPI factory + routes
├── config.py            # pydantic-settings
├── passwords.py         # bcrypt hash / verify
├── pdp.py               # HttpPdpClient → /risk/evaluate
├── tokens.py            # opaque session token + mock OTP compare
├── seed.py              # demo user + demo-banking-app (idempotent)
├── db/models.py         # applications, users, sessions, mfa_challenges
├── db/session.py
└── services/login.py    # verify + PDP + session/challenge
tests/
├── conftest.py          # in-memory sqlite + stub PDP
├── helpers.py
├── test_login.py
├── test_pdp.py
└── test_session.py
```

## HTTP API

Contracts: `../rba-contracts/openapi/idp.yaml`. Default port **8001**.

| Method | Path | Notes |
|---|---|---|
| `GET` | `/healthz` | `{ "status": "ok" }` |
| `POST` | `/login` | `LoginRequest` → `LoginResponse` |
| `POST` | `/mfa/verify` | `MfaVerifyRequest` → `LoginResponse` |
| `GET` | `/session` | Bearer required → `SessionResponse` |
| `POST` | `/logout` | Bearer; 204 even if already gone |

HTTP 400: unknown/expired challenge, unknown application.
HTTP 401: missing/expired/unknown session.
HTTP 503: PDP unavailable.

### Postgres tables (DB `rba_idp`)

Created on startup:

- `applications` — registered clients (`application_id` PK)
- `users` — `user_id`, unique email, bcrypt `password_hash`
- `sessions` — PK `token_hash`; TTL `SESSION_TTL_SECONDS` (8h)
- `mfa_challenges` — pending step-up; TTL 5m; `consumed_at` on success

## Setup

```bash
cd ../rba-infra && docker compose up -d && cd -

python3.12 -m venv .venv && source .venv/bin/activate
pip install -U pip
pip install -e ../rba-contracts -e ".[dev]"

pytest -q

# PDP must already be up on :8000 (see rba-decision-service README)

DATABASE_URL=postgresql+psycopg://rba:rba@localhost:5432/rba_idp \
PDP_BASE_URL=http://localhost:8000 \
uvicorn rba_idp.main:app --reload --port 8001
```

If Postgres was initialized **before** `rba_idp` existed:

```bash
docker compose -f ../rba-infra/docker-compose.yml exec postgres \
  psql -U rba -d postgres -c "CREATE DATABASE rba_idp;"
```

Tests use in-memory SQLite and a stub `PdpClient` — they do not need Docker
or the live PDP.

## Seeded identity

Written on every boot if missing (`seed.py`):

| | |
|---|---|
| Application | `demo-banking-app` (Demo banking app) |
| User | `demo@example.com` / `demo-password` (`usr_demo`) |
| Mock OTP | `000000` |

Matches `rba-contracts` IdP login examples.

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
| `DATABASE_URL` | `postgresql+psycopg://rba:rba@localhost:5432/rba_idp` | |
| `USE_MEMORY_DB` | `false` | sqlite StaticPool for tests |
| `PDP_BASE_URL` | `http://localhost:8000` | `rba-decision-service` |
| `PDP_TIMEOUT_SECONDS` | `2.0` | fail closed on timeout |
| `SESSION_TTL_SECONDS` | `28800` | 8h bearer session |
| `CHALLENGE_TTL_SECONDS` | `300` | 5m MFA/reauth challenge |
| `MOCK_OTP_CODE` | `000000` | thesis mock, not a real factor |
| `SEED_USER_ID` / `SEED_EMAIL` / `SEED_PASSWORD` | `usr_demo` / `demo@example.com` / `demo-password` | |
| `SEED_APPLICATION_ID` / `SEED_APPLICATION_NAME` | `demo-banking-app` / `Demo banking app` | |
| `HOST` / `PORT` | `0.0.0.0` / `8001` | |

## Guardrails

- Import login/evaluate models from `rba-contracts`. Map actions with
  `outcome_from_action` only.
- Call `/risk/evaluate` only after a successful password verify.
- Do not put identity in `decision-service`.
- Do not implement OIDC/SAML/SCIM. Do not add hosted HTML yet (IdP-5).
- Do not add Redis/Postgres compose here — use `../rba-infra`.

## Status

IdP-4 session + mock MFA. Next: **IdP-5** hosted login UI. Roadmap:
`../docs/plans/status.md`.
