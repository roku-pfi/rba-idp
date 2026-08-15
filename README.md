# rba-idp

Thesis-scale **IdP** (Authentik/Auth0-shaped shell). The thesis core is RBA
(`rba-decision-service`); this service is the PEP that calls it.

**IdP-3 (this slice):** local users + seeded application + `POST /login`
password verify, then `POST /risk/evaluate`. Maps PDP action → login outcome
and returns reasons. No session, no MFA challenge, no UI, no OIDC.

## Request path (IdP-3)

```
client → POST /login
           → lookup application (rba_idp)
           → verify password (bcrypt)
           → POST /risk/evaluate (rba-decision-service)
           → map action → outcome + reasons
```

| PDP action | Login outcome |
|---|---|
| `ALLOW` | `AUTHENTICATED` |
| `REQUIRE_MFA` | `MFA_REQUIRED` |
| `REAUTHENTICATE` | `REAUTH_REQUIRED` |
| `BLOCK` | `BLOCKED` |

Wrong password / unknown user → `INVALID_CREDENTIALS` (HTTP 200, **no** PDP
call). Unknown `application_id` → HTTP 400. PDP down / invalid response →
HTTP 503 (fail closed; not a fake `BLOCK`).

Contracts: `rba-contracts` v0.2.0 (`LoginRequest` / `LoginResponse`,
`outcome_from_action`). `session` / `challenge_id` stay unset until IdP-4.

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

Matches `rba-contracts` IdP login examples. Password is hashed with bcrypt at
seed time; it is never stored, echoed, or sent to the PDP.

## Example

```bash
curl -s localhost:8001/login -H 'content-type: application/json' -d '{
  "email": "demo@example.com",
  "password": "demo-password",
  "application_id": "demo-banking-app",
  "ip_address": "203.0.113.10",
  "asn": "13335",
  "country": "AR",
  "device_type": "mobile",
  "os": "Android",
  "browser": "Chrome"
}'
```

Success includes `outcome`, `user_id`, `event_id`, `action`, `risk_score`,
`risk_level`, and `reasons`. Wrong password / unknown user:
`{"outcome":"INVALID_CREDENTIALS"}` (HTTP 200).

## Env

| Variable | Default | Notes |
|---|---|---|
| `DATABASE_URL` | `postgresql+psycopg://rba:rba@localhost:5432/rba_idp` | DB created by `rba-infra` init |
| `USE_MEMORY_DB` | `false` | sqlite StaticPool for tests |
| `PDP_BASE_URL` | `http://localhost:8000` | `rba-decision-service` |
| `PDP_TIMEOUT_SECONDS` | `2.0` | fail closed on timeout |

## Status

IdP-3 PDP enforce. Next: IdP-4 (session + mock MFA). Roadmap:
`../docs/plans/status.md`.
