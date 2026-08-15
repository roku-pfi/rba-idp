# rba-idp

Thesis-scale **IdP** (Authentik/Auth0-shaped shell). The thesis core is RBA
(`rba-decision-service`); this service is the PEP that will call it at **IdP-3**.

**IdP-2 (this slice):** local users + one seeded application + `POST /login`
password verify. No PDP call, no session, no MFA, no UI, no OIDC.

## Request path (IdP-2)

```
client → POST /login
           → lookup application (rba_idp)
           → verify password (bcrypt)
           → AUTHENTICATED | INVALID_CREDENTIALS
```

Contracts: `rba-contracts` v0.2.0 (`LoginRequest` / `LoginResponse`). Optional
risk/session fields stay unset until IdP-3/4.

## Setup

```bash
# Shared Postgres lives in rba-infra (not this repo):
cd ../rba-infra && docker compose up -d && cd -

# from this repo
python3.12 -m venv .venv && source .venv/bin/activate
pip install -U pip
pip install -e ../rba-contracts -e ".[dev]"

pytest -q

DATABASE_URL=postgresql+psycopg://rba:rba@localhost:5432/rba_idp \
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
seed time; it is never stored or echoed.

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

Success: `{"outcome":"AUTHENTICATED","user_id":"usr_demo"}`.
Wrong password / unknown user: `{"outcome":"INVALID_CREDENTIALS"}` (HTTP 200).
Unknown `application_id`: HTTP 400.

## Env

| Variable | Default | Notes |
|---|---|---|
| `DATABASE_URL` | `postgresql+psycopg://rba:rba@localhost:5432/rba_idp` | DB created by `rba-infra` init |
| `USE_MEMORY_DB` | `false` | sqlite StaticPool for tests |

## Status

IdP-2 identity store. Next: IdP-3 (call `/risk/evaluate`). Roadmap:
`../docs/plans/status.md`.
