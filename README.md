# rba-idp

Thesis-scale **IdP** (Authentik/Auth0-shaped **shell**). The thesis core is RBA
(`rba-decision-service`); this service is the **PEP** that calls it and
enforces the action.

**IdP-7 (this slice):** groups with app-scoped `access` grants. Hosted login
at `GET /login`; admin console at `GET /admin` (users, applications, groups,
decision browser, policy). No OIDC/SAML/SCIM
([ADR-0014](../docs/decisions/0014-thesis-scale-idp-platform.md),
[ADR-0019](../docs/decisions/0019-groups-grant-app-access.md)).

Package version: **0.2.0**. Pins `rba-contracts` ≥ 0.4.0.

> Status: [`../docs/plans/status.md`](../docs/plans/status.md).
> ADRs: 0012–0019. AI: [`AGENTS.md`](AGENTS.md).

## Request path

```
browser  GET /login?application_id=demo-banking-app
           → HTML (email / password / MFA / blocked / signed-in)
           → POST /login  (JSON; ip_address from the page boot payload)
browser  GET /admin
           → React SPA (after hosted login as admin)
           → /admin/api/users|applications   (IdP DB)
           → /admin/api/decisions            (proxy → decision-service GET /decisions)
           → /admin/api/policy               (proxy → decision-service :8000)
client → POST /login
           → lookup application (rba_idp)
           → verify password (bcrypt)
           → require group grant (access) for this application
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
call). Password ok but no group grant for the app → `ACCESS_DENIED` (HTTP 200,
**no** PDP call; not a risk `BLOCK`). Unknown `application_id` → HTTP 400 (JSON) or an “unknown application”
panel (HTML). PDP down / invalid response → HTTP 503 (fail closed; not a fake
`BLOCK`). Admin APIs: HTTP 401 without a session, HTTP 403 if the user is not
`is_admin`. Audit/PDP down on those proxies → HTTP 503.

Mock OTP is always `000000` (thesis stand-in, not TOTP/WebAuthn). Completing
MFA does **not** re-score. Wrong code → `INVALID_CREDENTIALS` (challenge stays
open until expiry). Success → same `LoginResponse` shape with a session.
`GET /session` with `Authorization: Bearer …`. `POST /logout` returns 204
(idempotent).

Password never leaves this service (not logged, not returned, not sent to the
PDP). Session tokens are opaque random strings, stored **hashed** (sha256).
The hosted page keeps the token in `sessionStorage` and sends it as Bearer.

## Layout

```
src/rba_idp/
├── main.py              # FastAPI factory + JSON + hosted HTML + admin BFF
├── config.py            # pydantic-settings
├── passwords.py         # bcrypt hash / verify
├── pdp.py               # HttpPdpClient → /risk/evaluate
├── clients.py           # policy (PDP) + audit HTTP
├── tokens.py            # opaque session token + mock OTP compare
├── seed.py              # demo user, admin user, two applications, two groups
├── db/models.py         # applications, users, groups, sessions, mfa_challenges
├── db/session.py
├── services/login.py    # verify + group grant + PDP + session/challenge
├── services/admin.py    # users/apps/groups CRUD; proxy decisions/policy
├── web/                 # hosted login + built admin SPA
│   ├── templates/login.html
│   ├── static/login.{css,js}  admin.{css,js}
│   └── admin/           # Vite build output
admin-ui/                # React + Vite + TypeScript source
tests/
Dockerfile               # build from polyrepo root (copies rba-contracts)
```

## HTTP API

Contracts: `../rba-contracts/openapi/idp.yaml` (login) and
`idp-admin.yaml` (admin). Default port **8001**.

| Method | Path | Notes |
|---|---|---|
| `GET` | `/` or `/login` | Hosted UI. Query `application_id` (default: seeded app) |
| `GET` | `/admin` | Admin SPA. Sign in via `/login?application_id=idp-admin-console&next=/admin` |
| `GET` | `/static/…` | Login / admin CSS / JS |
| `GET` | `/healthz` | `{ "status": "ok" }` |
| `POST` | `/login` | `LoginRequest` → `LoginResponse` |
| `POST` | `/mfa/verify` | `MfaVerifyRequest` → `LoginResponse` |
| `GET` | `/session` | Bearer required → `SessionResponse` (`is_admin` on user) |
| `POST` | `/logout` | Bearer; 204 even if already gone |
| `GET/POST` | `/admin/api/users` | List / create (admin session) |
| `PATCH` | `/admin/api/users/{user_id}` | Enable / role / password |
| `GET/POST` | `/admin/api/applications` | List / register |
| `PATCH` | `/admin/api/applications/{id}` | Name / enabled |
| `GET/POST` | `/admin/api/groups` | List / create |
| `GET/PATCH/DELETE` | `/admin/api/groups/{id}` | Detail / rename / delete |
| `POST/DELETE` | `/admin/api/groups/{id}/members` | Add / remove user |
| `POST/DELETE` | `/admin/api/groups/{id}/grants` | Grant / revoke app `access` |
| `GET` | `/admin/api/decisions` | Decision browser (reasons) |
| `GET/PUT` | `/admin/api/policy` | Active PDP `PolicyConfig` |

HTTP 400: unknown/expired challenge, unknown application.
HTTP 401: missing/expired/unknown session.
HTTP 403: session is not an admin.
HTTP 503: PDP or audit store unavailable.

### Postgres tables (DB `rba_idp`)

Created on startup:

- `applications` — registered clients (`application_id` PK)
- `users` — `user_id`, unique email, bcrypt `password_hash`, `is_admin`
- `groups` / `group_memberships` / `group_app_grants` — IdP-7 app access
- `sessions` — PK `token_hash`; TTL `SESSION_TTL_SECONDS` (8h)
- `mfa_challenges` — pending step-up; TTL 5m; `consumed_at` on success

## Setup

```bash
cd ../rba-infra && docker compose up -d && cd -

python3.12 -m venv .venv && source .venv/bin/activate
pip install -U pip
pip install -e ../rba-contracts -e ".[dev]"

pytest -q

# Rebuild the admin SPA after UI edits:
#   cd admin-ui && npm install && npm run build

# PDP must already be up on :8000. Decision browser also needs
# rba-audit-api on :8002 (and the async plane to populate it).

DATABASE_URL=postgresql+psycopg://rba:rba@localhost:5432/rba_idp \
PDP_BASE_URL=http://localhost:8000 \
AUDIT_BASE_URL=http://localhost:8002 \
uvicorn rba_idp.main:app --reload --port 8001
```

Open [http://localhost:8001/login](http://localhost:8001/login) (or pass
`?application_id=demo-banking-app`).
Admin: [http://localhost:8001/admin](http://localhost:8001/admin)
(redirects to hosted login for `idp-admin-console`).

If Postgres was initialized **before** `rba_idp` existed:

```bash
docker compose -f ../rba-infra/docker-compose.yml exec postgres \
  psql -U rba -d postgres -c "CREATE DATABASE rba_idp;"
```

Tests use in-memory SQLite and stub PDP / policy / audit clients — they do
not need Docker or the live PDP.

### Docker / k8s

From the polyrepo root (`develop/`):

```bash
docker build -f rba-idp/Dockerfile -t rba-idp:dev .
```

Cluster install: `../rba-infra/scripts/k3d-up.sh`
([ADR-0020](../docs/decisions/0020-local-k8s-k3d-helm.md)). Hosted login then
at http://localhost:8080/login.

## Seeded identity

Written on every boot if missing (`seed.py`):

| | |
|---|---|
| Application | `demo-banking-app` (Demo banking app) |
| Application | `idp-admin-console` (IdP admin console) |
| User | `demo@example.com` / `demo-password` (`usr_demo`, not admin) |
| User | `admin@example.com` / `admin-password` (`usr_admin`, `is_admin`) |
| Group | `grp_banking` — demo user → `access` on `demo-banking-app` |
| Group | `grp_operators` — admin user → `access` on both apps |
| Mock OTP | `000000` |

Matches `rba-contracts` IdP login examples.

## Env

| Variable | Default | Notes |
|---|---|---|
| `DATABASE_URL` | `postgresql+psycopg://rba:rba@localhost:5432/rba_idp` | |
| `USE_MEMORY_DB` | `false` | sqlite StaticPool for tests |
| `PDP_BASE_URL` | `http://localhost:8000` | `rba-decision-service` |
| `PDP_TIMEOUT_SECONDS` | `2.0` | fail closed on timeout |
| `AUDIT_BASE_URL` | `http://localhost:8000` | PDP `GET /decisions` (live browser). Set to `:8002` only for the async audit copy |
| `SESSION_TTL_SECONDS` | `28800` | 8h bearer session |
| `CHALLENGE_TTL_SECONDS` | `300` | 5m MFA/reauth challenge |
| `MOCK_OTP_CODE` | `000000` | thesis mock, not a real factor |
| `SEED_USER_ID` / `SEED_EMAIL` / `SEED_PASSWORD` | `usr_demo` / `demo@example.com` / `demo-password` | |
| `SEED_ADMIN_*` | `usr_admin` / `admin@example.com` / `admin-password` | |
| `SEED_APPLICATION_ID` / `SEED_APPLICATION_NAME` | `demo-banking-app` / `Demo banking app` | |
| `SEED_ADMIN_APPLICATION_ID` | `idp-admin-console` | |
| `HOST` / `PORT` | `0.0.0.0` / `8001` | |

## Guardrails

- Import login/evaluate/admin models from `rba-contracts`. Map actions with
  `outcome_from_action` only.
- Call `/risk/evaluate` only after a successful password verify **and** a
  group grant for the application.
- Do not put identity in `decision-service`.
- Do not implement OIDC/SAML/SCIM. Groups grant `access` only (ADR-0019);
  `is_admin` still gates `/admin/api`.
- Hosted login stays on this origin ([ADR-0016](../docs/decisions/0016-hosted-login-on-idp.md)).
- Admin is colocated here ([ADR-0017](../docs/decisions/0017-admin-console-colocated-on-idp.md));
  do not query `rba_audit` / `rba_decision` tables from this process.
- Do not add Redis/Postgres compose here — use `../rba-infra`.

## Status

IdP-7 groups / app-scoped permissions. Local k8s via `../rba-infra` Helm
(K8s-1). Next: observability (K8s-2). Roadmap: `../docs/plans/status.md`.
