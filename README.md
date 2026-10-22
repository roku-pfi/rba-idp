# rba-idp

Thesis-scale **IdP** (Authentik/Auth0-shaped **shell**). The thesis core is RBA
(`rba-decision-service`); this service is the **PEP** that calls it and
enforces the action.

**Demo-4:** WebAuthn passkey for `REQUIRE_MFA` / `REAUTHENTICATE` (opaque
“confirm it’s you”). Mock OTP `000000` remains on `POST /mfa/verify` for tests.
Completing MFA does **not** re-score. Country/ASN on hosted login; presenter
walkthrough is on the bank (`/walkthrough`). Travel rule is in `rba-features` /
the PDP, not here.
Hosted login at `GET /login`; admin console at `GET /admin`. No OIDC/SAML/SCIM
([ADR-0014](../docs/decisions/0014-thesis-scale-idp-platform.md),
[ADR-0019](../docs/decisions/0019-groups-grant-app-access.md),
[ADR-0022](../docs/decisions/0022-product-demo-over-gitops.md)).

**Multi-tenant** ([ADR-0033](../docs/decisions/0033-multi-tenancy.md)): every
application, user, group and role belongs to one tenant. An app login takes its
tenant from the application; the console login (`/console/login`) takes it from
the operator's email domain. The IdP applies the PDP's `enforced_action`
([ADR-0034](../docs/decisions/0034-base-policy-and-engine-mode.md)) and does
not call the PDP at all for a tenant whose engine is `OFF`.

**Passkeys are enrolled only from a trusted context**
([ADR-0037](../docs/decisions/0037-passkey-enrollment-from-trusted-context.md)):
after a login the engine judged usual (the session may add one passkey within
10 minutes), or at `/activate` with an operator-issued code **plus** the
password. A step-up for a user without a passkey is refused
(`SECOND_FACTOR_MISSING`), never turned into an enrollment. The mock OTP exists
only with `MOCK_OTP_ENABLED=true` (tests).

Package version: **0.5.0**. Pins `rba-contracts` ≥ 0.10.0.

> Status: [`../docs/plans/status.md`](../docs/plans/status.md).
> ADRs: 0012–0026. AI: [`AGENTS.md`](AGENTS.md).

## Request path

```
browser  GET /login?application_id=roku-bank-web
           → HTML (email / password / MFA / blocked / signed-in)
           → POST /login  (JSON; ip_address / country / asn from the page boot payload)
browser  GET /console/login   (or GET / with no application)
           → POST /console/login  (no application_id: the email domain picks the tenant)
browser  GET /admin
           → React SPA (after the console login)
           → /admin/api/users|applications   (IdP DB, filtered by the operator's tenant)
           → /admin/api/decisions            (proxy → decision-service GET /decisions?tenant_id=)
           → /admin/api/policy               (proxy → decision-service /tenants/{id}/policy)
client → POST /login
           → lookup application → its tenant (rba_idp)
           → look the email up inside that tenant; verify password (bcrypt)
           → require a role on this application (ADR-0029)
           → tenant's engine OFF? → apply its base policy, no PDP call
           → POST /risk/evaluate with tenant_id (rba-decision-service)
           → apply enforced_action:
           → ALLOW          → session token
           → MFA / REAUTH   → challenge_id  (WebAuthn; tests may POST /mfa/verify with 000000)
           → BLOCK          → rejected (no session)
```

| Enforced action | Login outcome | What the IdP issues |
|---|---|---|
| `ALLOW` | `AUTHENTICATED` | `session.token` (Bearer) |
| `REQUIRE_MFA` | `MFA_REQUIRED` | `challenge_id` |
| `REAUTHENTICATE` | `REAUTH_REQUIRED` | `challenge_id` |
| `BLOCK` | `BLOCKED` | nothing |

Wrong password / unknown user → `INVALID_CREDENTIALS` (HTTP 200, **no** PDP
call). Password ok but no group grant for the app → `ACCESS_DENIED` (HTTP 200,
**no** PDP call; not a risk `BLOCK`). Unknown `application_id` → HTTP 400 (JSON) or an “unknown application”
panel (HTML). PDP down / invalid response on the login path → degrade to
`PDP_UNAVAILABLE_ACTION` (default `REQUIRE_MFA`) with a single `pdp_unavailable`
reason and `risk_score` 0.0 — never a 503 (that is the mass lockout RNF-03
forbids), never an `ALLOW`, and never a fake `BLOCK` (RF-10 / RNF-03, ADR-0028).
Console login: an unknown domain, an unknown user, a wrong password and a user
without a console role all answer the same `INVALID_CREDENTIALS`, at the same
bcrypt cost, so the form reveals no tenant.
Admin APIs: HTTP 401 without a session; HTTP 403 when the session is not on
its tenant's console, or lacks the permission the endpoint needs —
`admin:read` to open the console, `admin:write` to change identity,
`decisions:read` for decisions, `policy:write` to retune risk (ADR-0029).
Every query is filtered by the operator's tenant; another tenant's object
answers 404 exactly like a missing one. A platform operator (`rokusec` tenant,
`tenants:read`) acts on another tenant by sending `X-RokuSec-Tenant: <id>`;
anyone else naming another tenant gets the same 403 whether it exists or not.
Audit/PDP down on those read proxies → HTTP 503.

Live MFA is a platform passkey (`POST /mfa/webauthn/options` then
`POST /mfa/webauthn/verify`). Completing MFA does **not** re-score. Mock OTP
`000000` on `POST /mfa/verify` stays for tests. Wrong factor →
`INVALID_CREDENTIALS` (challenge stays open until expiry). Success → same
`LoginResponse` shape with a session. `GET /session` with
`Authorization: Bearer …`. `POST /logout` returns 204 (idempotent).

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
├── webauthn.py          # passkey create/get (py_webauthn)
├── seed.py              # demo user, admin user, two applications, two groups
├── db/models.py         # applications, users, groups, sessions, mfa, passkeys
├── db/session.py
├── services/login.py    # verify + group grant + PDP + session/challenge
├── services/admin.py    # users/apps/groups CRUD; proxy decisions/policy
├── geo.py               # TEST-NET prefix → country/ASN + query override
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
| `GET` | `/login` | Hosted UI. Query `application_id`; optional `country` / `asn` override |
| `GET` | `/` or `/console/login` | Console login (no `application_id`) |
| `GET` | `/admin` | Admin SPA. Sign in via `/console/login?next=/admin` |
| `GET` | `/static/…` | Login / admin CSS / JS |
| `GET` | `/healthz` | `{ "status": "ok" }` |
| `POST` | `/login` | `LoginRequest` → `LoginResponse` |
| `POST` | `/console/login` | `ConsoleLoginRequest` (no `application_id`) → `LoginResponse` |
| `POST` | `/mfa/verify` | Mock OTP (`MfaVerifyRequest`) → `LoginResponse`. **404 unless `MOCK_OTP_ENABLED`** |
| `POST` | `/passkeys/options`, `/passkeys/verify` | Bearer; enroll after a usual-context login (`passkey_offer`) |
| `GET` | `/activate` | Activation page (code + password → passkey) |
| `POST` | `/activate/options`, `/activate/verify` | `ActivationOptionsRequest` / `ActivationVerifyRequest` |
| `POST` | `/mfa/webauthn/options` | `MfaWebAuthnOptionsRequest` → create/get options |
| `POST` | `/mfa/webauthn/verify` | `MfaWebAuthnVerifyRequest` → `LoginResponse` |
| `GET` | `/session` | Bearer required → `SessionResponse` with `application_id` and the session's effective `permissions` |
| `POST` | `/logout` | Bearer; 204 even if already gone |
| `GET` | `/admin/api/tenant` | The tenant this console request is scoped to |
| `GET/POST` | `/admin/api/tenants` | Platform operator: list / create (with console + starter policy) |
| `PATCH` | `/admin/api/tenants/{id}` | Platform operator: name, operator domains, branding |
| `GET/POST` | `/admin/api/users` | List / create (console session) |
| `PATCH` | `/admin/api/users/{user_id}` | Enable / role / password |
| `POST` | `/admin/api/users/{user_id}/activation-code` | `admin:write`; one-time code, 15 min, shown once |
| `GET/POST` | `/admin/api/applications` | List / register |
| `PATCH` | `/admin/api/applications/{id}` | Name / enabled |
| `GET/POST` | `/admin/api/groups` | List / create |
| `GET/PATCH/DELETE` | `/admin/api/groups/{id}` | Detail / rename / delete |
| `POST/DELETE` | `/admin/api/groups/{id}/members` | Add / remove user |
| `POST/DELETE` | `/admin/api/groups/{id}/roles` | Assign / unassign a role |
| `GET/POST` | `/admin/api/roles` | List / create roles (`?application_id=` filter) |
| `GET/PATCH/DELETE` | `/admin/api/roles/{id}` | Role detail with its permissions |
| `PUT` | `/admin/api/roles/{id}/permissions` | Replace a role's permission set |
| `GET/POST` | `/admin/api/permissions` | List / create permissions |
| `GET` | `/admin/api/decisions` | Decision browser (reasons, verdict vs. enforced) |
| `GET/PUT` | `/admin/api/policy` | The tenant's `TenantPolicy` on the PDP |

HTTP 400: unknown/expired challenge, unknown application.
HTTP 401: missing/expired/unknown session.
HTTP 403: not a console session, missing permission, or another tenant named
without being a platform operator.
HTTP 404: unknown object — including any object of another tenant.
HTTP 503: PDP or audit store unavailable — **admin reads only**. The login
path degrades to a step-up instead (see above).

### Postgres tables (DB `rba_idp`)

Created on startup. There are no migrations: a database created before
tenancy is refused at startup with a message to reset it (ADR-0033).

- `tenants` — organisations; branding, `is_platform`, console application,
  admin group
- `tenant_domains` — operator email domain → tenant (`domain` PK: one tenant
  per domain across the platform)
- `applications` — registered clients (`application_id` PK, platform-wide), `tenant_id`
- `users` — `user_id`, `tenant_id`, email unique **per tenant**, bcrypt
  `password_hash`, `is_admin` (directory label only; drives the tenant's admin
  group)
- `groups` / `group_memberships` — who (`tenant_id`; names unique per tenant)
- `roles` / `permissions` / `role_permissions` / `group_roles` — what they may
  do. `user → group → role → permission(resource, operation)`, every role
  scoped to one application (ADR-0029)
- `sessions` — PK `token_hash`; TTL `SESSION_TTL_SECONDS` (8h)
- `mfa_challenges` — pending step-up; TTL 5m; `consumed_at` on success; WebAuthn nonce
- `webauthn_credentials` — platform passkeys (`credential_id` PK, COSE public key)
- `activation_codes` — operator-issued enrollment codes (hash only, single use)

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

Bank login: [http://localhost:8001/login?application_id=roku-bank-web](http://localhost:8001/login?application_id=roku-bank-web).
Console: [http://localhost:8001/admin](http://localhost:8001/admin)
(redirects to `/console/login`).

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

Written on every boot if missing (`seed.py`). Every password is
`<local part>-demo` (suffix: `SEED_PASSWORD_SUFFIX`).

| Tenant | Applications | Users |
|---|---|---|
| `roku-bank` (ALWAYS_MFA + MONITOR) | `roku-bank-web` (redirect `SEED_BANK_REDIRECT_URI`), `roku-bank-console` | `martin@correo.example` (customer), `sofia@correo.example` (viewer: no `transfer:create`), `diego@rokubank.example` (tenant-admin), `ana@rokubank.example` (support) |
| `kaze-labs` (PASSWORD_ONLY + ACTIVE) | `kaze-portal` (redirect `SEED_KAZE_REDIRECT_URI`), `kaze-labs-console` | `lucas@kazelabs.example` (tenant-admin + portal admin), `martin@kazelabs.example` (member), `valen@kazelabs.example` (viewer) |
| `rokusec` (platform) | `rokusec-console` | `juan@rokusec.example` (platform-operator: may switch tenants) |

Every tenant's console has the same two roles, `tenant-admin` and `support`,
and an `Administradores` group that `is_admin` adds a user to. Operator domains:
`rokubank.example`, `kazelabs.example`, `rokusec.example`. Tenant policies live
in the PDP (`rba-decision-service/config/policies/`).

No passkey is seeded. On a fresh database nobody can pass a step-up, so the first
code comes from the cluster (break glass), then operators issue the rest from
the console:

```bash
kubectl exec deploy/idp -- python -m rba_idp.activation juan@rokusec.example --tenant rokusec
```

## Env

| Variable | Default | Notes |
|---|---|---|
| `DEPLOYMENT` | `local` | `cloud` refuses to start while any local-only default remains (memory DB, mock OTP, `rba:rba`/localhost URLs, non-https public URL / WebAuthn origins, RP ID `localhost`, seed suffix `demo`), listing every problem at once |
| `PUBLIC_URL` | `http://localhost:8001` | browser-facing origin of this IdP (CloudFront in the cloud) |
| `DATABASE_URL` | `postgresql+psycopg://rba:rba@localhost:5432/rba_idp` | |
| `USE_MEMORY_DB` | `false` | sqlite StaticPool for tests |
| `PDP_BASE_URL` | `http://localhost:8000` | `rba-decision-service` |
| `PDP_TIMEOUT_SECONDS` | `2.0` | a timeout counts as unavailable |
| `PDP_UNAVAILABLE_ACTION` | `REQUIRE_MFA` | login-path degrade when the PDP does not answer. Only `REQUIRE_MFA` / `REAUTHENTICATE` are accepted — `ALLOW` and `BLOCK` are unrepresentable by design (RNF-03) |
| `AUDIT_BASE_URL` | `http://localhost:8000` | PDP `GET /decisions` (live browser). Set to `:8002` only for the async audit copy |
| `SESSION_TTL_SECONDS` | `28800` | 8h bearer session |
| `CHALLENGE_TTL_SECONDS` | `300` | 5m MFA/reauth challenge |
| `MOCK_OTP_ENABLED` | `false` | test-only fixed second factor; never in a deployment |
| `MOCK_OTP_CODE` | `000000` | the code, when enabled |
| `ENROLL_WINDOW_SECONDS` | `600` | how long a usual-context session may add a passkey |
| `ACTIVATION_TTL_SECONDS` | `900` | operator-issued activation code lifetime |
| `WEBAUTHN_RP_ID` | `localhost` | must match the browser host |
| `WEBAUTHN_ORIGIN` | `http://localhost:8001,http://localhost:8080` | comma-separated; k8s sets `:8080` |
| `POLICY_CACHE_SECONDS` | `5.0` | how long a tenant's policy is trusted before re-reading it (only `engine_mode: OFF` is decided from it) |
| `SEED_BANK_REDIRECT_URI` | `http://localhost:8002/callback` | k8s: `http://demo.localhost:8080/callback` |
| `SEED_KAZE_REDIRECT_URI` | `http://localhost:8003/callback` | |
| `SEED_PASSWORD_SUFFIX` | `demo` | seeded passwords are `<local part>-<suffix>` |
| `BCRYPT_ROUNDS` | `12` | the test suite sets 4 |
| `HOST` / `PORT` | `0.0.0.0` / `8001` | |

## Guardrails

- Import login/evaluate/admin models from `rba-contracts`. Map actions with
  `outcome_from_action` only.
- Call `/risk/evaluate` only after a successful password verify **and** a
  group grant for the application.
- Do not put identity in `decision-service`.
- Do not implement OIDC/SAML/SCIM. Authorization is RBAC (ADR-0029): groups hold
  roles, roles carry `resource:operation` permissions, roles are scoped to one
  application. `is_admin` is a directory label, never an authorization input.
- Hosted login stays on this origin ([ADR-0016](../docs/decisions/0016-hosted-login-on-idp.md)).
- Admin is colocated here ([ADR-0017](../docs/decisions/0017-admin-console-colocated-on-idp.md));
  do not query `rba_audit` / `rba_decision` tables from this process.
- Do not add Redis/Postgres compose here — use `../rba-infra`.

## Status

IdP-7 groups / app-scoped permissions. Demo-4 WebAuthn step-up. Local k8s via
`../rba-infra` Helm (K8s-1 + demo chart). Observability: `../rba-infra`
Grafana `/grafana` (K8s-2). Roadmap: `../docs/plans/status.md`.
