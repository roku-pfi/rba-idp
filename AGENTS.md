# AGENTS.md — rba-idp

Thesis-scale **IdP** (PEP / product shell) for a risk-based authentication (RBA)
thesis. Identity lives here; risk scoring stays in `rba-decision-service`.
Portable orientation for any AI coding tool.

## Where we are / where things are stated

**Polyrepo** (org `github.com/roku-pfi`), siblings cloned side-by-side. Roadmap /
status / decisions live in the **`docs`** repo (`../docs`):

- **Current status → `../docs/plans/status.md`**
- Phase rationale → `../docs/plans/development_plan.md` §8 Phase 7
- Decisions → `../docs/decisions/` (ADR-0012–0020)
- Narrative → `../docs/devlog.md`

Multi-tenant (ADR-0033/0034): tenant from the application (app login) or the
email domain (console login); every admin query filtered by the operator's
tenant; enforce the PDP's `enforced_action`; skip the PDP when the tenant's
engine is `OFF`. WebAuthn passkey for step-ups (opaque copy); passkeys are
enrolled only after a usual-context login or with an activation code
(ADR-0037), never during a step-up.
Mock OTP on `POST /mfa/verify` is off unless `MOCK_OTP_ENABLED` (tests). Completing MFA does not
re-score. Travel rule stays in `rba-features` + the PDP. Do **not** add
OIDC/SAML/SCIM
([ADR-0014](../docs/decisions/0014-thesis-scale-idp-platform.md)).
Presenter walkthrough lives on the bank (`/walkthrough`), not here.

## Layout

```
src/rba_idp/
  main.py                 # FastAPI: login HTML + JSON API + admin BFF
  config.py
  tokens.py / pdp.py / clients.py / webauthn.py
  seed.py                 # three tenants (roku-bank, kaze-labs, rokusec) + consoles
  tenancy.py              # email domain → tenant; per-tenant policy cache
  db/                     # applications, users, groups, sessions, mfa, passkeys
  services/login.py       # verify + group grant + PDP enforce + session/WebAuthn
  services/admin.py       # directory + groups CRUD + proxy to audit/policy
  web/                    # hosted login + Vite admin build
  geo.py                  # TEST-NET prefix → country/ASN + query override
admin-ui/                 # React + Vite source (`npm run build`)
tests/test_login.py test_pdp.py test_session.py test_hosted_login.py test_admin.py test_groups.py test_geo.py test_webauthn.py test_rbac.py test_tenancy.py
```

## Guardrails

- Import login / evaluate / admin models from `rba-contracts`. Map actions with
  `outcome_from_action` — do not re-implement the mapping.
- Call `/risk/evaluate` only after a successful password verify **and** a
  group `access` grant for the application. Never send the password (or email)
  to the PDP. Completing MFA does **not** re-score.
- Do **not** put identity in `decision-service`.
- Do **not** implement OIDC/SAML/SCIM (ADR-0014).
- Holding a role on an app is the sign-in grant (ADR-0029). The admin API
  requires a session on the caller's own tenant's console.
- Every admin query takes the `Operator`'s `tenant_id`; another tenant's
  object answers like a missing one (404). New admin endpoints get a row in
  `tests/test_tenancy.py::CROSS_TENANT`.
- Console login failures are all `INVALID_CREDENTIALS` (no tenant oracle).
- Do **not** query `rba_audit` or `rba_decision` tables — HTTP to those services.
- Hosted login stays here, not a new `rba-frontend` repo (ADR-0016/0017).
- Passwords: bcrypt only; never log or return the password.
- Session tokens: opaque, stored hashed; `Authorization: Bearer`.
- MFA: hosted login is WebAuthn (platform authenticator). Mock OTP (`000000`)
  on `POST /mfa/verify` exists only with `MOCK_OTP_ENABLED` (tests). No TOTP/SMS. Completing MFA does
  **not** re-score.
- Do **not** add Redis/Postgres compose here — use `../rba-infra`.
- PDP unavailable on the **login** path → degrade to `PDP_UNAVAILABLE_ACTION`
  (default `REQUIRE_MFA`) with a `pdp_unavailable` reason and `fallback=true`.
  Never 503 the login (mass lockout) and never let it through (RF-10 / RNF-03,
  ADR-0028). Do not invent a `BLOCK` or fake a score.
- PDP or audit unavailable on the **admin read** proxies → HTTP 503. A dashboard
  that cannot load is not a login that cannot happen.
- Only commit when explicitly asked; Conventional Commits; never commit secrets.

## Setup

```bash
cd ../rba-infra && docker compose up -d && cd -
python3.12 -m venv .venv && source .venv/bin/activate
pip install -e ../rba-contracts -e ".[dev]"
pytest -q
```
