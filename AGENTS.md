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

This slice is Demo-3-ready: thin `redirect_uri` callback for `rba-demo-banking`.
Travel rule stays in `rba-features` + the PDP. Do **not** add OIDC/SAML/SCIM
([ADR-0014](../docs/decisions/0014-thesis-scale-idp-platform.md)). Next is Demo-4
(WebAuthn). Presenter walkthrough lives on the bank (`/walkthrough`), not here.

## Layout

```
src/rba_idp/
  main.py                 # FastAPI: login HTML + JSON API + admin BFF
  config.py
  passwords.py / tokens.py / pdp.py / clients.py
  seed.py                 # demo + admin user, two applications, two groups
  db/                     # applications, users, groups, sessions, mfa_challenges
  services/login.py       # verify + group grant + PDP enforce + session/challenge
  services/admin.py       # directory + groups CRUD + proxy to audit/policy
  web/                    # hosted login + Vite admin build
  geo.py                  # TEST-NET prefix → country/ASN + query override
admin-ui/                 # React + Vite source (`npm run build`)
tests/test_login.py test_pdp.py test_session.py test_hosted_login.py test_admin.py test_groups.py test_geo.py
```

## Guardrails

- Import login / evaluate / admin models from `rba-contracts`. Map actions with
  `outcome_from_action` — do not re-implement the mapping.
- Call `/risk/evaluate` only after a successful password verify **and** a
  group `access` grant for the application. Never send the password (or email)
  to the PDP. Completing MFA does **not** re-score.
- Do **not** put identity in `decision-service`.
- Do **not** implement OIDC/SAML/SCIM (ADR-0014).
- Groups grant app `access` only (ADR-0019). Admin BFF still uses `is_admin`.
- Do **not** query `rba_audit` or `rba_decision` tables — HTTP to those services.
- Hosted login stays here, not a new `rba-frontend` repo (ADR-0016/0017).
- Passwords: bcrypt only; never log or return the password.
- Session tokens: opaque, stored hashed; `Authorization: Bearer`.
- MFA: mock OTP (`000000`) is enough. No WebAuthn/TOTP provider.
- Do **not** add Redis/Postgres compose here — use `../rba-infra`.
- PDP or audit unavailable → HTTP 503 (fail closed). Do not invent a `BLOCK`
  or fake decisions.
- Only commit when explicitly asked; Conventional Commits; never commit secrets.

## Setup

```bash
cd ../rba-infra && docker compose up -d && cd -
python3.12 -m venv .venv && source .venv/bin/activate
pip install -e ../rba-contracts -e ".[dev]"
pytest -q
```
