# AGENTS.md — rba-idp

Thesis-scale **IdP** (PEP / product shell) for a risk-based authentication (RBA)
thesis. Identity lives here; risk scoring stays in `rba-decision-service`.
Portable orientation for any AI coding tool.

## Where we are / where things are stated

**Polyrepo** (org `github.com/roku-pfi`), siblings cloned side-by-side. Roadmap /
status / decisions live in the **`docs`** repo (`../docs`):

- **Current status → `../docs/plans/status.md`**
- Phase rationale → `../docs/plans/development_plan.md` §8 Phase 7
- Decisions → `../docs/decisions/` (ADR-0012–0017)
- Narrative → `../docs/devlog.md`

**This slice is IdP-6:** admin console at `/admin` (users, apps, decisions,
policy). Do **not** add groups or OIDC until those stages
([ADR-0017](../docs/decisions/0017-admin-console-colocated-on-idp.md)).

## Layout

```
src/rba_idp/
  main.py                 # FastAPI: login HTML + JSON API + admin BFF
  config.py
  passwords.py / tokens.py / pdp.py / clients.py
  seed.py                 # demo + admin user, two applications
  db/                     # applications, users, sessions, mfa_challenges
  services/login.py       # verify + PDP enforce + session/challenge
  services/admin.py       # directory CRUD + proxy to audit/policy
  web/                    # hosted login + Vite admin build
admin-ui/                 # React + Vite source (`npm run build`)
tests/test_login.py test_pdp.py test_session.py test_hosted_login.py test_admin.py
```

## Guardrails

- Import login / evaluate / admin models from `rba-contracts`. Map actions with
  `outcome_from_action` — do not re-implement the mapping.
- Call `/risk/evaluate` only after a successful password verify. Never send
  the password (or email) to the PDP. Completing MFA does **not** re-score.
- Do **not** put identity in `decision-service`.
- Do **not** implement OIDC/SAML/SCIM (ADR-0014).
- Do **not** add groups (IdP-7). Admin uses `is_admin` only.
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
