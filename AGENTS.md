# AGENTS.md — rba-idp

Thesis-scale **IdP** (PEP / product shell) for a risk-based authentication (RBA)
thesis. Identity lives here; risk scoring stays in `rba-decision-service`.
Portable orientation for any AI coding tool.

## Where we are / where things are stated

**Polyrepo** (org `github.com/roku-pfi`), siblings cloned side-by-side. Roadmap /
status / decisions live in the **`docs`** repo (`../docs`):

- **Current status → `../docs/plans/status.md`**
- Phase rationale → `../docs/plans/development_plan.md` §8 Phase 7
- Decisions → `../docs/decisions/` (ADR-0012–0015)
- Narrative → `../docs/devlog.md`

**This slice is IdP-2:** users + seeded application + password verify. Do **not**
call the PDP, issue sessions, add MFA, UI, admin, or OIDC until those stages.

## Layout

```
src/rba_idp/
  main.py                 # FastAPI app + POST /login
  config.py               # pydantic-settings
  passwords.py            # bcrypt
  seed.py                 # demo user + demo-banking-app
  db/                     # applications + users (SQLAlchemy)
  services/login.py       # credential verify
tests/test_login.py
```

## Guardrails

- Import login models from `rba-contracts` (`LoginRequest` / `LoginResponse`).
- Do **not** call `/risk/evaluate` (IdP-3). Do **not** put identity in
  `decision-service`.
- Do **not** implement OIDC/SAML/SCIM (ADR-0014).
- Passwords: bcrypt only; never log or return the password.
- Do **not** add Redis/Postgres compose here — use `../rba-infra`.
- Only commit when explicitly asked; Conventional Commits; never commit secrets.

## Setup

```bash
cd ../rba-infra && docker compose up -d && cd -
python3.12 -m venv .venv && source .venv/bin/activate
pip install -e ../rba-contracts -e ".[dev]"
pytest -q
```
