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

**This slice is IdP-3:** password verify then `POST /risk/evaluate`; map action
→ outcome + reasons. Do **not** issue sessions, add MFA challenges, UI, admin,
or OIDC until those stages.

## Layout

```
src/rba_idp/
  main.py                 # FastAPI app + POST /login
  config.py               # pydantic-settings
  passwords.py            # bcrypt
  pdp.py                  # HttpPdpClient → /risk/evaluate
  seed.py                 # demo user + demo-banking-app
  db/                     # applications + users (SQLAlchemy)
  services/login.py       # credential verify + PDP enforce
tests/test_login.py
tests/test_pdp.py
```

## Guardrails

- Import login / evaluate models from `rba-contracts`. Map actions with
  `outcome_from_action` — do not re-implement the mapping.
- Call `/risk/evaluate` only after a successful password verify. Never send
  the password (or email) to the PDP.
- Do **not** put identity in `decision-service`.
- Do **not** implement OIDC/SAML/SCIM (ADR-0014).
- Do **not** add session cookies or MFA OTP yet (IdP-4).
- Passwords: bcrypt only; never log or return the password.
- Do **not** add Redis/Postgres compose here — use `../rba-infra`.
- PDP unavailable → HTTP 503 (fail closed). Do not invent a `BLOCK`.
- Only commit when explicitly asked; Conventional Commits; never commit secrets.

## Setup

```bash
cd ../rba-infra && docker compose up -d && cd -
python3.12 -m venv .venv && source .venv/bin/activate
pip install -e ../rba-contracts -e ".[dev]"
pytest -q
```
