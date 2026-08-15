# AGENTS.md — rba-idp

Thesis-scale **IdP** (PEP / product shell) for a risk-based authentication (RBA)
thesis. Identity lives here; risk scoring stays in `rba-decision-service`.
Portable orientation for any AI coding tool.

## Where we are / where things are stated

**Polyrepo** (org `github.com/roku-pfi`), siblings cloned side-by-side. Roadmap /
status / decisions live in the **`docs`** repo (`../docs`):

- **Current status → `../docs/plans/status.md`**
- Phase rationale → `../docs/plans/development_plan.md` §8 Phase 7
- Decisions → `../docs/decisions/` (ADR-0012–0016)
- Narrative → `../docs/devlog.md`

**This slice is IdP-5:** hosted login HTML on this origin. Do **not** add admin
or OIDC until those stages ([ADR-0016](../docs/decisions/0016-hosted-login-on-idp.md)).

## Layout

```
src/rba_idp/
  main.py                 # FastAPI: HTML GET / /login + JSON API
  config.py               # pydantic-settings
  passwords.py            # bcrypt
  pdp.py                  # HttpPdpClient → /risk/evaluate
  tokens.py               # opaque session token + mock OTP compare
  seed.py                 # demo user + demo-banking-app
  db/                     # applications, users, sessions, mfa_challenges
  services/login.py       # verify + PDP enforce + session/challenge
  web/                    # hosted login templates + static
tests/test_login.py
tests/test_pdp.py
tests/test_session.py
tests/test_hosted_login.py
```

## Guardrails

- Import login / evaluate models from `rba-contracts`. Map actions with
  `outcome_from_action` — do not re-implement the mapping.
- Call `/risk/evaluate` only after a successful password verify. Never send
  the password (or email) to the PDP. Completing MFA does **not** re-score.
- Do **not** put identity in `decision-service`.
- Do **not** implement OIDC/SAML/SCIM (ADR-0014).
- Do **not** add an admin console yet (IdP-6). Hosted login stays here, not a
  new `rba-frontend` repo (ADR-0016).
- Passwords: bcrypt only; never log or return the password.
- Session tokens: opaque, stored hashed; `Authorization: Bearer`.
- MFA: mock OTP (`000000`) is enough. No WebAuthn/TOTP provider.
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
