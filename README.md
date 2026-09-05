# API Sentinel

Behavioral threat detection for APIs. Instead of matching requests against
static signatures (regex/WAF rules), API Sentinel builds a live behavioral
profile per identity (token/user) and scores each request against it. This
catches the attacks that matter most and that signature tools structurally
can't see — **BOLA/IDOR, ID enumeration, and abuse patterns** — because any
single request in these attacks is perfectly valid (correct token, correct
schema, under any fixed rate limit). The attack is only visible as a
*pattern across a sequence of requests*.

## Why this approach

| Attack class | Looks valid at request-level? | Caught by regex/WAF? | Caught here? |
|---|---|---|---|
| SQLi / XSS in a field | No — malformed payload | Yes | Yes (out of scope for this demo, but same middleware) |
| BOLA / IDOR | **Yes** | No | **Yes** — ownership-deviation signal |
| ID enumeration / scraping | **Yes**, one request at a time | No | **Yes** — sequential-access signal |
| Credential-stuffing / abuse bursts | **Yes** | Only via fixed global limits | **Yes** — per-identity velocity baseline |
| Excessive data exposure | **Yes** — it's just "too much" in the response | No | **Yes** — static schema-diff audit |

## Architecture

```
                     ┌─────────────────────────┐
   client request →  │   Flask app (main.py)    │
                     │  ┌────────────────────┐  │
                     │  │ auth (toy tokens)  │  │
                     │  ├────────────────────┤  │
                     │  │ /orders/{id}       │──┼──► detection.evaluate_request()
                     │  │ (protected route)  │  │        │
                     │  └────────────────────┘  │        ▼
                     │                           │   store.Profile (per identity)
                     │  ┌────────────────────┐  │     - known_resource_ids
                     │  │ dashboard API      │◄─┼──── - recent_ids (enum window)
                     │  │ /api/dashboard/*   │  │     - request_times (velocity)
                     │  └────────────────────┘  │
                     └─────────────────────────┘
                                  ▲
                                  │ polls every 1.5s
                     ┌─────────────────────────┐
                     │  dashboard/index.html    │
                     │  - live force-graph      │
                     │  - alert feed + override │
                     │  - exposure audit panel  │
                     └─────────────────────────┘
```

- **`backend/store.py`** — in-memory "source of truth": users, tokens,
  resources + real ownership, and the live behavioral `Profile` per identity.
- **`backend/detection.py`** — the detection engine. Three independent
  signals (ownership deviation, sequential enumeration, velocity anomaly)
  combine into a 0–100 anomaly score, mapped to allow/throttle/block. Also
  contains the static excessive-data-exposure schema audit.
- **`backend/main.py`** — the mock target API (`/orders/{id}`) guarded by
  the detection engine, plus the dashboard's read/override API.
- **`dashboard/index.html`** — single-file live console: force-directed
  access graph (identities ↔ resources, colored/sized by anomaly score),
  alert feed with one-click override, and the exposure audit.
- **`simulator/simulate.py`** — generates realistic traffic: a normal user,
  a BOLA/enumeration attacker, and a velocity-burst abuser, so you can
  demo detection live instead of describing it.

## Running it

```bash
pip install flask requests

cd backend
python main.py            # serves on http://localhost:8000
```

Open `dashboard/index.html` directly in a browser (it talks to
`localhost:8000`).

In another terminal, generate traffic:

```bash
cd simulator
python simulate.py normal     # clean baseline — no alerts
python simulate.py attacker   # BOLA enumeration — watch it get caught mid-attack
python simulate.py burst      # velocity-only abuse from a legitimate identity
python simulate.py all        # runs all three, spaced out
```

Watch the dashboard: the access graph lights up red around the attacker
node, the alert feed shows exactly which signals fired and why, and you can
override any decision live (e.g. "allow anyway" to show a security engineer
retains final say).

## Tuning the detection engine

All thresholds live at the top of `backend/detection.py`:

```python
THRESHOLD_THROTTLE = 40
THRESHOLD_BLOCK = 70
OWNERSHIP_WEIGHT = 45
ENUMERATION_WEIGHT = 35
VELOCITY_WEIGHT = 25
VELOCITY_LIMIT_PER_5S = 6
```

This is deliberately exposed and simple (not a black-box ML model) so you
can explain — and a judge can verify — exactly why any given request was
flagged. That explainability is itself part of the pitch: a security team
won't trust a system whose blocking decisions it can't audit.

## What to build next (if you have more hackathon time)

- Extend `evaluate_request` to a second resource type (e.g. `/users/{id}/profile`)
  to show the engine generalizes beyond one endpoint.
- Replace the fixed velocity window with an EWMA baseline per identity so
  "abnormal" is relative to that identity's own history, not a global constant.
- Persist `store.py`'s in-memory state to SQLite/Redis for a real deployment.
- Auto-infer `ORDER_FIELDS_CONSUMED_BY_UI` from real frontend network logs
  instead of hardcoding it, so the exposure audit needs no manual config.
