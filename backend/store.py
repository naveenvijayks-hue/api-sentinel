"""
In-memory data store for API Sentinel.

Everything here is intentionally in-memory (dicts/lists/deques) so the
whole demo can run with zero external dependencies (no Postgres/Redis
needed). Swap for a real DB/cache in production.
"""
import time
import uuid
from collections import deque, defaultdict

# ---------------------------------------------------------------------------
# Identity & ownership (simulated backend "truth")
# ---------------------------------------------------------------------------

# token -> user_id
TOKENS: dict[str, str] = {}

# user_id -> user record
USERS: dict[str, dict] = {
    "user_1": {"user_id": "user_1", "name": "Alice"},
    "user_2": {"user_id": "user_2", "name": "Bob"},
    "user_3": {"user_id": "user_3", "name": "Carla"},
    "attacker_1": {"user_id": "attacker_1", "name": "Unknown"},
}

# order_id -> full order record (owner_id + sensitive fields)
ORDERS: dict[str, dict] = {}


def _seed_orders():
    # owners[i % 3]: user_1 owns i%3==0 (3,6,9...), user_2 owns i%3==1 (1,4,7...),
    # user_3 owns i%3==2 (2,5,8...)
    owners = ["user_1", "user_2", "user_3"]
    for i in range(1, 41):
        owner = owners[i % len(owners)]
        ORDERS[str(i)] = {
            "order_id": str(i),
            "owner_id": owner,
            "item": f"Item-{i}",
            "total": round(19.99 + i * 3.5, 2),
            # sensitive / over-exposed fields a naive API might leak
            "shipping_address": f"{100 + i} Main St",
            "card_last4": f"{4000 + i}",
            "customer_email": f"{owner}@example.com",
            "internal_risk_score": round((i * 17) % 100 / 100, 2),
        }


_seed_orders()

# The fields the *legitimate frontend* actually renders for an order.
# Anything beyond this returned by the API is "excessive data exposure".
ORDER_FIELDS_CONSUMED_BY_UI = {"order_id", "item", "total"}
ORDER_FIELDS_RETURNED_BY_API = set(next(iter(ORDERS.values())).keys())


def issue_token(user_id: str) -> str:
    token = str(uuid.uuid4())
    TOKENS[token] = user_id
    return token


def resolve_token(token: str) -> str | None:
    return TOKENS.get(token)


# ---------------------------------------------------------------------------
# Behavioral profiles (per identity, built up live from traffic)
# ---------------------------------------------------------------------------

class Profile:
    """Rolling behavioral profile for a single identity (token/user)."""

    def __init__(self, user_id: str):
        self.user_id = user_id
        # resource ids this identity has legitimately owned/touched before
        self.known_resource_ids: set[str] = set()
        # last N (resource_type, resource_id) accesses, for enumeration detection
        self.recent_ids: dict[str, deque] = defaultdict(lambda: deque(maxlen=8))
        # timestamps of recent requests, for velocity detection
        self.request_times: deque = deque(maxlen=50)

    def record_request(self):
        self.request_times.append(time.time())

    def velocity(self, window_seconds: float = 5.0) -> int:
        now = time.time()
        return sum(1 for t in self.request_times if now - t <= window_seconds)


PROFILES: dict[str, Profile] = {}


def get_profile(user_id: str) -> Profile:
    if user_id not in PROFILES:
        PROFILES[user_id] = Profile(user_id)
    return PROFILES[user_id]


# ---------------------------------------------------------------------------
# Alerts + access log (feeds the dashboard)
# ---------------------------------------------------------------------------

ALERTS: list[dict] = []
ACCESS_LOG: list[dict] = deque(maxlen=500)


def add_alert(*, user_id, resource_type, resource_id, score, reasons, action):
    alert = {
        "id": str(uuid.uuid4()),
        "ts": time.time(),
        "user_id": user_id,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "score": score,
        "reasons": reasons,
        "action": action,       # "allow" | "throttle" | "block"
        "override": None,        # set by an analyst later: "allow" | "block"
    }
    ALERTS.append(alert)
    return alert


def log_access(*, user_id, resource_type, resource_id, score, action):
    ACCESS_LOG.append({
        "ts": time.time(),
        "user_id": user_id,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "score": score,
        "action": action,
    })
