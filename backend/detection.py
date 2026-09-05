"""
Detection engine.

The core idea: most dangerous API abuse (BOLA / IDOR, scraping, account
enumeration) looks 100% valid at the single-request level — valid token,
valid schema, valid rate limit. It only becomes visible as a *pattern*
across a sequence of requests from the same identity. So instead of
matching requests against static signatures, we score each request
against a live behavioral profile of the caller.

Three independent signals are combined into one anomaly score (0-100):

1. Ownership deviation  - is this identity touching a resource it has
   no established relationship to? (classic BOLA/IDOR precursor)
2. Sequential enumeration - is this identity walking through resource
   IDs in order, the signature of ID-guessing/scraping?
3. Velocity anomaly     - is this identity calling far faster than its
   own recent baseline (not just a fixed global rate limit)?

Scores map to an action: allow / throttle / block. Thresholds are
config so a team can demo the precision/recall trade-off live.
"""
from dataclasses import dataclass, field

from store import Profile, get_profile, ORDERS

THRESHOLD_THROTTLE = 40
THRESHOLD_BLOCK = 70

OWNERSHIP_WEIGHT = 45
ENUMERATION_WEIGHT = 35
VELOCITY_WEIGHT = 25
VELOCITY_LIMIT_PER_5S = 6


@dataclass
class Verdict:
    score: int
    reasons: list[str] = field(default_factory=list)
    action: str = "allow"


def _check_ownership(profile: Profile, resource_id: str, owner_id: str) -> tuple[int, str | None]:
    if owner_id == profile.user_id:
        profile.known_resource_ids.add(resource_id)
        return 0, None
    if resource_id in profile.known_resource_ids:
        # previously flagged/seen — still not theirs, still suspicious,
        # but don't re-explain every time
        return OWNERSHIP_WEIGHT, "Accessing a resource this identity does not own (BOLA)"
    return OWNERSHIP_WEIGHT, "Accessing a resource this identity does not own (BOLA)"


def _check_enumeration(profile: Profile, resource_type: str, resource_id: str) -> tuple[int, str | None]:
    history = profile.recent_ids[resource_type]
    history.append(resource_id)
    if len(history) < 4:
        return 0, None
    try:
        nums = [int(x) for x in history]
    except ValueError:
        return 0, None
    diffs = [b - a for a, b in zip(nums, nums[1:])]
    # monotonic +1 or -1 walk across the recent window = enumeration
    if all(d == 1 for d in diffs) or all(d == -1 for d in diffs):
        return ENUMERATION_WEIGHT, "Sequential ID enumeration pattern detected"
    return 0, None


def _check_velocity(profile: Profile) -> tuple[int, str | None]:
    v = profile.velocity(window_seconds=5.0)
    if v > VELOCITY_LIMIT_PER_5S:
        return VELOCITY_WEIGHT, f"Abnormal request velocity ({v} requests / 5s)"
    return 0, None


def evaluate_request(*, user_id: str, resource_type: str, resource_id: str, owner_id: str) -> Verdict:
    profile = get_profile(user_id)
    profile.record_request()

    score = 0
    reasons = []

    for check in (
        _check_ownership(profile, resource_id, owner_id),
        _check_enumeration(profile, resource_type, resource_id),
        _check_velocity(profile),
    ):
        pts, reason = check
        score += pts
        if reason:
            reasons.append(reason)

    score = min(score, 100)

    if score >= THRESHOLD_BLOCK:
        action = "block"
    elif score >= THRESHOLD_THROTTLE:
        action = "throttle"
    else:
        action = "allow"

    return Verdict(score=score, reasons=reasons, action=action)


def exposure_audit() -> list[dict]:
    """Static schema-diff: fields the API returns vs. fields the UI
    actually consumes. Flags excessive data exposure independent of
    any single request's behavior."""
    from store import ORDER_FIELDS_RETURNED_BY_API, ORDER_FIELDS_CONSUMED_BY_UI

    over_exposed = sorted(ORDER_FIELDS_RETURNED_BY_API - ORDER_FIELDS_CONSUMED_BY_UI)
    return [{
        "endpoint": "GET /orders/{order_id}",
        "fields_returned": sorted(ORDER_FIELDS_RETURNED_BY_API),
        "fields_consumed_by_ui": sorted(ORDER_FIELDS_CONSUMED_BY_UI),
        "over_exposed_fields": over_exposed,
        "risk": "high" if len(over_exposed) >= 3 else "medium" if over_exposed else "none",
        "recommendation": (
            f"Return a filtered response contract limited to "
            f"{sorted(ORDER_FIELDS_CONSUMED_BY_UI)} for this client, or introduce "
            f"a field-level scope so sensitive fields require elevated auth."
        ) if over_exposed else "No action needed.",
    }]
