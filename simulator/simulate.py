"""
Traffic simulator for demoing API Sentinel live.

Run the backend first:
    cd backend && uvicorn main:app --reload --port 8000

Then in another terminal:
    python simulate.py normal      # a legit user browsing their own orders
    python simulate.py attacker    # BOLA enumeration attack
    python simulate.py burst       # velocity/abuse burst from one identity
    python simulate.py all         # runs all three, spaced out, for a full demo
"""
import sys
import time
import requests

BASE = "http://localhost:8000"


def login(user_id: str) -> str:
    r = requests.post(f"{BASE}/auth/login", json={"user_id": user_id})
    r.raise_for_status()
    return r.json()["token"]


def get_order(token: str, order_id: str):
    r = requests.get(f"{BASE}/orders/{order_id}", headers={"Authorization": f"Bearer {token}"})
    print(f"  order {order_id}: {r.status_code} {'BLOCKED' if r.status_code == 403 else ''}")
    return r


def scenario_normal():
    print("[normal] Alice browsing her own orders...")
    token = login("user_1")
    # user_1 owns orders where i % 3 == 0 -> 3,6,9,12...
    for oid in ["3", "6", "9"]:
        get_order(token, oid)
        time.sleep(0.5)


def scenario_attacker():
    print("[attacker] enumerating order IDs sequentially with a stolen/guessed token...")
    token = login("attacker_1")
    for oid in range(1, 15):
        get_order(token, str(oid))
        time.sleep(0.15)


def scenario_burst():
    print("[burst] one identity hammering the endpoint far above its own baseline...")
    token = login("user_2")
    # order 4 is genuinely user_2's own order (i % 3 == 1) — isolates the
    # velocity signal from the ownership signal for a clean demo.
    for _ in range(20):
        get_order(token, "4")
        time.sleep(0.05)


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "all"
    if mode == "normal":
        scenario_normal()
    elif mode == "attacker":
        scenario_attacker()
    elif mode == "burst":
        scenario_burst()
    elif mode == "all":
        scenario_normal()
        print()
        time.sleep(1)
        scenario_attacker()
        print()
        time.sleep(1)
        scenario_burst()
    else:
        print("usage: python simulate.py [normal|attacker|burst|all]")


if __name__ == "__main__":
    main()
