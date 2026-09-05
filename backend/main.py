"""
API Sentinel — backend.

Contains three logical layers in one process for demo simplicity:

  1. A mock "target" API (the thing being protected): /orders/{id}, /login
  2. The security layer: every protected route runs each request through
     detection.evaluate_request() before deciding to allow/throttle/block
  3. The dashboard API: read-only views into alerts / live access graph /
     exposure audit, plus an override endpoint for analysts

Run with:  python main.py   (serves on http://localhost:8000)
Dashboard: open dashboard/index.html in a browser (it calls this API)

Built on Flask's dev server only (no extra deps) so it runs anywhere
with just `pip install flask requests`.
"""
from flask import Flask, request, jsonify

import store
import detection

app = Flask(__name__)


@app.after_request
def add_cors_headers(resp):
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Access-Control-Allow-Headers"] = "*"
    resp.headers["Access-Control-Allow-Methods"] = "*"
    return resp


@app.route("/<path:_path>", methods=["OPTIONS"])
@app.route("/", methods=["OPTIONS"])
def cors_preflight(_path=""):
    return ("", 204)


# ---------------------------------------------------------------------------
# Auth (toy) — issues a bearer token for a given demo user
# ---------------------------------------------------------------------------

@app.post("/auth/login")
def login():
    body = request.get_json(force=True) or {}
    user_id = body.get("user_id")
    if user_id not in store.USERS:
        return jsonify({"error": "unknown user_id"}), 404
    token = store.issue_token(user_id)
    return jsonify({"token": token, "user_id": user_id})


def _authenticate():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None, ({"error": "missing bearer token"}, 401)
    token = auth[len("Bearer "):]
    user_id = store.resolve_token(token)
    if not user_id:
        return None, ({"error": "invalid token"}, 401)
    return user_id, None


# ---------------------------------------------------------------------------
# Protected target API — this is the "application being defended"
# ---------------------------------------------------------------------------

@app.get("/orders/<order_id>")
def get_order(order_id):
    user_id, err = _authenticate()
    if err:
        return jsonify(err[0]), err[1]

    order = store.ORDERS.get(order_id)
    if not order:
        return jsonify({"error": "order not found"}), 404

    verdict = detection.evaluate_request(
        user_id=user_id,
        resource_type="orders",
        resource_id=order_id,
        owner_id=order["owner_id"],
    )

    store.log_access(
        user_id=user_id, resource_type="orders", resource_id=order_id,
        score=verdict.score, action=verdict.action,
    )

    alert = None
    if verdict.reasons:
        alert = store.add_alert(
            user_id=user_id, resource_type="orders", resource_id=order_id,
            score=verdict.score, reasons=verdict.reasons, action=verdict.action,
        )

    if verdict.action == "block" and (alert is None or alert["override"] != "allow"):
        return jsonify({
            "message": "Request blocked by API Sentinel",
            "score": verdict.score,
            "reasons": verdict.reasons,
        }), 403

    # NOTE: intentionally returns the *full* over-exposed schema so the
    # exposure-audit endpoint has something real to flag. See detection.exposure_audit().
    return jsonify(order)


# ---------------------------------------------------------------------------
# Dashboard API
# ---------------------------------------------------------------------------

@app.get("/api/dashboard/alerts")
def dashboard_alerts():
    limit = int(request.args.get("limit", 50))
    return jsonify(list(reversed(store.ALERTS[-limit:])))


@app.get("/api/dashboard/stats")
def dashboard_stats():
    total = len(store.ACCESS_LOG)
    blocked = sum(1 for e in store.ACCESS_LOG if e["action"] == "block")
    throttled = sum(1 for e in store.ACCESS_LOG if e["action"] == "throttle")
    flagged_users = len({a["user_id"] for a in store.ALERTS})
    return jsonify({
        "total_requests": total,
        "blocked": blocked,
        "throttled": throttled,
        "allowed": total - blocked - throttled,
        "flagged_identities": flagged_users,
        "total_alerts": len(store.ALERTS),
    })


@app.get("/api/dashboard/graph")
def dashboard_graph():
    limit = int(request.args.get("limit", 200))
    nodes: dict[str, dict] = {}
    edges = []

    for entry in list(store.ACCESS_LOG)[-limit:]:
        user_node = f"user:{entry['user_id']}"
        res_node = f"{entry['resource_type']}:{entry['resource_id']}"

        nodes.setdefault(user_node, {
            "id": user_node, "type": "identity", "label": entry["user_id"], "max_score": 0,
        })
        nodes.setdefault(res_node, {
            "id": res_node, "type": "resource", "label": res_node, "max_score": 0,
        })
        nodes[user_node]["max_score"] = max(nodes[user_node]["max_score"], entry["score"])
        nodes[res_node]["max_score"] = max(nodes[res_node]["max_score"], entry["score"])

        edges.append({
            "source": user_node,
            "target": res_node,
            "score": entry["score"],
            "action": entry["action"],
            "ts": entry["ts"],
        })

    return jsonify({"nodes": list(nodes.values()), "edges": edges})


@app.get("/api/dashboard/exposure-audit")
def dashboard_exposure_audit():
    return jsonify(detection.exposure_audit())


@app.post("/api/dashboard/alerts/<alert_id>/override")
def override_alert(alert_id):
    body = request.get_json(force=True) or {}
    decision = body.get("decision")
    for a in store.ALERTS:
        if a["id"] == alert_id:
            a["override"] = decision
            return jsonify(a)
    return jsonify({"error": "alert not found"}), 404


@app.get("/api/dashboard/users")
def dashboard_users():
    return jsonify(list(store.USERS.values()))


@app.get("/")
def root():
    return jsonify({
        "service": "API Sentinel",
        "dashboard": "open dashboard/index.html separately",
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=False)
