"""
Flask Dashboard API
"""

import sys, os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, render_template, jsonify, request
from flask_cors import CORS
import pymongo
import json
from datetime import datetime, timezone
from collections import Counter
from config.settings import (
    MONGO_URI, MONGO_DB, MONGO_COLLECTION,
    ROLLBACK_LOG_FILE, FLASK_HOST, FLASK_PORT, FLASK_DEBUG, DRY_RUN
)

app        = Flask(__name__)
CORS(app)
client     = pymongo.MongoClient(MONGO_URI)
collection = client[MONGO_DB][MONGO_COLLECTION]

# ── Page ───────────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return render_template("index.html")

# ── Stats Summary ──────────────────────────────────────────────────────────────
@app.route("/api/stats")
def stats():
    total    = collection.count_documents({})
    high     = collection.count_documents({"severity": "HIGH"})
    medium   = collection.count_documents({"severity": "MEDIUM"})
    low      = collection.count_documents({"severity": "LOW"})
    blocked  = collection.count_documents({"is_blocked": True})

    rollback_log = []
    if os.path.exists(ROLLBACK_LOG_FILE):
        with open(ROLLBACK_LOG_FILE) as f:
            rollback_log = json.load(f)

    return jsonify({
        "total":          total,
        "high_risk":      high,
        "medium_risk":    medium,
        "low_risk":       low,
        "blocked":        blocked,
        "active_rules":   len(rollback_log),
    })

# ── Recent Threats ─────────────────────────────────────────────────────────────
@app.route("/api/threats")
def threats():
    limit  = int(request.args.get("limit", 50))
    cursor = collection.find(
        {"normalized": True},
        {"_id": 0, "ip_address": 1, "domain": 1, "threat_type": 1,
         "risk_score": 1, "severity": 1, "source": 1,
         "is_blocked": 1, "status": 1, "date_added": 1, "tags": 1}
    ).sort("risk_score", pymongo.DESCENDING).limit(limit)
    return jsonify(list(cursor))

# ── Blocked IPs ────────────────────────────────────────────────────────────────
@app.route("/api/blocked")
def blocked():
    if not os.path.exists(ROLLBACK_LOG_FILE):
        return jsonify([])
    with open(ROLLBACK_LOG_FILE) as f:
        return jsonify(json.load(f))

# ── Chart Data ─────────────────────────────────────────────────────────────────
@app.route("/api/charts")
def charts():
    all_docs = list(collection.find({"normalized": True}, {"threat_type": 1, "severity": 1, "risk_score": 1, "_id": 0}))

    threat_counts = Counter(d.get("threat_type", "Unknown") for d in all_docs)
    severity_counts = {
        "HIGH":   collection.count_documents({"severity": "HIGH"}),
        "MEDIUM": collection.count_documents({"severity": "MEDIUM"}),
        "LOW":    collection.count_documents({"severity": "LOW"}),
    }

    # Risk score distribution buckets
    buckets = {"0–2": 0, "2–4": 0, "4–6": 0, "6–8": 0, "8–10": 0}
    for d in all_docs:
        s = d.get("risk_score", 0)
        if   s < 2:  buckets["0–2"]  += 1
        elif s < 4:  buckets["2–4"]  += 1
        elif s < 6:  buckets["4–6"]  += 1
        elif s < 8:  buckets["6–8"]  += 1
        else:        buckets["8–10"] += 1

    return jsonify({
        "threat_types":    dict(threat_counts.most_common(6)),
        "severity":        severity_counts,
        "risk_buckets":    buckets,
    })

# ── Manual Block ───────────────────────────────────────────────────────────────
@app.route("/api/block", methods=["POST"])
def manual_block():
    data = request.get_json()
    ip   = data.get("ip", "").strip()
    if not ip:
        return jsonify({"error": "No IP provided"}), 400

    collection.update_one(
        {"ip_address": ip},
        {"$set": {"is_blocked": True, "status": "blocked", "severity": "HIGH"}},
        upsert=True
    )
    return jsonify({"success": True, "message": f"Marked {ip} as blocked."})

# ── Rollback Endpoint ──────────────────────────────────────────────────────────
@app.route("/api/rollback", methods=["POST"])
def rollback():
    data = request.get_json()
    ip   = data.get("ip", "").strip()
    if not ip:
        return jsonify({"error": "No IP provided"}), 400

    collection.update_one(
        {"ip_address": ip},
        {"$set": {"is_blocked": False, "status": "active"}}
    )

    if os.path.exists(ROLLBACK_LOG_FILE):
        with open(ROLLBACK_LOG_FILE) as f:
            entries = json.load(f)
        entries = [e for e in entries if e["ip"] != ip]
        with open(ROLLBACK_LOG_FILE, "w") as f:
            json.dump(entries, f, indent=2)

    return jsonify({"success": True, "message": f"Rolled back block on {ip}."})

if __name__ == "__main__":
    print(f"\n🌐 Dashboard running at http://localhost:{FLASK_PORT}")
    print(f"   DRY_RUN mode: {DRY_RUN}")
    app.run(host=FLASK_HOST, port=FLASK_PORT, debug=FLASK_DEBUG)