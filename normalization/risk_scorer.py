"""
Risk Scoring & Normalization Engine
Reads raw indicators from MongoDB and assigns risk scores 0.0 – 10.0
"""

import sys, os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pymongo
from datetime import datetime, timezone
from config.settings import (
    MONGO_URI, MONGO_DB, MONGO_COLLECTION,
    HIGH_RISK_THRESHOLD, MEDIUM_RISK_THRESHOLD
)

client     = pymongo.MongoClient(MONGO_URI)
db         = client[MONGO_DB]
collection = db[MONGO_COLLECTION]

# ── Scoring Tables ─────────────────────────────────────────────────────────────
SOURCE_SCORES = {
    "feodotracker":    9.0,   # Active botnet C2 – extremely reliable
    "alienvault_otx":  8.0,
    "cins_score":      7.5,
    "urlhaus":         7.0,
    "placeholder":     0.0,
}

THREAT_TYPE_BONUS = {
    "Botnet C2":              1.5,
    "Malware Hosting":        1.2,
    "Malware Distribution":   1.0,
    "Known Bad Actor":        0.8,
    "Phishing":               0.9,
    "Ransomware":             1.5,
    "Unknown":                0.0,
}

TAG_BONUSES = {
    "ransomware": 1.0,
    "apt":        1.0,
    "c2":         0.8,
    "botnet":     0.7,
    "malware":    0.5,
    "phishing":   0.4,
    "scanner":    0.2,
    "recon":      0.2,
}

# ── Scoring Function ───────────────────────────────────────────────────────────
def calculate_risk_score(doc: dict) -> float:
    base  = SOURCE_SCORES.get(doc.get("source", ""), 5.0)
    bonus = THREAT_TYPE_BONUS.get(doc.get("threat_type", "Unknown"), 0.0)

    tag_bonus = 0.0
    for tag in doc.get("tags", []):
        tag_bonus += TAG_BONUSES.get(tag.lower(), 0.0)
    tag_bonus = min(tag_bonus, 1.5)      # cap tag contribution

    score = base + bonus + tag_bonus
    return round(min(score, 10.0), 2)    # cap at 10.0

def severity_label(score: float) -> str:
    if score >= HIGH_RISK_THRESHOLD:   return "HIGH"
    if score >= MEDIUM_RISK_THRESHOLD: return "MEDIUM"
    return "LOW"

# ── Main Normalization Pass ────────────────────────────────────────────────────
def normalize_all():
    cursor = collection.find({"normalized": False})
    updated = 0

    for doc in cursor:
        score    = calculate_risk_score(doc)
        severity = severity_label(score)

        collection.update_one(
            {"_id": doc["_id"]},
            {"$set": {
                "risk_score":      score,
                "severity":        severity,
                "normalized":      True,
                "normalized_at":   datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            }}
        )
        updated += 1

    return updated

if __name__ == "__main__":
    print("=" * 55)
    print("  RISK SCORER — Normalizing indicators...")
    print("=" * 55)
    count = normalize_all()
    print(f"\n✅ Normalized {count} indicators.")

    # Summary breakdown
    high   = collection.count_documents({"severity": "HIGH"})
    medium = collection.count_documents({"severity": "MEDIUM"})
    low    = collection.count_documents({"severity": "LOW"})
    print(f"   🔴 HIGH:   {high}")
    print(f"   🟡 MEDIUM: {medium}")
    print(f"   🟢 LOW:    {low}")
    print("=" * 55)