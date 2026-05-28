"""
OSINT Threat Intelligence Scraper
Feeds: Feodo Tracker | URLhaus | CINS Score | AlienVault OTX
"""

import sys, os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import requests
import pymongo
from datetime import datetime, timezone
from config.settings import (
    MONGO_URI, MONGO_DB, MONGO_COLLECTION, OTX_API_KEY
)

# ── Database Setup ────────────────────────────────────────────────────────────
client     = pymongo.MongoClient(MONGO_URI)
db         = client[MONGO_DB]
collection = db[MONGO_COLLECTION]

# Unique index so duplicates are automatically rejected
collection.create_index([("ip_address", 1), ("source", 1)], unique=True, sparse=True)
collection.create_index([("url", 1), ("source", 1)],        unique=True, sparse=True)

# ── Helper ────────────────────────────────────────────────────────────────────
def now_utc():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def upsert(doc: dict):
    """Insert or update based on ip+source or url+source."""
    key = {"ip_address": doc.get("ip_address"), "source": doc["source"]} \
          if doc.get("ip_address") else \
          {"url": doc.get("url"), "source": doc["source"]}
    try:
        collection.update_one(key, {"$set": doc}, upsert=True)
    except Exception as e:
        print(f"  ⚠ DB write error: {e}")

# ── Feed 1: Feodo Tracker (Botnet C2 IPs) ────────────────────────────────────
def scrape_feodo_tracker():
    print("\n[1/4] Fetching Feodo Tracker botnet C2 IPs...")
    url = "https://feodotracker.abuse.ch/downloads/ipblocklist.csv"
    try:
        resp = requests.get(url, timeout=15)
        resp.raise_for_status()
        count = 0
        for line in resp.text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(",")
            if len(parts) < 2:
                continue
            ip = parts[1].strip().strip('"')
            if not ip:
                continue
            doc = {
                "ip_address":  ip,
                "domain":      None,
                "url":         None,
                "threat_type": "Botnet C2",
                "source":      "feodotracker",
                "risk_score":  0.0,
                "status":      "active",
                "is_blocked":  False,
                "tags":        ["botnet", "c2", "malware"],
                "normalized":  False,
                "date_added":  now_utc(),
                "last_seen":   now_utc(),
            }
            upsert(doc)
            count += 1
        print(f"  ✅ Feodo Tracker: {count} IPs ingested.")
    except Exception as e:
        print(f"  ❌ Feodo Tracker failed: {e}")

# ── Feed 2: URLhaus (Malware Distribution URLs) ───────────────────────────────
def scrape_urlhaus():
    print("\n[2/4] Fetching URLhaus malware URLs...")
    url = "https://urlhaus.abuse.ch/downloads/text/"
    try:
        resp = requests.get(url, timeout=15)
        resp.raise_for_status()
        count = 0
        for line in resp.text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            domain = line.split("/")[2] if "//" in line else line
            doc = {
                "ip_address":  None,
                "domain":      domain,
                "url":         line,
                "threat_type": "Malware Distribution",
                "source":      "urlhaus",
                "risk_score":  0.0,
                "status":      "active",
                "is_blocked":  False,
                "tags":        ["malware", "url", "phishing"],
                "normalized":  False,
                "date_added":  now_utc(),
                "last_seen":   now_utc(),
            }
            upsert(doc)
            count += 1
        print(f"  ✅ URLhaus: {count} URLs ingested.")
    except Exception as e:
        print(f"  ❌ URLhaus failed: {e}")

# ── Feed 3: CINS Score (Known Bad Actors) ─────────────────────────────────────
def scrape_cins():
    print("\n[3/4] Fetching CINS Score bad actor IPs...")
    url = "http://cinsscore.com/list/ci-badguys.txt"
    try:
        resp = requests.get(url, timeout=15)
        resp.raise_for_status()
        count = 0
        for line in resp.text.splitlines():
            ip = line.strip()
            if not ip or ip.startswith("#") or "/" in ip:
                continue
            doc = {
                "ip_address":  ip,
                "domain":      None,
                "url":         None,
                "threat_type": "Known Bad Actor",
                "source":      "cins_score",
                "risk_score":  0.0,
                "status":      "active",
                "is_blocked":  False,
                "tags":        ["scanner", "bruteforce", "recon"],
                "normalized":  False,
                "date_added":  now_utc(),
                "last_seen":   now_utc(),
            }
            upsert(doc)
            count += 1
        print(f"  ✅ CINS Score: {count} IPs ingested.")
    except Exception as e:
        print(f"  ❌ CINS Score failed: {e}")

# ── Feed 4: AlienVault OTX (requires free API key) ───────────────────────────
def scrape_alienvault_otx():
    print("\n[4/4] Fetching AlienVault OTX pulses...")
    if OTX_API_KEY == "YOUR_FREE_OTX_KEY_HERE":
        print("  ⚠ OTX API key not set. Skipping. Get a free key at otx.alienvault.com")
        return
    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    url     = "https://otx.alienvault.com/api/v1/pulses/subscribed?limit=20"
    try:
        resp = requests.get(url, headers=headers, timeout=20)
        resp.raise_for_status()
        pulses = resp.json().get("results", [])
        count  = 0
        for pulse in pulses:
            tags = pulse.get("tags", [])
            for indicator in pulse.get("indicators", []):
                itype = indicator.get("type", "")
                value = indicator.get("indicator", "")
                doc   = {
                    "ip_address":  value if itype in ("IPv4", "IPv6") else None,
                    "domain":      value if itype == "domain" else None,
                    "url":         value if itype == "URL" else None,
                    "threat_type": pulse.get("name", "Unknown")[:80],
                    "source":      "alienvault_otx",
                    "risk_score":  0.0,
                    "status":      "active",
                    "is_blocked":  False,
                    "tags":        tags,
                    "normalized":  False,
                    "date_added":  now_utc(),
                    "last_seen":   now_utc(),
                }
                upsert(doc)
                count += 1
        print(f"  ✅ AlienVault OTX: {count} indicators ingested.")
    except Exception as e:
        print(f"  ❌ AlienVault OTX failed: {e}")

# ── Main ──────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 55)
    print("  THREAT INTEL SCRAPER — Starting ingestion...")
    print("=" * 55)
    scrape_feodo_tracker()
    scrape_urlhaus()
    scrape_cins()
    scrape_alienvault_otx()
    total = collection.count_documents({})
    print(f"\n✅ Ingestion complete. Total indicators in DB: {total}")
    print("=" * 55)