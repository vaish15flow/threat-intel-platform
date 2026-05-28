"""
Dynamic Security Policy Enforcer Daemon
Monitors high-risk IPs and auto-blocks them via iptables.
Run with: sudo python enforcer/policy_daemon.py
Use DRY_RUN=true for testing without root.
"""

import sys, os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import time
import json
import signal
import subprocess
import logging
from datetime import datetime, timezone
import pymongo
from config.settings import (
    MONGO_URI, MONGO_DB, MONGO_COLLECTION,
    HIGH_RISK_THRESHOLD, ENFORCER_POLL_INTERVAL,
    ROLLBACK_LOG_FILE, BLOCKED_LOG_FILE, DRY_RUN
)

# ── Logging Setup ──────────────────────────────────────────────────────────────
os.makedirs("logs", exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [ENFORCER] %(levelname)s — %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(BLOCKED_LOG_FILE),
    ]
)
log = logging.getLogger(__name__)

# ── Database ───────────────────────────────────────────────────────────────────
client     = pymongo.MongoClient(MONGO_URI)
collection = client[MONGO_DB][MONGO_COLLECTION]

# ── Rollback Log (JSON) ────────────────────────────────────────────────────────
def load_rollback_log() -> list:
    if os.path.exists(ROLLBACK_LOG_FILE):
        with open(ROLLBACK_LOG_FILE, "r") as f:
            return json.load(f)
    return []

def save_rollback_log(entries: list):
    os.makedirs(os.path.dirname(ROLLBACK_LOG_FILE), exist_ok=True)
    with open(ROLLBACK_LOG_FILE, "w") as f:
        json.dump(entries, f, indent=2)

# ── iptables Helpers ───────────────────────────────────────────────────────────
def rule_exists(ip: str) -> bool:
    """Check if an iptables DROP rule already exists for this IP."""
    result = subprocess.run(
        ["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"],
        capture_output=True
    )
    return result.returncode == 0

def block_ip(ip: str, risk_score: float, threat_type: str):
    if DRY_RUN:
        log.info(f"[DRY RUN] Would block: {ip} | Score: {risk_score} | Type: {threat_type}")
        return True

    if rule_exists(ip):
        log.info(f"Already blocked: {ip} — skipping.")
        return False

    cmd = ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode == 0:
        log.info(f"🚫 BLOCKED: {ip} | Risk: {risk_score} | Type: {threat_type}")
        entry = {
            "ip":          ip,
            "risk_score":  risk_score,
            "threat_type": threat_type,
            "blocked_at":  datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "command":     " ".join(cmd),
        }
        rollback_log = load_rollback_log()
        rollback_log.append(entry)
        save_rollback_log(rollback_log)

        # Mark as blocked in MongoDB
        collection.update_one(
            {"ip_address": ip},
            {"$set": {"is_blocked": True, "status": "blocked"}}
        )
        return True
    else:
        log.error(f"Failed to block {ip}: {result.stderr}")
        return False

# ── Main Scan Loop ─────────────────────────────────────────────────────────────
running = True

def shutdown(sig, frame):
    global running
    log.info("Shutdown signal received. Stopping daemon...")
    running = False

signal.signal(signal.SIGTERM, shutdown)
signal.signal(signal.SIGINT,  shutdown)

def scan_and_enforce():
    query = {
        "severity":   "HIGH",
        "is_blocked": False,
        "ip_address": {"$ne": None},
        "status":     "active",
    }
    threats = list(collection.find(query))
    if not threats:
        log.info("No new high-risk IPs to block.")
        return

    log.info(f"Found {len(threats)} high-risk IPs to evaluate...")
    blocked = 0
    for doc in threats:
        ip = doc.get("ip_address")
        if ip:
            if block_ip(ip, doc.get("risk_score", 0), doc.get("threat_type", "Unknown")):
                blocked += 1

    log.info(f"Cycle complete. Newly blocked: {blocked}")

if __name__ == "__main__":
    mode = "DRY RUN" if DRY_RUN else "LIVE (iptables)"
    log.info(f"{'='*50}")
    log.info(f"  Dynamic Policy Enforcer started — Mode: {mode}")
    log.info(f"  Poll interval: {ENFORCER_POLL_INTERVAL}s | Threshold: {HIGH_RISK_THRESHOLD}")
    log.info(f"{'='*50}")

    while running:
        scan_and_enforce()
        time.sleep(ENFORCER_POLL_INTERVAL)

    log.info("Enforcer daemon stopped cleanly.")