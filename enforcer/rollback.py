"""
Rollback Manager
Reverses specific or all automated iptables blocks.
Run with: sudo python enforcer/rollback.py
"""

import sys, os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json
import subprocess
import pymongo
from datetime import datetime, timezone
from config.settings import (
    MONGO_URI, MONGO_DB, MONGO_COLLECTION,
    ROLLBACK_LOG_FILE, DRY_RUN
)

client     = pymongo.MongoClient(MONGO_URI)
collection = client[MONGO_DB][MONGO_COLLECTION]

def load_log() -> list:
    if not os.path.exists(ROLLBACK_LOG_FILE):
        print("No rollback log found. Nothing to rollback.")
        return []
    with open(ROLLBACK_LOG_FILE) as f:
        return json.load(f)

def save_log(entries: list):
    with open(ROLLBACK_LOG_FILE, "w") as f:
        json.dump(entries, f, indent=2)

def unblock_ip(ip: str) -> bool:
    if DRY_RUN:
        print(f"[DRY RUN] Would unblock: {ip}")
        return True

    cmd    = ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode == 0:
        collection.update_one(
            {"ip_address": ip},
            {"$set": {"is_blocked": False, "status": "active"}}
        )
        print(f"  ✅ Unblocked: {ip}")
        return True
    else:
        print(f"  ❌ Failed to unblock {ip}: {result.stderr.strip()}")
        return False

def rollback_single(ip: str):
    entries = load_log()
    match   = [e for e in entries if e["ip"] == ip]
    if not match:
        print(f"IP {ip} not found in rollback log.")
        return

    if unblock_ip(ip):
        remaining = [e for e in entries if e["ip"] != ip]
        save_log(remaining)
        print(f"Rollback log updated. {len(remaining)} rules remaining.")

def rollback_all():
    entries = load_log()
    if not entries:
        return
    print(f"Rolling back {len(entries)} blocked IPs...")
    success = 0
    for entry in entries:
        if unblock_ip(entry["ip"]):
            success += 1
    save_log([])
    print(f"\n✅ Rolled back {success}/{len(entries)} rules.")

def list_blocked():
    entries = load_log()
    if not entries:
        print("No active auto-blocks found.")
        return
    print(f"\n{'─'*60}")
    print(f"{'#':<4} {'IP Address':<20} {'Risk':<8} {'Blocked At'}")
    print(f"{'─'*60}")
    for i, e in enumerate(entries, 1):
        print(f"{i:<4} {e['ip']:<20} {e['risk_score']:<8} {e['blocked_at']}")
    print(f"{'─'*60}\n")

if __name__ == "__main__":
    print("\n🔄 ROLLBACK MANAGER")
    print("=" * 40)
    print("1. List all blocked IPs")
    print("2. Rollback a specific IP")
    print("3. Rollback ALL (full reset)")
    print("=" * 40)
    choice = input("Choose [1/2/3]: ").strip()

    if choice == "1":
        list_blocked()
    elif choice == "2":
        list_blocked()
        ip = input("Enter IP to unblock: ").strip()
        rollback_single(ip)
    elif choice == "3":
        confirm = input("⚠ This removes ALL auto-blocks. Type YES to confirm: ")
        if confirm.strip().upper() == "YES":
            rollback_all()