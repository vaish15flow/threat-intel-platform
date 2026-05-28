import os

# ── MongoDB ──────────────────────────────────────────────
MONGO_URI        = os.getenv("MONGO_URI", "mongodb://localhost:27017/")
MONGO_DB         = "threat_intel"
MONGO_COLLECTION = "indicators"

# ── Elasticsearch ────────────────────────────────────────
ELASTICSEARCH_HOST  = os.getenv("ES_HOST", "http://localhost:9200")
ELASTICSEARCH_INDEX = "threat_indicators"

# ── Risk Score Thresholds ────────────────────────────────
HIGH_RISK_THRESHOLD   = 7.0
MEDIUM_RISK_THRESHOLD = 4.0

# ── Policy Enforcer ──────────────────────────────────────
ENFORCER_POLL_INTERVAL = 30          # seconds between scans
ROLLBACK_LOG_FILE      = "logs/rollback_log.json"
BLOCKED_LOG_FILE       = "logs/blocked_ips.log"
DRY_RUN = os.getenv("DRY_RUN", "false").lower() == "true"  # set True on Windows

# ── AlienVault OTX (free key at otx.alienvault.com) ─────
OTX_API_KEY = os.getenv("OTX_API_KEY", "YOUR_FREE_OTX_KEY_HERE")

# ── Flask Dashboard ──────────────────────────────────────
FLASK_HOST  = "0.0.0.0"
FLASK_PORT  = 5000
FLASK_DEBUG = True