"""
SIEM Integration — Pipes MongoDB indicators into Elasticsearch
"""

import sys, os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pymongo
from elasticsearch import Elasticsearch, helpers
from config.settings import (
    MONGO_URI, MONGO_DB, MONGO_COLLECTION,
    ELASTICSEARCH_HOST, ELASTICSEARCH_INDEX
)

client     = pymongo.MongoClient(MONGO_URI)
collection = client[MONGO_DB][MONGO_COLLECTION]
es         = Elasticsearch(ELASTICSEARCH_HOST)

INDEX_MAPPING = {
    "mappings": {
        "properties": {
            "ip_address":  {"type": "ip",      "ignore_malformed": True},
            "domain":      {"type": "keyword"},
            "url":         {"type": "keyword"},
            "threat_type": {"type": "keyword"},
            "source":      {"type": "keyword"},
            "risk_score":  {"type": "float"},
            "severity":    {"type": "keyword"},
            "status":      {"type": "keyword"},
            "is_blocked":  {"type": "boolean"},
            "tags":        {"type": "keyword"},
            "date_added":  {"type": "date"},
            "last_seen":   {"type": "date"},
            "normalized_at": {"type": "date"},
        }
    }
}

def create_index():
    if not es.indices.exists(index=ELASTICSEARCH_INDEX):
        es.indices.create(index=ELASTICSEARCH_INDEX, body=INDEX_MAPPING)
        print(f"  ✅ Created Elasticsearch index: {ELASTICSEARCH_INDEX}")
    else:
        print(f"  ℹ  Index '{ELASTICSEARCH_INDEX}' already exists.")

def generate_actions(batch_size=500):
    """Yield bulk-index actions from MongoDB."""
    cursor = collection.find({"normalized": True}, batch_size=batch_size)
    for doc in cursor:
        doc["_id"] = str(doc["_id"])  # serialize ObjectId
        yield {
            "_index": ELASTICSEARCH_INDEX,
            "_id":    doc["_id"],
            "_source": doc,
        }

def pipe_to_elasticsearch():
    print("\n[SIEM] Piping indicators to Elasticsearch...")
    try:
        success, errors = helpers.bulk(es, generate_actions(), raise_on_error=False)
        print(f"  ✅ Indexed {success} documents.")
        if errors:
            print(f"  ⚠  {len(errors)} errors during indexing.")
    except Exception as e:
        print(f"  ❌ Pipeline failed: {e}")

if __name__ == "__main__":
    print("=" * 55)
    print("  SIEM PIPELINE — Elasticsearch integration")
    print("=" * 55)

    if not es.ping():
        print("❌ Cannot reach Elasticsearch at", ELASTICSEARCH_HOST)
        print("   → Start it with: docker-compose up -d")
        sys.exit(1)

    create_index()
    pipe_to_elasticsearch()
    count = es.count(index=ELASTICSEARCH_INDEX)["count"]
    print(f"\n✅ Total documents in Elasticsearch: {count}")
    print("=" * 55)