import pymongo
from datetime import datetime

def connect_to_database():
    try:
        client = pymongo.MongoClient("mongodb://localhost:27017/")
        
        db = client["threat_intel"]
        
        collection = db["indicators"]
        
        print("🎉 Success! Connected to MongoDB seamlessly.")
        
        sample_threat = {
            "ip_address": "1.1.1.1",
            "threat_type": "Malware Hosting",
            "risk_score": 0.0,
            "status": "placeholder",
            "date_added": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        }
        
        inserted = collection.insert_one(sample_threat)
        print(f"Inserted dummy test record with ID: {inserted.inserted_id}")
        
    except Exception as e:
        print(f"❌ Connection failed. Error: {e}")

if __name__ == "__main__":
    connect_to_database()