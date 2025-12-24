# database.py
from pymongo import MongoClient, UpdateOne, DESCENDING
from config import MONGO_URI, DB_NAME, COLLECTION_NAME

class Database:
    def __init__(self):
        self.client = MongoClient(MONGO_URI)
        self.db = self.client[DB_NAME]
        self.collection = self.db[COLLECTION_NAME]

    def insert_batch(self, cves):
        if cves:
            # unique=True prevents duplicate CVE IDs
            self.collection.create_index("cve.id", unique=True)
            
            # Index on lastModified for faster sorting/syncing
            self.collection.create_index([("cve.lastModified", DESCENDING)])

            operations = []
            for item in cves:
                cve_id = item.get("cve", {}).get("id")
                if cve_id:
                    operations.append(
                        UpdateOne({"cve.id": cve_id}, {"$set": item}, upsert=True)
                    )
            
            if operations:
                self.collection.bulk_write(operations)

    def get_cve_by_id(self, cve_id):
        return self.collection.find_one({"cve.id": cve_id}, {"_id": 0})

    def get_cves_by_date(self, days_ago_date):
        query = {
            "cve.lastModified": {"$gte": days_ago_date}
        }
        return list(self.collection.find(query, {"_id": 0}))

    
    def get_latest_timestamp(self):
        """
        Finds the most recent 'lastModified' date in the database.
        Returns: ISO Format String (e.g., '2023-10-25T10:00:00') or None
        """
        # Sort by lastModified descending (newest first) and take 1
        latest = self.collection.find_one(sort=[("cve.lastModified", DESCENDING)])
        
        if latest and "cve" in latest and "lastModified" in latest["cve"]:
            return latest["cve"]["lastModified"]
        return None

db = Database()