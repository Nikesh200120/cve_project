# main.py
from fastapi import FastAPI, HTTPException, Query
from datetime import datetime, timedelta
from database import db

app = FastAPI(
    title="NVD CVE API",
    description="API to query CVE data fetched from NVD",
    version="1.0"
)

@app.get("/")
def home():
    return {"message": "Welcome to the CVE API. Use /cves/{cve_id} or /cves/recent to query."}

# 1. Retrieval by CVE ID
@app.get("/cves/{cve_id}")
def get_cve_by_id(cve_id: str):
    """
    Fetch details of a specific CVE by its ID (e.g., CVE-2023-1234).
    """
    result = db.get_cve_by_id(cve_id)
    if result:
        return result
    raise HTTPException(status_code=404, detail="CVE not found")

# 2. Filter by Last Modified Date
@app.get("/cves/recent/")
def get_recent_cves(days: int = Query(..., description="Number of days to look back")):
    """
    Fetch CVEs modified within the last X days.
    """
    if days < 0:
        raise HTTPException(status_code=400, detail="Days cannot be negative")

    # Calculate the date threshold
    cutoff_date = datetime.now() - timedelta(days=days)
    # Convert to ISO format string to match NVD format (e.g. 2023-10-01T00:00:00)
    cutoff_str = cutoff_date.isoformat()

    results = db.get_cves_by_date(cutoff_str)
    
    return {
        "count": len(results),
        "days_lookback": days,
        "cves": results
    }
# 3. Check count of records
@app.get("/stats")
def get_db_stats():
    count = db.collection.count_documents({})
    return {"total_cves_stored": count}