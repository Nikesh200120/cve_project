# fetch_cve.py
import requests
import time
from datetime import datetime, timedelta, timezone
from config import NVD_API_URL, RESULTS_PER_PAGE, SLEEP_TIME
from database import db

def fetch_and_store_data():
    # 1. Check database for the latest CVE date
    last_mod_date = db.get_latest_timestamp()
    
    # 2. Setup the API Parameters
    params = {
        "resultsPerPage": RESULTS_PER_PAGE,
        "startIndex": 0
    }

    if last_mod_date:
        print(f"--- Incremental Sync Detected ---")
        print(f"Latest CVE in DB is from: {last_mod_date}")
        
        # NVD requires both start and end date if filtering by date
        # We set start date to our last known date, and end date to NOW.
        params["lastModStartDate"] = last_mod_date
        params["lastModEndDate"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        
        # NOTE: NVD API limits the range to 120 days. 
        # If your script hasn't run in >120 days, you might need a full re-sync.
    else:
        print("--- Full Sync Detected (Database is empty) ---")

    # 3. Start the Loop
    total_results = 1 
    current_index = 0

    while current_index < total_results:
        try:
            # Update startIndex for pagination
            params["startIndex"] = current_index
            
            print(f"Fetching... (Index: {current_index})")
            response = requests.get(NVD_API_URL, params=params, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                total_results = data.get("totalResults", 0)
                vulnerabilities = data.get("vulnerabilities", [])
                
                if not vulnerabilities:
                    print("No new records found.")
                    break

                db.insert_batch(vulnerabilities)
                print(f"Stored {len(vulnerabilities)} records.")

                current_index += RESULTS_PER_PAGE
                time.sleep(SLEEP_TIME)
                
            elif response.status_code == 403:
                print("Error 403: Rate Limit Exceeded or API Key issue.")
                break
            else:
                print(f"Error: Received status code {response.status_code}")
                time.sleep(SLEEP_TIME * 2)

        except Exception as e:
            print(f"Exception occurred: {e}")
            break

    print("--- Sync Completed ---")
# main method
if __name__ == "__main__":
    fetch_and_store_data()