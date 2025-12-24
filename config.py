# config.py
import os

# NVD API Settings
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
RESULTS_PER_PAGE = 2000  # Max allowed by NVD is 2000
SLEEP_TIME = 6  # Seconds to sleep between requests (NVD rate limit rule)

# MongoDB Settings
MONGO_URI = "mongodb://localhost:27017/"
DB_NAME = "nvd_cve_db"
COLLECTION_NAME = "cves"