import requests
import json
import time

API_KEY = "YOUR_API_KEY"
VT_URL = "https://www.virustotal.com/api/v3/files/{}"
HEADERS = {"x-apikey": API_KEY}

# Put your hashes here (you can copy from your hash file)
hashes = [
    "aaaaaaaa...sha256hash1...",
    "bbbbbbbb...sha256hash2...",
]

results = []

for h in hashes:
    url = VT_URL.format(h)
    r = requests.get(url, headers=HEADERS)
    if r.status_code == 200:
        data = r.json()
        attr = data.get("data", {}).get("attributes", {})
        stats = attr.get("last_analysis_stats", {})
        meaningful_name = attr.get("meaningful_name", "")
        tags = attr.get("tags", [])
        results.append({
            "hash": h,
            "name": meaningful_name,
            "stats": stats,
            "tags": tags
        })
    else:
        results.append({
            "hash": h,
            "error": r.status_code
        })
    # Respect free-tier rate limits
    time.sleep(16)   # free tier ~4 requests/min, adjust as needed

print(json.dumps(results, indent=2))
