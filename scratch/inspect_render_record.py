import urllib.request
import json

req = urllib.request.Request("https://detect-threat-ai.onrender.com/api/cases")
with urllib.request.urlopen(req) as resp:
    data = json.loads(resp.read().decode())
    print(f"Count: {len(data)}")
    if data:
        print("Keys:", list(data[0].keys()))
        print("id:", data[0].get("id"))
        print("case_id:", data[0].get("case_id"))
        print("subject:", data[0].get("subject"))
        print("ai_status:", data[0].get("ai_status"))
        print("raw keys:", list(data[0].get("raw_data", {}).keys()) if isinstance(data[0].get("raw_data"), dict) else "not dict")
        raw = data[0].get("raw_data", {})
        print("raw ai_status:", raw.get("ai_status"))
        print("raw ai_error:", raw.get("ai_error"))
        print("raw ai_investigation:", raw.get("ai_investigation"))
