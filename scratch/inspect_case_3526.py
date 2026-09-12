import urllib.request
import json

req = urllib.request.Request("https://detect-threat-ai.onrender.com/api/cases/CASE-2026-3526")
with urllib.request.urlopen(req) as resp:
    data = json.loads(resp.read().decode())
    inv = data.get("investigationData", {})
    print("investigationData keys:", list(inv.keys()))
    print("ai_status:", inv.get("ai_status"))
    print("ai_error:", inv.get("ai_error"))
    print("ai_investigation:", inv.get("ai_investigation"))
    print("risk_score:", inv.get("security_analysis", {}).get("risk_score"))
