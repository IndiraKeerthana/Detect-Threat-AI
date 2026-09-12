import urllib.request
import json
import os
from pathlib import Path

RENDER_URL = "https://detect-threat-ai.onrender.com"

def check_render():
    print("--- 1. Health Check ---")
    try:
        req = urllib.request.Request(f"{RENDER_URL}/api/health")
        with urllib.request.urlopen(req) as resp:
            print("Status:", resp.status)
            print("Headers:", dict(resp.headers))
            data = json.loads(resp.read().decode())
            print("Health Response:", json.dumps(data, indent=2))
    except Exception as e:
        print("Health check error:", e)

    print("\n--- 2. List Cases ---")
    try:
        req = urllib.request.Request(f"{RENDER_URL}/api/cases")
        with urllib.request.urlopen(req) as resp:
            print("Status:", resp.status)
            cases = json.loads(resp.read().decode())
            print(f"Total Cases: {len(cases)}")
            for c in cases[:5]:
                print(f"  ID: {c.get('case_id')} | Created: {c.get('created_at')} | Subject: {c.get('subject')[:40]} | Score: {c.get('risk_score')}")
    except Exception as e:
        print("Cases error:", e)

if __name__ == "__main__":
    check_render()
