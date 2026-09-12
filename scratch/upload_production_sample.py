import os
import requests
from pathlib import Path
import json

SPECIMEN = Path("backend/tests/fixtures/sample_bec_investigation.eml")
URL = "https://detect-threat-ai.onrender.com/api/emails/analyze"

def upload_sample():
    assert SPECIMEN.exists(), f"{SPECIMEN} not found"
    with open(SPECIMEN, "rb") as f:
        files = {"file": ("sample_bec_investigation.eml", f, "message/rfc822")}
        print(f"Uploading {SPECIMEN.name} ({SPECIMEN.stat().st_size} bytes) to {URL}...")
        resp = requests.post(URL, files=files, timeout=90)
        print("HTTP status:", resp.status_code)
        try:
            data = resp.json()
            print("Response keys:", list(data.keys()))
            print("case_id (or caseId):", data.get("case_id") or data.get("caseId"))
            print("ai_status:", data.get("ai_status"))
            print("ai_error:", data.get("ai_error"))
            print("ai_investigation:", data.get("ai_investigation"))
            print("risk_score:", data.get("security_analysis", {}).get("risk_score") if isinstance(data.get("security_analysis"), dict) else data.get("risk_score"))
            
            # Save full response to inspect
            with open("scratch/production_upload_response.json", "w") as out:
                json.dump(data, out, indent=2)
            print("Saved full response to scratch/production_upload_response.json")
        except Exception as e:
            print("Error parsing json:", e)
            print("Text:", resp.text[:500])

if __name__ == "__main__":
    upload_sample()
