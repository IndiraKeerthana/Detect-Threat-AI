import requests
from pathlib import Path
import json

SPECIMEN = Path("backend/tests/fixtures/sample_bec_investigation.eml")
URL = "http://localhost:9001/api/emails/analyze"

def upload_local():
    assert SPECIMEN.exists(), f"{SPECIMEN} not found"
    with open(SPECIMEN, "rb") as f:
        files = {"file": ("sample_bec_investigation.eml", f, "message/rfc822")}
        print(f"Uploading {SPECIMEN.name} to local {URL}...")
        resp = requests.post(URL, files=files, timeout=90)
        print("Local HTTP status:", resp.status_code)
        try:
            data = resp.json()
            print("Local caseId:", data.get("caseId") or data.get("case_id"))
            print("Local ai_status:", data.get("ai_status"))
            print("Local ai_error:", data.get("ai_error"))
            ai_inv = data.get("ai_investigation")
            print("Local ai_investigation present?", ai_inv is not None)
            if ai_inv:
                print("  source:", ai_inv.get("source"))
                print("  model:", ai_inv.get("model"))
                print("  provider:", ai_inv.get("provider"))
                print("  classification:", ai_inv.get("classification"))
                print("  confidence:", ai_inv.get("confidence"))
                print("  summary:", ai_inv.get("summary")[:100] if ai_inv.get("summary") else None)
            print("Local risk score:", data.get("risk_assessment", {}).get("score"))
            with open("scratch/local_upload_response.json", "w") as out:
                json.dump(data, out, indent=2)
            print("Saved local response to scratch/local_upload_response.json")
        except Exception as e:
            print("Error parsing json:", e)
            print("Text:", resp.text[:500])

if __name__ == "__main__":
    upload_local()
