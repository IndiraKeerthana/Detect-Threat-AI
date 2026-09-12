import urllib.request
import json
import uuid
from pathlib import Path

sample_path = Path(r"d:\DetectThreatAI\backend\tests\fixtures\sample_bec_investigation.eml")
file_bytes = sample_path.read_bytes()

boundary = uuid.uuid4().hex
body = bytearray()
body.extend(f"--{boundary}\r\n".encode("utf-8"))
body.extend(f'Content-Disposition: form-data; name="file"; filename="sample_bec_investigation.eml"\r\n'.encode("utf-8"))
body.extend(b"Content-Type: message/rfc822\r\n\r\n")
body.extend(file_bytes)
body.extend(f"\r\n--{boundary}--\r\n".encode("utf-8"))

url = "https://detect-threat-ai.onrender.com/api/emails/analyze"
print(f"Uploading {len(file_bytes)} bytes to {url} ...")

req = urllib.request.Request(
    url,
    data=body,
    headers={
        "Content-Type": f"multipart/form-data; boundary={boundary}",
        "User-Agent": "Mozilla/5.0",
    },
    method="POST"
)

try:
    with urllib.request.urlopen(req, timeout=120) as resp:
        res_bytes = resp.read()
        status = resp.status
        data = json.loads(res_bytes.decode("utf-8"))
        print(f"\nResponse Status: {status}")
        print(f"Case ID: {data.get('case_id')}")
        print(f"Subject: {data.get('subject')}")
        print(f"Risk Score: {data.get('risk_assessment', {}).get('score')}")
        print(f"ai_status: {data.get('ai_status')}")
        print(f"ai_error: {data.get('ai_error')}")
        ai = data.get("ai_investigation")
        if ai:
            print("\nAI Investigation:")
            print(f"  Source: {ai.get('source')}")
            print(f"  Provider: {ai.get('provider')}")
            print(f"  Model: {ai.get('model')}")
            print(f"  Classification: {ai.get('classification')}")
            print(f"  Threat Level: {ai.get('threat_level') or ai.get('risk_level')}")
            print(f"  Confidence: {ai.get('confidence')}")
            print(f"  Email Intent: {ai.get('email_intent')}")
            print(f"  Claimed Identity: {ai.get('claimed_identity')}")
            print(f"  Requested Action: {ai.get('requested_action')}")
            print(f"  Summary: {ai.get('summary')}")
            print(f"  Fishy findings: {ai.get('suspicious_content_findings')}")
        else:
            print("ai_investigation is None!")
        
        # Also dump full ai-related keys
        print("\nFull AI-related payload keys:")
        for k in ["ai_status", "ai_error", "ai_investigation"]:
            print(f"  {k}: {data.get(k)}")

except urllib.error.HTTPError as e:
    print(f"HTTPError: {e.code}")
    print(e.read().decode("utf-8", errors="ignore"))
except Exception as e:
    print(f"Error: {e}")
