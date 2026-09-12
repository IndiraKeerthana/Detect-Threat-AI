"""Upload the sample EML to the local backend and check what happens."""
import json
import urllib.request
import urllib.error
from pathlib import Path

eml_path = Path(r"D:\DetectThreatAI\backend\tests\fixtures\sample_bec_investigation.eml")
eml_data = eml_path.read_bytes()

# Build multipart form data manually
boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW"
body = (
    f"--{boundary}\r\n"
    f'Content-Disposition: form-data; name="file"; filename="sample_bec_investigation.eml"\r\n'
    f"Content-Type: message/rfc822\r\n\r\n"
).encode() + eml_data + f"\r\n--{boundary}--\r\n".encode()

req = urllib.request.Request(
    "http://127.0.0.1:9001/api/emails/analyze",
    data=body,
    headers={
        "Content-Type": f"multipart/form-data; boundary={boundary}",
    },
    method="POST",
)

try:
    with urllib.request.urlopen(req, timeout=90) as resp:
        data = json.loads(resp.read().decode())
        ai = data.get("ai_investigation")
        if ai:
            print("AI ANALYSIS SUCCESS!")
            print(f"  source: {ai.get('source')}")
            print(f"  provider: {ai.get('provider')}")
            print(f"  model: {ai.get('model')}")
            print(f"  classification: {ai.get('classification')}")
            print(f"  risk_level: {ai.get('risk_level')}")
            print(f"  confidence: {ai.get('confidence')}")
            print(f"  summary: {str(ai.get('summary',''))[:200]}")
        else:
            print("NO ai_investigation in response!")
            print(f"Keys: {list(data.keys())}")
            # Check if there's an error field
            for k in ['error', 'detail', 'ai_error', 'ai_status']:
                if k in data:
                    print(f"  {k}: {data[k]}")
except urllib.error.HTTPError as e:
    body = e.read().decode()
    print(f"HTTP ERROR {e.code}")
    print(f"Body: {body[:1000]}")
except Exception as e:
    print(f"ERROR: {type(e).__name__}: {e}")
