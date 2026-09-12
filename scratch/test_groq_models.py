"""Check if Groq API is accessible at all — list models."""
import json
import os
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError
from dotenv import load_dotenv
from pathlib import Path

env_path = Path(__file__).resolve().parent.parent / "backend" / ".env"
load_dotenv(env_path)

api_key = os.getenv("GROQ_API_KEY")
print(f"API Key prefix: {api_key[:15]}..." if api_key else "NO KEY")

# Try listing models
url = "https://api.groq.com/openai/v1/models"
headers = {
    "Authorization": f"Bearer {api_key}",
}

req = Request(url, headers=headers, method="GET")
try:
    with urlopen(req, timeout=30) as resp:
        body = json.loads(resp.read().decode())
        print(f"\nSUCCESS listing models!")
        for m in body.get("data", []):
            print(f"  - {m['id']}")
except HTTPError as e:
    body = e.read().decode()
    print(f"\nHTTP ERROR {e.code}")
    print(f"Body: {body}")
except URLError as e:
    print(f"\nNETWORK ERROR: {e.reason}")
