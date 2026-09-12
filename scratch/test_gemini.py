"""Quick test: verify Gemini API key and make a test call."""
import json
import os
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError
from dotenv import load_dotenv
from pathlib import Path

env_path = Path(__file__).resolve().parent.parent / "backend" / ".env"
load_dotenv(env_path, override=True)

provider = os.getenv("AI_PROVIDER")
model = os.getenv("AI_MODEL")
api_key = os.getenv("AI_API_KEY", "")

print(f"Provider: {provider}")
print(f"Model: {model}")
print(f"Key set: {bool(api_key and api_key != 'PASTE_YOUR_GEMINI_KEY_HERE')}")
if api_key and len(api_key) > 10:
    print(f"Key prefix: {api_key[:10]}...")

if not api_key or api_key == "PASTE_YOUR_GEMINI_KEY_HERE":
    print("\nERROR: Gemini API key not set yet!")
    exit(1)

# Test the Gemini API
url = "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions"
payload = {
    "model": model,
    "messages": [
        {"role": "user", "content": "Say hello in one sentence."}
    ],
    "max_tokens": 50,
    "temperature": 0.1,
}

headers = {
    "Content-Type": "application/json",
    "Authorization": f"Bearer {api_key}",
}

req = Request(url, data=json.dumps(payload).encode(), headers=headers, method="POST")

try:
    with urlopen(req, timeout=30) as resp:
        body = json.loads(resp.read().decode())
        print(f"\nSUCCESS! Status: {resp.status}")
        print(f"Model used: {body.get('model')}")
        print(f"Response: {body['choices'][0]['message']['content']}")
except HTTPError as e:
    body = e.read().decode()
    print(f"\nHTTP ERROR {e.code}")
    print(f"Body: {body[:500]}")
except URLError as e:
    print(f"\nNETWORK ERROR: {e.reason}")
except Exception as e:
    print(f"\nERROR: {type(e).__name__}: {e}")
