"""Direct test of Groq API with mixtral-8x7b-32768."""
import json
import os
import sys
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError
from dotenv import load_dotenv
from pathlib import Path

# Load .env from the backend directory
env_path = Path(__file__).resolve().parent.parent / "backend" / ".env"
load_dotenv(env_path)

api_key = os.getenv("GROQ_API_KEY")
model = os.getenv("AI_MODEL", "mixtral-8x7b-32768")

print(f"API Key present: {bool(api_key)}")
print(f"API Key prefix: {api_key[:15]}..." if api_key else "NO KEY")
print(f"Model: {model}")

url = "https://api.groq.com/openai/v1/chat/completions"
payload = {
    "model": model,
    "messages": [
        {"role": "system", "content": "You are a helpful assistant."},
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
        print(f"Tokens: {body.get('usage', {})}")
except HTTPError as e:
    body = e.read().decode()
    print(f"\nHTTP ERROR {e.code}")
    print(f"Body: {body}")
except URLError as e:
    print(f"\nNETWORK ERROR: {e.reason}")
except Exception as e:
    print(f"\nUNEXPECTED ERROR: {type(e).__name__}: {e}")
