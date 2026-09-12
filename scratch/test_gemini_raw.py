"""See exactly what Gemini returns in the raw response."""
import json
import os
import sys
from urllib.request import Request, urlopen
from dotenv import load_dotenv
from pathlib import Path

load_dotenv(Path(r"D:\DetectThreatAI\backend\.env"), override=True)

api_key = os.getenv("AI_API_KEY", "")
model = os.getenv("AI_MODEL", "gemini-3.6-flash")

url = "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions"
payload = {
    "model": model,
    "temperature": 0,
    "max_tokens": 500,
    "response_format": {"type": "json_object"},
    "messages": [
        {
            "role": "system",
            "content": 'Return exactly one JSON object: {"type": "final", "result": {"summary": "test email", "risk_level": "low", "classification": "benign", "confidence": "low", "reasoning": "test", "key_findings": [], "recommended_actions": [], "attribution": {"status": "infrastructure_only", "assessment": "test", "confidence": "low", "supporting_evidence": [], "limitations": []}, "evidence": [], "tool_calls": [], "iterations": 1, "source": "ai_agent"}}'
        },
        {
            "role": "user",
            "content": '{"email": {"subject": "Test", "from": "test@example.com"}}'
        }
    ],
}

headers = {
    "Content-Type": "application/json",
    "Authorization": f"Bearer {api_key}",
}

req = Request(url, data=json.dumps(payload).encode(), headers=headers, method="POST")

with urlopen(req, timeout=30) as resp:
    raw = resp.read()
    envelope = json.loads(raw.decode())
    print("=== RAW ENVELOPE ===")
    print(json.dumps(envelope, indent=2)[:3000])
    
    # Extract the message content like the provider does
    msg = envelope["choices"][0]["message"]
    content = msg.get("content", "")
    print(f"\n=== MESSAGE CONTENT (type={type(content).__name__}) ===")
    print(content[:2000])
    
    # Try parsing it
    if isinstance(content, str):
        try:
            parsed = json.loads(content)
            print(f"\n=== PARSED JSON ===")
            print(json.dumps(parsed, indent=2)[:2000])
            print(f"\nHas 'type' key: {'type' in parsed}")
            print(f"Has 'kind' key: {'kind' in parsed}")
            print(f"Has 'summary' key: {'summary' in parsed}")
            print(f"Has 'risk_level' key: {'risk_level' in parsed}")
        except:
            print("\nFailed to parse content as JSON!")
