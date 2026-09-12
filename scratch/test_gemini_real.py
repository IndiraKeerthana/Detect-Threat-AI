"""Test with REAL sample to see what Gemini returns for the actual forensic prompt."""
import json
import os
import sys
import logging

logging.basicConfig(level=logging.DEBUG, stream=sys.stdout, format='%(name)s %(levelname)s: %(message)s')

from dotenv import load_dotenv
from pathlib import Path
load_dotenv(Path(r"D:\DetectThreatAI\backend\.env"), override=True)
sys.path.insert(0, str(Path(r"D:\DetectThreatAI\backend")))

# Monkey-patch _extract_decision_from_raw to log what it gets
import app.services.ai_agent.provider as prov
original_extract = prov.OpenAICompatibleProvider._extract_decision_from_raw

def patched_extract(self, raw):
    try:
        envelope = json.loads(raw.decode("utf-8"))
        msg = envelope["choices"][0]["message"]
        content = msg.get("content", "")
        print(f"\n=== GEMINI CONTENT (len={len(str(content))}) ===")
        print(str(content)[:2000])
        print("=== END CONTENT ===\n")
    except Exception as e:
        print(f"\n=== FAILED TO INSPECT RAW: {e} ===\n")
    return original_extract(self, raw)

prov.OpenAICompatibleProvider._extract_decision_from_raw = patched_extract

from app.config import Settings
from app.services.ai_agent.provider import create_provider, ProviderError
from app.services.ai_agent.agent import FOUNDATION_SYSTEM_PROMPT

settings = Settings()

provider = create_provider(
    settings.ai_provider,
    api_key=settings.effective_ai_api_key,
    model=settings.ai_model,
    timeout_seconds=60.0,
)

# Use a minimal but realistic context
context = {
    "email": {
        "subject": "Urgent Wire Transfer Required",
        "from": "ceo@company-corp.com",
        "to": "finance@company.com",
        "body_preview": "Please process the attached wire transfer immediately. This is urgent and confidential."
    },
    "entities": [
        {"type": "email", "value": "ceo@company-corp.com", "sources": ["from_header"]},
        {"type": "domain", "value": "company-corp.com", "sources": ["from_header"]},
    ],
    "observations": [],
    "security": {"spf": "fail", "dkim": "fail", "dmarc": "fail"},
}

try:
    result = provider.decide_once(
        context,
        system_prompt=FOUNDATION_SYSTEM_PROMPT,
        max_tokens=2048,
    )
    print(f"\nRESULT kind: {result.kind}")
    if result.result:
        print(f"RESULT data: {json.dumps(result.result, indent=2)[:1000]}")
    else:
        print("RESULT is None!")
except Exception as e:
    print(f"\nERROR: {type(e).__name__}: {e}")
    import traceback
    traceback.print_exc()
