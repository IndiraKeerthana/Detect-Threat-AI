"""Directly test the AI agent code path with Gemini to see the exact error."""
import json
import logging
import sys
import os

# Enable ALL logging
logging.basicConfig(level=logging.DEBUG, stream=sys.stdout, format='%(name)s %(levelname)s: %(message)s')

# Must set env BEFORE importing app modules (lru_cache)
os.environ["AI_AGENT_ENABLED"] = "true"
os.environ["AI_PROVIDER"] = "gemini"
os.environ["AI_MODEL"] = "gemini-3.6-flash"

from dotenv import load_dotenv
from pathlib import Path
load_dotenv(Path(r"D:\DetectThreatAI\backend\.env"), override=True)

# Now patch settings before import
os.environ["AI_API_KEY"] = os.getenv("AI_API_KEY", "")

sys.path.insert(0, str(Path(r"D:\DetectThreatAI\backend")))

from app.config import Settings

# Create fresh settings (bypass lru_cache)
settings = Settings()
print(f"Provider: {settings.ai_provider}")
print(f"Model: {settings.ai_model}")
print(f"Key present: {bool(settings.effective_ai_api_key)}")
print(f"Key prefix: {(settings.effective_ai_api_key or '')[:15]}...")
print(f"AI enabled: {settings.ai_agent_enabled}")

# Now test the provider directly
from app.services.ai_agent.provider import create_provider, ProviderError

try:
    provider = create_provider(
        settings.ai_provider,
        api_key=settings.effective_ai_api_key,
        model=settings.ai_model,
        timeout_seconds=30.0,
    )
    print(f"\nProvider created: {provider.name}")
    print(f"Endpoint: {provider.endpoint}")
    print(f"Model: {provider.model}")
    
    # Try a simple decide_once call
    test_context = {
        "email": {"subject": "Test", "from": "test@example.com"},
        "entities": [],
        "observations": [],
    }
    
    result = provider.decide_once(
        test_context,
        system_prompt="You are a test. Return JSON: {\"summary\": \"test\", \"risk_level\": \"low\", \"classification\": \"benign\", \"confidence\": \"low\", \"reasoning\": \"test\", \"key_findings\": [], \"recommended_actions\": [], \"attribution\": {\"status\": \"infrastructure_only\", \"assessment\": \"test\", \"confidence\": \"low\", \"supporting_evidence\": [], \"limitations\": []}, \"evidence\": [], \"tool_calls\": [], \"iterations\": 1, \"source\": \"ai_agent\"}",
        max_tokens=500,
    )
    print(f"\nResult kind: {result.kind}")
    print(f"Result: {json.dumps(result.result, indent=2)[:500] if result.result else 'None'}")
    
except ProviderError as e:
    print(f"\nPROVIDER ERROR: {e}")
    print(f"  category: {e.category}")
    print(f"  status_code: {e.status_code}")
    print(f"  model: {e.model}")
    print(f"  provider: {e.provider}")
except Exception as e:
    print(f"\nERROR: {type(e).__name__}: {e}")
    import traceback
    traceback.print_exc()
