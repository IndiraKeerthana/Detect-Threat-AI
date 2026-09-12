import traceback
import sys
import logging
import asyncio
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend"))

# Configure root logger to print everything
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(name)s: %(message)s')

from app.config import get_settings
from app.services.email_parser import parse_email
from app.services.relay_analyzer import analyze_received_headers
from app.services.security_analysis import analyze_security
from app.services.threat_intelligence import analyze_threat_intelligence
from app.services.investigation import analyze_investigation
from app.services.ai_agent.agent import (
    run_ai_investigation,
    AIAnalysisError,
    AIConfigurationError,
)

async def main():
    settings = get_settings()
    print(f"AI_AGENT_ENABLED: {settings.ai_agent_enabled}")
    print(f"AI_PROVIDER: {settings.ai_provider}")
    print(f"AI_MODEL: {settings.ai_model}")
    print(f"GROQ_API_KEY present: {bool(settings.groq_api_key)}")
    print(f"EFFECTIVE_AI_API_KEY present: {bool(settings.effective_ai_api_key)}")

    eml_bytes = Path("backend/tests/fixtures/sample_bec_investigation.eml").read_bytes()
    parsed_email = parse_email(eml_bytes)
    relay_analysis = analyze_received_headers(parsed_email.received)
    security_analysis = analyze_security(parsed_email)
    threat_intelligence = analyze_threat_intelligence(
        parsed_email, relay_analysis, security_analysis
    )
    investigation = analyze_investigation(
        parsed_email, security_analysis, threat_intelligence
    )

    print("\n--- CALLING run_ai_investigation ---")
    try:
        result = await asyncio.to_thread(
            run_ai_investigation,
            parsed_email,
            security_analysis,
            threat_intelligence,
            investigation,
            settings=settings,
        )
        print("\nSUCCESS!")
        print("Source:", result.source)
        print("Provider:", result.provider)
        print("Model:", result.model)
        print("Classification:", result.classification)
        print("Confidence:", result.confidence)
        print("Summary:", result.summary)
    except Exception as e:
        print("\nFAILED WITH EXCEPTION:")
        print("Exception Type:", type(e).__name__)
        print("Exception Details:", str(e))
        if hasattr(e, "category"):
            print("Category:", getattr(e, "category"))
        if hasattr(e, "status_code"):
            print("Status Code:", getattr(e, "status_code"))
        if hasattr(e, "iteration"):
            print("Iteration:", getattr(e, "iteration"))
        if hasattr(e, "provider"):
            print("Provider:", getattr(e, "provider"))
        if hasattr(e, "model"):
            print("Model:", getattr(e, "model"))
        print("\nFull Traceback:")
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(main())
