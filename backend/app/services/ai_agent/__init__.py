"""Bounded, provider-neutral Step 7 investigation agent.

The lazy exports avoid importing the orchestration module while the email
schema is being initialized.
"""

from app.services.ai_agent.schemas import AIInvestigationResult

__all__ = ["AIInvestigationAgent", "AIInvestigationResult", "build_investigation_context", "run_ai_investigation"]


def __getattr__(name: str):
    if name in {"AIInvestigationAgent", "build_investigation_context", "run_ai_investigation"}:
        from app.services.ai_agent.agent import (
            AIInvestigationAgent,
            build_investigation_context,
            run_ai_investigation,
        )
        return {
            "AIInvestigationAgent": AIInvestigationAgent,
            "build_investigation_context": build_investigation_context,
            "run_ai_investigation": run_ai_investigation,
        }[name]
    raise AttributeError(name)
