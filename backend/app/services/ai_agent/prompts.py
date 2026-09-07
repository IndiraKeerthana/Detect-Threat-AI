"""Prompts for the constrained investigation protocol."""

from __future__ import annotations

import json
from typing import Any

SYSTEM_PROMPT = """You are a security investigation assistant.
Use only the normalized evidence in the supplied context and tool results.
Never invent entities, facts, actors, URLs, or provider observations.
Do not request URL execution, downloading, shell access, attachments, secrets,
or arbitrary tools. Infrastructure is not actor attribution.
Return exactly one JSON object per turn:
{"kind":"tool","tool":"<registered name>","arguments":{}}
or {"kind":"final","result":{...}}.
The final result must contain summary, risk_level, classification, confidence,
reasoning, key_findings, recommended_actions, attribution, evidence, tool_calls,
iterations, and source. Keep reasoning concise and evidence-backed."""


def make_user_prompt(
    context: dict[str, Any],
    history: list[dict[str, Any]],
    available_tools: list[str],
) -> str:
    # json is used only for the bounded structured context, never raw email.
    prompt_context = context.get("compact", context)
    return json.dumps(
        {
            "context": prompt_context,
            "available_tools": available_tools,
            "history": history[-12:],
        },
        separators=(",", ":"),
        sort_keys=True,
    )
