"""Provider abstraction for the Step 7 agent.

The default implementation uses only urllib and the OpenAI-compatible chat
completions protocol.  A provider cannot access the uploaded email; it receives
the already-reduced context assembled by :mod:`agent`.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Protocol
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from urllib.parse import urlsplit

from app.services.ai_agent.prompts import SYSTEM_PROMPT, make_user_prompt

logger = logging.getLogger(__name__)


class ProviderError(RuntimeError):
    """A provider was unavailable or returned an unusable response."""


class ProviderTimeout(ProviderError):
    """The provider exceeded the configured timeout."""


@dataclass(frozen=True)
class ProviderDecision:
    """One bounded agent decision."""

    kind: str
    tool: str | None = None
    arguments: dict[str, Any] = field(default_factory=dict)
    result: dict[str, Any] | None = None


class LLMProvider(Protocol):
    def decide(
        self,
        context: dict[str, Any],
        history: list[dict[str, Any]],
        available_tools: list[str],
    ) -> ProviderDecision:
        ...


class OpenAICompatibleProvider:
    """Small standard-library OpenAI-compatible client."""

    endpoint = "https://api.openai.com/v1/chat/completions"
    groq_endpoint = "https://api.groq.com/openai/v1/chat/completions"
    gemini_endpoint = "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions"

    def __init__(
        self,
        api_key: str,
        model: str,
        timeout_seconds: float = 30.0,
        *,
        endpoint: str | None = None,
    ) -> None:
        if not api_key:
            raise ProviderError("provider key is missing")
        self.api_key = api_key
        self.model = model
        self.timeout_seconds = timeout_seconds
        if endpoint:
            self.endpoint = endpoint

    def decide(
        self,
        context: dict[str, Any],
        history: list[dict[str, Any]],
        available_tools: list[str],
    ) -> ProviderDecision:
        payload = {
            "model": self.model,
            "temperature": 0,
            "max_tokens": 1200,
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": make_user_prompt(context, history, available_tools)},
            ],
        }
        request = Request(
            self.endpoint,
            data=json.dumps(payload, separators=(",", ":")).encode("utf-8"),
            headers={
                "Authorization": "Bearer " + self.api_key,
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            method="POST",
        )
        location = urlsplit(self.endpoint)
        logger.info(
            "AI provider request provider=%s model=%s endpoint=%s key_configured=%s",
            "gemini" if self.endpoint == self.gemini_endpoint else "openai-compatible",
            self.model,
            location.netloc + location.path,
            bool(self.api_key),
        )
        raw: bytes | None = None
        for attempt in range(3):
            try:
                with urlopen(request, timeout=self.timeout_seconds) as response:
                    raw = response.read(2_000_000)
                    logger.info("AI provider response status=%s attempt=%s", response.status, attempt + 1)
                    break
            except TimeoutError as exc:
                logger.warning("AI provider response category=timeout")
                raise ProviderTimeout("provider timed out") from exc
            except HTTPError as exc:
                retryable = exc.code in {408, 429, 500, 502, 503, 504}
                logger.warning(
                    "AI provider response status=%s category=http retryable=%s attempt=%s",
                    exc.code,
                    retryable,
                    attempt + 1,
                )
                if retryable and attempt < 2:
                    time.sleep(0.5 * (attempt + 1))
                    continue
                raise ProviderError("provider unavailable") from exc
            except (URLError, OSError) as exc:
                logger.warning("AI provider response category=network")
                raise ProviderError("provider unavailable") from exc
        if raw is None:
            raise ProviderError("provider unavailable")
        try:
            envelope = json.loads(raw.decode("utf-8"))
            content = envelope["choices"][0]["message"]["content"]
            decision = json.loads(content) if isinstance(content, str) else content
            logger.info("AI provider response parsing=success")
        except (ValueError, KeyError, IndexError, TypeError) as exc:
            logger.warning("AI provider response parsing=failure")
            raise ProviderError("provider returned malformed JSON") from exc
        return self._parse_decision(decision)

    @staticmethod
    def _parse_decision(value: Any) -> ProviderDecision:
        if not isinstance(value, dict):
            raise ProviderError("provider decision is not an object")
        kind = value.get("type", value.get("kind"))
        if kind in {"tool_call", "tool"}:
            tool = value.get("tool", value.get("name"))
            args = value.get("arguments", {})
            if not isinstance(tool, str) or not isinstance(args, dict):
                raise ProviderError("malformed tool decision")
            return ProviderDecision(kind="tool_call", tool=tool, arguments=args)
        if kind == "final":
            result = value.get("result", value.get("data"))
            if not isinstance(result, dict):
                raise ProviderError("malformed final decision")
            return ProviderDecision(kind="final", result=result)
        # A few OpenAI-compatible gateways omit the wrapper and return the
        # result object directly.  It is still validated by the agent schema.
        if {"summary", "risk_level", "attribution"}.issubset(value):
            return ProviderDecision(kind="final", result=value)
        raise ProviderError("unknown provider decision")


# Friendly name for applications that do not need to know the protocol detail.
OpenAIProvider = OpenAICompatibleProvider


def create_provider(
    provider_name: str,
    *,
    api_key: str | None,
    model: str,
    timeout_seconds: float,
) -> LLMProvider:
    """Create a configured provider or fail closed for unknown providers."""
    normalized_name = provider_name.lower()
    if normalized_name in {
        "openai",
        "openai_compatible",
        "openai-compatible",
        "groq",
        "gemini",
    }:
        if not api_key:
            raise ProviderError("provider key is missing")
        endpoint = {
            "groq": OpenAICompatibleProvider.groq_endpoint,
            "gemini": OpenAICompatibleProvider.gemini_endpoint,
        }.get(normalized_name, OpenAICompatibleProvider.endpoint)
        return OpenAICompatibleProvider(api_key, model, timeout_seconds, endpoint=endpoint)
    raise ProviderError("provider unavailable")
