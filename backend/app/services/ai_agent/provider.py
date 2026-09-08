"""Provider abstraction for the Step 7 autonomous forensic agent.

The default implementation uses only urllib and the OpenAI-compatible chat
completions protocol, targeting Groq as the primary provider.
A provider cannot access the uploaded email; it receives the already-reduced
context assembled by :mod:`agent`.
"""

from __future__ import annotations

import json
import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any, Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from app.services.ai_agent.prompts import SYSTEM_PROMPT, make_user_prompt

logger = logging.getLogger(__name__)


class ProviderError(RuntimeError):
    """A provider was unavailable or returned an unusable response."""


class ProviderTimeout(ProviderError):
    """The provider exceeded the configured timeout."""


MODEL_FALLBACKS: dict[str, str] = {
    "llama-3.3-70b-versatile": "groq/compound-mini",
    "llama-3.1-70b-versatile": "groq/compound-mini",
    "llama3-70b-8192": "groq/compound-mini",
    "gemini-3.5-flash": "gemini-3.5-flash-lite",
    "gemini-3.8-flash": "gemini-3.5-flash-lite",
    "gemini-3-flash-preview": "gemini-3.5-flash-lite",
}


def _supports_reasoning_effort(model: str) -> bool:
    lowered = model.lower()
    return "flash-lite" not in lowered and "3.6" not in lowered and ("gemini" in lowered or "gpt-5" in lowered or "o3" in lowered)


def _clean_and_parse_json(content: str) -> dict[str, Any]:
    """Clean markdown fences and repair common malformed JSON issues."""
    cleaned = content.strip()
    if cleaned.startswith("```"):
        lines = cleaned.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].startswith("```"):
            lines = lines[:-1]
        cleaned = "\n".join(lines).strip()
    try:
        data = json.loads(cleaned)
        if isinstance(data, dict):
            return data
    except (ValueError, TypeError):
        pass

    # Bounded repair: find outermost JSON object braces
    start = cleaned.find("{")
    end = cleaned.rfind("}")
    if start != -1 and end > start:
        candidate = cleaned[start : end + 1]
        try:
            data = json.loads(candidate)
            if isinstance(data, dict):
                return data
        except (ValueError, TypeError):
            # Attempt trailing comma cleanup: e.g. ", }" or ", ]"
            fixed = re.sub(r",\s*([\]}])", r"\1", candidate)
            data = json.loads(fixed)
            if isinstance(data, dict):
                return data

    raise ValueError("malformed JSON content")


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
    """Small standard-library OpenAI-compatible client targeting Groq."""

    groq_endpoint = "https://api.groq.com/openai/v1/chat/completions"
    openai_endpoint = "https://api.openai.com/v1/chat/completions"
    gemini_endpoint = "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions"

    # Default to Groq
    endpoint = "https://api.groq.com/openai/v1/chat/completions"

    def __init__(
        self,
        api_key: str,
        model: str,
        timeout_seconds: float = 60.0,
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

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": "Bearer " + self.api_key,
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "DetectThreatAI/1.0",
        }

    def decide(
        self,
        context: dict[str, Any],
        history: list[dict[str, Any]],
        available_tools: list[str],
    ) -> ProviderDecision:
        payload: dict[str, Any] = {
            "model": self.model,
            "temperature": 0,
            "max_tokens": 1500,
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": make_user_prompt(context, history, available_tools)},
            ],
        }
        if (self.endpoint == self.gemini_endpoint or "gemini" in self.model.lower()) and _supports_reasoning_effort(self.model):
            payload["reasoning_effort"] = "none"

        request = Request(
            self.endpoint,
            data=json.dumps(payload, separators=(",", ":")).encode("utf-8"),
            headers=self._headers(),
            method="POST",
        )
        location = urlsplit(self.endpoint)
        logger.info(
            "AI provider request provider=%s model=%s endpoint=%s key_configured=%s",
            "groq" if "groq.com" in self.endpoint else ("gemini" if "googleapis.com" in self.endpoint else "openai"),
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
                if (exc.code in {404, 429}) and self.model in MODEL_FALLBACKS:
                    fallback_model = MODEL_FALLBACKS[self.model]
                    logger.info("AI provider model switch %s -> %s (status=%d)", self.model, fallback_model, exc.code)
                    self.model = fallback_model
                    payload["model"] = fallback_model
                    if not _supports_reasoning_effort(fallback_model):
                        payload.pop("reasoning_effort", None)
                    request = Request(
                        self.endpoint,
                        data=json.dumps(payload, separators=(",", ":")).encode("utf-8"),
                        headers=self._headers(),
                        method="POST",
                    )
                    continue

                retryable = exc.code in {408, 429, 500, 502, 503, 504}
                err_body = exc.read().decode("utf-8", errors="replace") if hasattr(exc, "read") else ""
                logger.warning(
                    "AI provider response status=%s category=http retryable=%s attempt=%s body=%s",
                    exc.code,
                    retryable,
                    attempt + 1,
                    err_body[:300],
                )
                if retryable and attempt < 2:
                    retry_after = exc.headers.get("Retry-After") if exc.headers else None
                    if not retry_after and "try again in " in err_body:
                        match = re.search(r"try again in ([0-9]+(?:\.[0-9]+)?)s", err_body)
                        if match:
                            retry_after = match.group(1)
                    sleep_time = 0.5 * (2 ** attempt)
                    if retry_after:
                        try:
                            sleep_time = max(0.5, min(float(retry_after), 10.0))
                        except (ValueError, TypeError):
                            pass
                    time.sleep(sleep_time)
                    continue
                raise ProviderError("provider unavailable") from exc
            except (URLError, OSError) as exc:
                logger.warning("AI provider response category=network")
                raise ProviderError("provider unavailable") from exc

        if raw is None:
            raise ProviderError("provider unavailable")

        decision = self._extract_decision_from_raw(raw)
        return self._parse_decision(decision)

    def _extract_decision_from_raw(self, raw: bytes) -> dict[str, Any]:
        """Extract and parse decision JSON, with one bounded repair attempt."""
        try:
            envelope = json.loads(raw.decode("utf-8"))
            msg = envelope["choices"][0]["message"]
            content = msg.get("content")
            if isinstance(content, str):
                return _clean_and_parse_json(content)
            if isinstance(content, dict):
                return content
            if not content and msg.get("tool_calls"):
                first_tool = msg["tool_calls"][0]
                fn = first_tool.get("function", {})
                args = fn.get("arguments", "{}")
                return {
                    "kind": "tool_call",
                    "tool": fn.get("name"),
                    "arguments": json.loads(args) if isinstance(args, str) else args,
                }
            return {}
        except Exception as exc:
            logger.warning("AI provider primary JSON parsing failed (%s), attempting repair", type(exc).__name__)
            # Bounded one-shot repair attempt
            try:
                text = raw.decode("utf-8", errors="replace")
                return _clean_and_parse_json(text)
            except Exception:
                raise ProviderError("provider returned malformed JSON") from exc

    def decide_once(
        self,
        context: dict[str, Any],
        *,
        system_prompt: str,
        max_tokens: int = 2500,
    ) -> ProviderDecision:
        """Make one bounded request for the non-agent foundation path."""
        payload: dict[str, Any] = {
            "model": self.model,
            "temperature": 0,
            "max_tokens": max_tokens,
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": json.dumps(context, separators=(",", ":"), sort_keys=True)},
            ],
        }
        if (self.endpoint == self.gemini_endpoint or "gemini" in self.model.lower()) and _supports_reasoning_effort(self.model):
            payload["reasoning_effort"] = "none"

        request = Request(
            self.endpoint,
            data=json.dumps(payload, separators=(",", ":")).encode("utf-8"),
            headers=self._headers(),
            method="POST",
        )
        location = urlsplit(self.endpoint)
        logger.info(
            "AI foundation request provider=%s model=%s endpoint=%s key_configured=%s",
            "groq" if "groq.com" in self.endpoint else "openai-compatible",
            self.model,
            location.netloc + location.path,
            bool(self.api_key),
        )
        raw: bytes | None = None
        for attempt in range(3):
            try:
                with urlopen(request, timeout=self.timeout_seconds) as response:
                    raw = response.read(2_000_000)
                    logger.info("AI foundation response status=%s attempt=%s", response.status, attempt + 1)
                    break
            except TimeoutError as exc:
                logger.warning("AI foundation response category=timeout")
                raise ProviderTimeout("provider timed out") from exc
            except HTTPError as exc:
                if (exc.code in {404, 429}) and self.model in MODEL_FALLBACKS:
                    fallback_model = MODEL_FALLBACKS[self.model]
                    logger.info("AI foundation model switch %s -> %s (status=%d)", self.model, fallback_model, exc.code)
                    self.model = fallback_model
                    payload["model"] = fallback_model
                    if not _supports_reasoning_effort(fallback_model):
                        payload.pop("reasoning_effort", None)
                    request = Request(
                        self.endpoint,
                        data=json.dumps(payload, separators=(",", ":")).encode("utf-8"),
                        headers=self._headers(),
                        method="POST",
                    )
                    continue

                retryable = exc.code in {408, 429, 500, 502, 503, 504}
                err_body = exc.read().decode("utf-8", errors="replace") if hasattr(exc, "read") else ""
                logger.warning(
                    "AI foundation response status=%s category=http retryable=%s attempt=%s body=%s",
                    exc.code,
                    retryable,
                    attempt + 1,
                    err_body[:300],
                )
                if retryable and attempt < 2:
                    retry_after = exc.headers.get("Retry-After") if exc.headers else None
                    if not retry_after and "try again in " in err_body:
                        match = re.search(r"try again in ([0-9]+(?:\.[0-9]+)?)s", err_body)
                        if match:
                            retry_after = match.group(1)
                    sleep_time = 0.5 * (2 ** attempt)
                    if retry_after:
                        try:
                            sleep_time = max(0.5, min(float(retry_after), 10.0))
                        except (ValueError, TypeError):
                            pass
                    time.sleep(sleep_time)
                    continue
                raise ProviderError("provider unavailable") from exc
            except (URLError, OSError) as exc:
                logger.warning("AI foundation response category=network")
                raise ProviderError("provider unavailable") from exc

        if raw is None:
            raise ProviderError("provider unavailable")

        decision = self._extract_decision_from_raw(raw)
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
        # result object directly. It is still validated by the agent schema.
        if {"summary", "risk_level", "attribution"}.issubset(value):
            return ProviderDecision(kind="final", result=value)
        raise ProviderError("unknown provider decision")


# Friendly name for applications that do not need to know the protocol detail.
OpenAIProvider = OpenAICompatibleProvider
GroqProvider = OpenAICompatibleProvider


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
        "groq",
        "openai",
        "openai_compatible",
        "openai-compatible",
        "gemini",
    }:
        if not api_key:
            raise ProviderError("provider key is missing")
        endpoint = {
            "groq": OpenAICompatibleProvider.groq_endpoint,
            "gemini": OpenAICompatibleProvider.gemini_endpoint,
            "openai": OpenAICompatibleProvider.openai_endpoint,
        }.get(normalized_name, OpenAICompatibleProvider.groq_endpoint)
        return OpenAICompatibleProvider(api_key, model, timeout_seconds, endpoint=endpoint)
    raise ProviderError("provider unavailable")
