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

from email.utils import parsedate_to_datetime

logger = logging.getLogger(__name__)


class ProviderError(RuntimeError):
    """A provider was unavailable or returned an unusable response."""


class ProviderTimeout(ProviderError):
    """The provider exceeded the configured timeout."""


TRANSIENT_HTTP_CODES = {408, 429, 500, 502, 503, 504}
AUTH_HTTP_CODES = {401, 403}
MAX_RETRIES_PER_MODEL = 3
DEFAULT_MAX_RETRY_DELAY = 10.0
DEFAULT_BASE_BACKOFF = 0.5

MODEL_FALLBACKS: dict[str, list[str]] = {
    "openai/gpt-oss-120b": ["openai/gpt-oss-20b", "qwen/qwen3.8-27b"],
    "openai/gpt-oss-20b": ["qwen/qwen3.8-27b"],
    "llama-3.3-70b-versatile": ["llama-3.1-8b-instant", "groq/compound-mini"],
    "llama-3.1-70b-versatile": ["llama-3.1-8b-instant", "groq/compound-mini"],
    "llama3-70b-8192": ["llama-3.1-8b-instant", "groq/compound-mini"],
    "gemini-3.5-flash": ["gemini-3.5-flash-lite"],
    "gemini-3.8-flash": ["gemini-3.5-flash-lite"],
    "gemini-3-flash-preview": ["gemini-3.5-flash-lite"],
}


def _get_fallback_models(model: str) -> list[str]:
    entry = MODEL_FALLBACKS.get(model, [])
    if isinstance(entry, str):
        return [entry]
    return list(entry)


def _safe_retry_delay(
    headers: Any,
    body: str,
    attempt: int,
    *,
    max_delay: float = DEFAULT_MAX_RETRY_DELAY,
    base_backoff: float = DEFAULT_BASE_BACKOFF,
) -> float:
    """Safely parse Retry-After header or message body delay, strictly bounded by max_delay."""
    retry_val: str | None = None
    if headers:
        retry_val = headers.get("Retry-After")
    if not retry_val and body and "try again in " in body:
        match = re.search(r"try again in ([0-9]+(?:\.[0-9]+)?)s", body)
        if match:
            retry_val = match.group(1)

    if retry_val is not None:
        try:
            delay = float(retry_val)
            if 0.0 <= delay and delay == delay and delay != float("inf"):
                return min(delay, max_delay)
        except (ValueError, TypeError):
            try:
                dt = parsedate_to_datetime(retry_val)
                delay = dt.timestamp() - time.time()
                if 0.0 <= delay:
                    return min(delay, max_delay)
            except Exception:
                pass

    # Exponential backoff: base_backoff * (2 ** attempt)
    backoff = base_backoff * (2 ** attempt)
    return min(backoff, max_delay)


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
    model: str

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
        name: str = "groq",
        endpoint: str | None = None,
        max_retries_per_model: int = MAX_RETRIES_PER_MODEL,
        max_retry_delay: float = DEFAULT_MAX_RETRY_DELAY,
        base_backoff: float = DEFAULT_BASE_BACKOFF,
    ) -> None:
        if not api_key:
            raise ProviderError("provider key is missing")
        self.api_key = api_key
        self.name = name
        self.model = model
        self.timeout_seconds = timeout_seconds
        self.max_retries_per_model = max(1, min(max_retries_per_model, 5))
        self.max_retry_delay = max(0.1, min(max_retry_delay, 60.0))
        self.base_backoff = max(0.01, min(base_backoff, 5.0))
        if endpoint:
            self.endpoint = endpoint

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": "Bearer " + self.api_key,
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "DetectThreatAI/1.0",
        }

    def _execute_request(self, payload: dict[str, Any]) -> bytes:
        """Execute request with bounded retries, safe Retry-After backoff, and graceful model fallback."""
        models_to_try = [self.model]
        for fallback in _get_fallback_models(self.model):
            if fallback not in models_to_try:
                models_to_try.append(fallback)

        last_error: Exception | None = None

        for model_idx, model_name in enumerate(models_to_try):
            self.model = model_name
            payload["model"] = model_name

            # Configure model-specific reasoning parameters
            if "gpt-oss" in model_name.lower() or "qwen" in model_name.lower():
                payload["reasoning_effort"] = "low"
                payload["reasoning_format"] = "parsed"
            elif self.endpoint == self.gemini_endpoint or "gemini" in model_name.lower():
                if _supports_reasoning_effort(model_name):
                    payload["reasoning_effort"] = "none"
                else:
                    payload.pop("reasoning_effort", None)
                payload.pop("reasoning_format", None)
            else:
                payload.pop("reasoning_effort", None)
                payload.pop("reasoning_format", None)

            # Ensure max completion tokens is bounded
            if "max_completion_tokens" not in payload and "max_tokens" not in payload:
                payload["max_completion_tokens"] = 2500

            request = Request(
                self.endpoint,
                data=json.dumps(payload, separators=(",", ":")).encode("utf-8"),
                headers=self._headers(),
                method="POST",
            )
            location = urlsplit(self.endpoint)
            logger.info(
                "AI provider request provider=%s model=%s endpoint=%s key_configured=%s (candidate %d/%d)",
                "groq" if "groq.com" in self.endpoint else ("gemini" if "googleapis.com" in self.endpoint else "openai"),
                self.model,
                location.netloc + location.path,
                bool(self.api_key),
                model_idx + 1,
                len(models_to_try),
            )

            for attempt in range(self.max_retries_per_model):
                try:
                    with urlopen(request, timeout=self.timeout_seconds) as response:
                        raw = response.read(2_000_000)
                        logger.info("AI provider response status=%s model=%s attempt=%s", response.status, self.model, attempt + 1)
                        return raw
                except TimeoutError as exc:
                    logger.warning("AI provider timeout on model=%s attempt=%d", self.model, attempt + 1)
                    last_error = exc
                    if attempt < self.max_retries_per_model - 1:
                        sleep_time = _safe_retry_delay(None, "", attempt, max_delay=self.max_retry_delay, base_backoff=self.base_backoff)
                        time.sleep(sleep_time)
                        continue
                    break
                except HTTPError as exc:
                    err_body = exc.read().decode("utf-8", errors="replace") if hasattr(exc, "read") else ""
                    last_error = exc

                    # Authentication / authorization errors: fail immediately without useless retries
                    if exc.code in AUTH_HTTP_CODES:
                        logger.warning(
                            "AI provider authentication error status=%d model=%s attempt=%d body=%s",
                            exc.code,
                            self.model,
                            attempt + 1,
                            err_body[:300],
                        )
                        raise ProviderError(f"permanent provider error status={exc.code}") from exc

                    # HTTP 400: schema/model compatibility or prompt issue.
                    # Fail clearly on current model and try configured fallback model if available!
                    if exc.code == 400:
                        logger.warning(
                            "AI provider HTTP 400 error status=400 model=%s attempt=%d body=%s; evaluating fallback candidates",
                            self.model,
                            attempt + 1,
                            err_body[:300],
                        )
                        break

                    # HTTP 404: model not found -> move to next fallback candidate
                    if exc.code == 404:
                        logger.warning(
                            "AI provider model not found status=404 model=%s; evaluating fallback candidates",
                            self.model,
                        )
                        break

                    # Transient HTTP errors: 408, 429, 500, 502, 503, 504
                    if exc.code in TRANSIENT_HTTP_CODES:
                        logger.warning(
                            "AI provider transient HTTP error status=%d model=%s attempt=%d/%d body=%s",
                            exc.code,
                            self.model,
                            attempt + 1,
                            self.max_retries_per_model,
                            err_body[:300],
                        )
                        if attempt < self.max_retries_per_model - 1:
                            sleep_time = _safe_retry_delay(exc.headers, err_body, attempt, max_delay=self.max_retry_delay, base_backoff=self.base_backoff)
                            time.sleep(sleep_time)
                            continue
                        logger.warning("Exhausted retries for model=%s on transient HTTP %d", self.model, exc.code)
                        break

                    # Other unhandled HTTP errors
                    logger.warning("AI provider unhandled HTTP error status=%d model=%s", exc.code, self.model)
                    raise ProviderError(f"unhandled provider error status={exc.code}") from exc

                except (URLError, OSError) as exc:
                    logger.warning("AI provider network error on model=%s attempt=%d: %s", self.model, attempt + 1, exc)
                    last_error = exc
                    if attempt < self.max_retries_per_model - 1:
                        sleep_time = _safe_retry_delay(None, "", attempt, max_delay=self.max_retry_delay, base_backoff=self.base_backoff)
                        time.sleep(sleep_time)
                        continue
                    break

        if isinstance(last_error, TimeoutError):
            raise ProviderTimeout("provider timed out") from last_error
        raise ProviderError("provider unavailable") from last_error

    def chat_step(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        *,
        temperature: float = 0,
        max_tokens: int = 2500,
    ) -> dict[str, Any]:
        """Execute one bounded chat step with native OpenAI-compatible function calling."""
        payload: dict[str, Any] = {
            "model": self.model,
            "temperature": temperature,
            "max_completion_tokens": max_tokens,
            "messages": messages,
        }
        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = "auto"
        raw = self._execute_request(payload)
        envelope = json.loads(raw.decode("utf-8"))
        msg = envelope["choices"][0]["message"]
        return msg

    def synthesize_final(
        self,
        messages: list[dict[str, Any]],
        *,
        system_prompt: str | None = None,
        max_tokens: int = 2500,
    ) -> dict[str, Any]:
        """Request the final structured JSON investigation report without tools."""
        synthesis_messages = list(messages)
        if system_prompt:
            synthesis_messages = [
                {"role": "system", "content": system_prompt},
                *[m for m in messages if m.get("role") != "system"],
            ]
        synthesis_messages.append({
            "role": "user",
            "content": "Tool investigation complete. Synthesize your final investigation report as a valid JSON object matching the required schema now.",
        })
        payload: dict[str, Any] = {
            "model": self.model,
            "temperature": 0,
            "max_completion_tokens": max_tokens,
            "response_format": {"type": "json_object"},
            "messages": synthesis_messages,
        }
        raw = self._execute_request(payload)
        return self._extract_decision_from_raw(raw)

    def decide(
        self,
        context: dict[str, Any],
        history: list[dict[str, Any]],
        available_tools: list[str],
    ) -> ProviderDecision:
        """Backward-compatible single-decision interface for legacy mocks."""
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
        raw = self._execute_request(payload)
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
        raw = self._execute_request(payload)
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
    max_retries_per_model: int = MAX_RETRIES_PER_MODEL,
    max_retry_delay: float = DEFAULT_MAX_RETRY_DELAY,
    base_backoff: float = DEFAULT_BASE_BACKOFF,
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
        return OpenAICompatibleProvider(
            api_key,
            model,
            timeout_seconds,
            name=normalized_name,
            endpoint=endpoint,
            max_retries_per_model=max_retries_per_model,
            max_retry_delay=max_retry_delay,
            base_backoff=base_backoff,
        )
    raise ProviderError("provider unavailable")
