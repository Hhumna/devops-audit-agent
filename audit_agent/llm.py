"""LLM client."""
from __future__ import annotations

import os
import sys
import time

import openai
from openai import OpenAI

RETRYABLE_STATUS = {408, 409, 429}


class LLMError(Exception):
    """Fatal LLM problem: bad configuration, rejected request, or retries exhausted."""


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, "") or default)
    except ValueError:
        return default


class LLMClient:
    """Thin wrapper around the plain OpenAI SDK (works with Gemini's compatible endpoint)."""

    def __init__(self, api_key=None, model=None, base_url=None, timeout=None, max_retries=8):
        self.api_key = (api_key or os.getenv("LLM_API_KEY", "")).strip()
        self.model = (model or os.getenv("LLM_MODEL", "")).strip()
        raw_url = base_url if base_url is not None else os.getenv("LLM_BASE_URL", "")
        self.base_url = raw_url.strip()
        self.timeout = timeout or _env_float("LLM_TIMEOUT_SECONDS", 60.0)
        self.max_retries = max_retries
        if not self.api_key or self.api_key.startswith("your_"):
            raise LLMError("LLM_API_KEY is not set. Copy .env.example to .env and add your key.")
        if not self.model or self.model.startswith("your_"):
            raise LLMError("LLM_MODEL is not set. Set it in .env.")
        self._client = OpenAI(
            api_key=self.api_key,
            base_url=self.base_url or None,
            timeout=self.timeout,
            max_retries=0,
        )

    def _scrub(self, text: str) -> str:
        return text.replace(self.api_key, "[REDACTED]")

    def chat(self, messages: list[dict], tools: list[dict]):
        """Send one chat request and return the assistant message. Retries transient errors."""
        last = "unknown error"
        for attempt in range(self.max_retries + 1):
            try:
                resp = self._client.chat.completions.create(
                    model=self.model, messages=messages, tools=tools, tool_choice="auto"
                )
            except openai.APIConnectionError as exc:
                last = f"connection problem or timeout ({type(exc).__name__})"
            except openai.APIStatusError as exc:
                code = exc.status_code
                if code in (401, 403):
                    raise LLMError(
                        f"authentication failed (HTTP {code}); check LLM_API_KEY"
                    ) from None
                if code == 404:
                    raise LLMError(
                        "model or endpoint not found (HTTP 404); check LLM_MODEL and LLM_BASE_URL"
                    ) from None
                if code == 429 and 'insufficient_quota' in str(exc):
                    raise LLMError('OpenAI quota exhausted (insufficient_quota). Add billing credit at platform.openai.com, then retry.') from None
                if code in RETRYABLE_STATUS or code >= 500:
                    last = f"HTTP {code}"
                else:
                    raise LLMError(
                        f"request rejected (HTTP {code}): {self._scrub(str(exc))[:300]}"
                    ) from None
            except openai.OpenAIError as exc:
                raise LLMError(f"LLM client error: {self._scrub(str(exc))[:300]}") from None
            else:
                if resp.choices:
                    return resp.choices[0].message
                last = "empty response from model"
            if attempt < self.max_retries:
                delay = min(60, 5 * (2 ** attempt))
                print(
                    f"[llm] {last}; retrying in {delay}s ({attempt + 1}/{self.max_retries})",
                    file=sys.stderr, flush=True,
                )
                time.sleep(delay)
        raise LLMError(f"LLM request failed after {self.max_retries + 1} attempts: {last}")


def message_to_dict(msg) -> dict:
    """Convert an assistant message to a plain dict that can be sent back to the API.

    Extra provider fields on tool calls are kept, because some providers require them.
    """
    out: dict = {"role": "assistant", "content": msg.content or ""}
    calls = []
    for index, call in enumerate(msg.tool_calls or []):
        data = call.model_dump(exclude_none=True)
        if not data.get("id"):
            data["id"] = f"call_{index}"
        data.setdefault("type", "function")
        calls.append(data)
    if calls:
        out["tool_calls"] = calls
    return out