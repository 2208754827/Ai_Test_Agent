from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class TokenUsage(BaseModel):
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0

    def merge_latest(self, other: "TokenUsage") -> "TokenUsage":
        """Accumulate output tokens while keeping the latest prompt size.

        prompt_tokens reflects the size of the most recent request context,
        completion/total accumulate across loop iterations within a turn.
        """
        return TokenUsage(
            prompt_tokens=other.prompt_tokens or self.prompt_tokens,
            completion_tokens=self.completion_tokens + other.completion_tokens,
            total_tokens=self.total_tokens + other.total_tokens,
        )


def _as_int(value: Any) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 0


def normalize_usage(provider_usage: Any) -> TokenUsage:
    """Normalize provider usage payloads into a unified TokenUsage.

    Supported shapes:
    - OpenAI-compatible: prompt_tokens / completion_tokens / total_tokens
    - Anthropic messages: input_tokens / output_tokens
    - Google Gemini: promptTokenCount / candidatesTokenCount / totalTokenCount
    """
    if not isinstance(provider_usage, dict) or not provider_usage:
        return TokenUsage()
    prompt = _as_int(
        provider_usage.get("prompt_tokens")
        or provider_usage.get("input_tokens")
        or provider_usage.get("promptTokenCount")
    )
    completion = _as_int(
        provider_usage.get("completion_tokens")
        or provider_usage.get("output_tokens")
        or provider_usage.get("candidatesTokenCount")
    )
    total = _as_int(
        provider_usage.get("total_tokens")
        or provider_usage.get("totalTokenCount")
    )
    if not total:
        total = prompt + completion
    return TokenUsage(
        prompt_tokens=prompt,
        completion_tokens=completion,
        total_tokens=total,
    )


def estimate_tokens(text: str) -> int:
    """Heuristic token estimate used only before the first provider usage
    is available. CJK characters count roughly one token each, other
    characters roughly one token per four characters.
    """
    if not text:
        return 0
    cjk = 0
    other = 0
    for char in text:
        if "\u4e00" <= char <= "\u9fff" or "\u3000" <= char <= "\u30ff":
            cjk += 1
        else:
            other += 1
    return cjk + max(1, other // 4) if other else cjk
