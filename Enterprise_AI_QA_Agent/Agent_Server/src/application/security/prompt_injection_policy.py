from __future__ import annotations

import base64
import html
import re
import unicodedata
from collections.abc import Iterable
from typing import Any
from urllib.parse import unquote

from src.schemas.intent import ContentSafetyAssessment, InputProvenance


class PromptInjectionPolicy:
    """Detect control-like instructions without treating untrusted content as authority."""

    UNTRUSTED_PROVENANCE = {
        "attachment",
        "retrieved_document",
        "memory",
        "tool_output",
    }
    PATTERNS: dict[str, tuple[re.Pattern[str], ...]] = {
        "ignore_previous_instructions": (
            re.compile(r"ignore\s+(?:all\s+)?(?:previous|prior|above)\s+(?:(?:system|developer)\s+)?(?:instructions?|rules?|prompts?)", re.I),
            re.compile(r"忽略\s*(?:之前|以上|前面|所有)\s*(?:的)?\s*(?:(?:系统|开发者)\s*)?(?:指令|规则|提示词|要求)"),
        ),
        "system_prompt_request": (
            re.compile(r"(?:reveal|show|print|return|extract).{0,40}(?:system|developer)\s+(?:prompt|message)", re.I),
            re.compile(r"(?:显示|输出|返回|提取|泄露).{0,30}(?:系统|开发者)(?:提示词|消息|指令)"),
        ),
        "policy_bypass": (
            re.compile(r"(?:bypass|disable|override).{0,30}(?:policy|guardrail|permission|safety)", re.I),
            re.compile(r"(?:绕过|关闭|覆盖|解除).{0,20}(?:安全|权限|策略|限制)"),
            re.compile(r"\bjailbreak\b", re.I),
        ),
        "secret_exfiltration": (
            re.compile(r"(?:read|collect|extract|export).{0,40}(?:environment variables?|api keys?|tokens?|credentials?|secrets?)", re.I),
            re.compile(r"(?:读取|收集|提取|导出).{0,30}(?:环境变量|密钥|令牌|凭据|密码)"),
        ),
        "external_exfiltration": (
            re.compile(r"(?:send|upload|post|exfiltrate).{0,60}(?:secret|token|credential|api key|environment variable)", re.I),
            re.compile(r"(?:发送|上传|提交).{0,40}(?:密钥|令牌|凭据|密码|环境变量)"),
        ),
        "authority_impersonation": (
            re.compile(r"(?:i am|act as|this is).{0,30}(?:the system|developer|administrator|root)", re.I),
            re.compile(r"(?:我是|作为|这就是).{0,20}(?:系统|开发者|管理员|最高权限)"),
        ),
    }

    def assess(self, content: Any, provenance: InputProvenance) -> ContentSafetyAssessment:
        candidates = self._candidate_texts(self._stringify(content))
        signals = [
            key
            for key, patterns in self.PATTERNS.items()
            if any(pattern.search(candidate) for pattern in patterns for candidate in candidates)
        ]
        signals = list(dict.fromkeys(signals))
        indirect = provenance in self.UNTRUSTED_PROVENANCE
        return ContentSafetyAssessment(
            provenance=provenance,
            direct_injection_signals=[] if indirect else signals,
            indirect_injection_signals=signals if indirect else [],
            restrictions=(
                ["ignore_untrusted_instructions", "do_not_expand_tool_access"]
                if signals
                else []
            ),
            reason_codes=["prompt_injection_signals_detected"] if signals else [],
        )

    def merge_into_safety(
        self,
        safety: dict[str, Any],
        assessments: Iterable[ContentSafetyAssessment],
    ) -> dict[str, Any]:
        merged = dict(safety)
        direct = list(merged.get("direct_injection_signals") or [])
        indirect = list(merged.get("indirect_injection_signals") or [])
        restrictions = list(merged.get("restrictions") or [])
        reason_codes = list(merged.get("reason_codes") or [])
        for assessment in assessments:
            direct.extend(assessment.direct_injection_signals)
            indirect.extend(assessment.indirect_injection_signals)
            restrictions.extend(assessment.restrictions)
            reason_codes.extend(assessment.reason_codes)
        merged["direct_injection_signals"] = list(dict.fromkeys(direct))
        merged["indirect_injection_signals"] = list(dict.fromkeys(indirect))
        merged["restrictions"] = list(dict.fromkeys(restrictions))
        merged["reason_codes"] = list(dict.fromkeys(reason_codes))
        if (direct or indirect) and merged.get("decision") == "allow":
            merged["decision"] = "allow_with_limits"
        return merged

    def _candidate_texts(self, text: str) -> list[str]:
        normalized = unicodedata.normalize("NFKC", html.unescape(text))
        normalized = re.sub(r"[\u200b-\u200f\u202a-\u202e\u2060\ufeff]", "", normalized)
        candidates = [normalized]
        decoded_url = unquote(unquote(normalized))
        if decoded_url != normalized:
            candidates.append(decoded_url)
        candidates.extend(self._decode_base64_segments(normalized))
        return list(dict.fromkeys(item for item in candidates if item))

    def _decode_base64_segments(self, text: str) -> list[str]:
        decoded: list[str] = []
        for match in re.finditer(r"(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/_-]{24,400}={0,2}(?![A-Za-z0-9+/=_-])", text):
            token = match.group(0)
            try:
                raw = base64.urlsafe_b64decode(token + "=" * (-len(token) % 4))
                value = raw.decode("utf-8")
            except (ValueError, UnicodeDecodeError):
                continue
            if value and sum(character.isprintable() for character in value) / len(value) >= 0.9:
                decoded.append(unicodedata.normalize("NFKC", value))
        return decoded

    def _stringify(self, content: Any) -> str:
        if isinstance(content, str):
            return content
        if isinstance(content, dict):
            return "\n".join(f"{key}: {self._stringify(value)}" for key, value in content.items())
        if isinstance(content, (list, tuple, set)):
            return "\n".join(self._stringify(item) for item in content)
        return str(content or "")
