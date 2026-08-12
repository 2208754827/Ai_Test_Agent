"""Structure-preserving compaction for large security tool output (S4).

Worker tools (nmap / nuclei / nikto / httpx / sqlmap ...) can emit tens of
kilobytes of output. The previous behaviour truncated the head to a fixed
character budget, which frequently dropped the very lines that carry the
finding (a CVE id near the end of a nuclei run, an open-port table, a
vulnerable URL).

This module replaces that blind truncation with a deterministic *extractive*
summary: it keeps a head/tail context window plus every security-relevant
"signal" line (ports, services, CVE ids, URLs, HTTP status, vulnerability and
severity markers), preserving original order and staying within a byte budget.

Why not the shared ``context_compaction_service``? That service summarizes a
``SessionRecord`` message transcript via an async model call. The compaction
here runs inside the synchronous result-persistence path (``_apply_worker_output``)
where no model runtime is available and blocking on an LLM per task would be
costly and failure-prone. A deterministic, dependency-free compactor is the
right primitive for this hot path; an LLM-backed semantic pass can be layered
on later without changing this call site.
"""
from __future__ import annotations

import re

DEFAULT_THRESHOLD_BYTES = 16384
_DEFAULT_HEAD_LINES = 40
_DEFAULT_TAIL_LINES = 20
_MAX_SIGNAL_LINES = 400
_PER_LINE_CHAR_CAP = 2000

# High-signal patterns worth preserving verbatim from security tool output.
_SIGNAL_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE),
    re.compile(r"https?://", re.IGNORECASE),
    re.compile(r"\b\d{1,5}/(?:tcp|udp)\b", re.IGNORECASE),  # nmap port rows
    re.compile(r"\b(?:open|filtered|closed)\b", re.IGNORECASE),
    re.compile(r"\b(?:critical|high|medium|low)\b", re.IGNORECASE),
    re.compile(r"\bvuln", re.IGNORECASE),  # vulnerable / vulnerability
    re.compile(r"\b(?:misconfig|exposed|disclosure|leak|injection|traversal|bypass)", re.IGNORECASE),
    re.compile(r"\b(?:password|credential|secret|token|api[_-]?key)\b", re.IGNORECASE),
    re.compile(r"\b(?:server|x-powered-by|set-cookie|www-authenticate)\s*:", re.IGNORECASE),
    re.compile(r"\bHTTP/\d", re.IGNORECASE),
    re.compile(r"\b[1-5]\d\d\b\s*(?:ok|found|moved|forbidden|unauthorized|error)", re.IGNORECASE),
    re.compile(r"\b(?:tls|ssl|certificate|cipher|expired|self-signed)\b", re.IGNORECASE),
    re.compile(r"\[(?:critical|high|medium|low|info)\]", re.IGNORECASE),  # nuclei severity tags
    re.compile(r"^\s*\[[+\-*!]\]"),  # [+]/[-]/[*]/[!] tool markers
)


def byte_length(text: str) -> int:
    return len(text.encode("utf-8", errors="replace"))


def is_signal_line(line: str) -> bool:
    return any(pattern.search(line) for pattern in _SIGNAL_PATTERNS)


def compact_security_output(
    text: str,
    *,
    max_bytes: int = DEFAULT_THRESHOLD_BYTES,
    head_lines: int = _DEFAULT_HEAD_LINES,
    tail_lines: int = _DEFAULT_TAIL_LINES,
) -> str:
    """Return ``text`` unchanged when small, else a structure-preserving digest.

    The digest keeps a head context window, every signal line (deduplicated,
    in original order, capped), and a tail context window. It never blindly
    drops the tail of the output the way a head truncation does.
    """
    raw = str(text or "")
    if max_bytes <= 0 or byte_length(raw) <= max_bytes:
        return raw

    lines = raw.splitlines()
    total_lines = len(lines)
    head_lines = max(0, head_lines)
    tail_lines = max(0, tail_lines)

    # Index-tagged selection so we can restore original order and dedupe.
    selected: dict[int, str] = {}
    for idx in range(min(head_lines, total_lines)):
        selected[idx] = lines[idx]
    for idx in range(max(0, total_lines - tail_lines), total_lines):
        selected[idx] = lines[idx]

    signal_indices: list[int] = [
        idx for idx, line in enumerate(lines) if line.strip() and is_signal_line(line)
    ]
    truncated_signals = False
    if len(signal_indices) > _MAX_SIGNAL_LINES:
        signal_indices = signal_indices[:_MAX_SIGNAL_LINES]
        truncated_signals = True
    for idx in signal_indices:
        selected[idx] = lines[idx]

    ordered = [
        _cap_line(selected[idx]) for idx in sorted(selected)
    ]

    header = (
        f"[security-output compacted: original {byte_length(raw)} bytes / "
        f"{total_lines} lines -> kept {len(ordered)} lines "
        f"({len(signal_indices)} signal + head/tail context)"
        + ("; signal lines truncated" if truncated_signals else "")
        + "]"
    )
    body = "\n".join(ordered)
    result = f"{header}\n{body}"

    # Final safety cap: if even the digest is oversized, keep the header and as
    # many leading digest characters as the budget allows (signals are already
    # front-loaded via head + ordered signal lines).
    budget = max(max_bytes, len(header) + 1)
    if byte_length(result) > budget:
        result = _truncate_to_bytes(result, budget) + "\n[...digest truncated to byte budget...]"
    return result


def _cap_line(line: str) -> str:
    if len(line) > _PER_LINE_CHAR_CAP:
        return line[:_PER_LINE_CHAR_CAP] + "...(line truncated)"
    return line


def _truncate_to_bytes(text: str, max_bytes: int) -> str:
    encoded = text.encode("utf-8", errors="replace")
    if len(encoded) <= max_bytes:
        return text
    return encoded[:max_bytes].decode("utf-8", errors="ignore")


__all__ = [
    "DEFAULT_THRESHOLD_BYTES",
    "byte_length",
    "is_signal_line",
    "compact_security_output",
]
