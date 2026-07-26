from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any

from src.application.security.output_safety_policy import OutputSafetyPolicy


_AUDIT_OUTPUT_POLICY = OutputSafetyPolicy()

from src.graph.state import AgentGraphState
from src.schemas.session import ExecutionEvent


def truncate_text(value: str, limit: int = 180) -> str:
    normalized = " ".join(value.split())
    if len(normalized) <= limit:
        return normalized
    return normalized[: limit - 3] + "..."


def summarize_messages(messages: list[dict[str, Any]], limit: int = 2) -> list[dict[str, str]]:
    return [
        {
            "role": str(item.get("role", "unknown")),
            "content_preview": truncate_text(str(item.get("content", "")), 160),
        }
        for item in messages[:limit]
    ]


def append_graph_event(
    state: AgentGraphState,
    event_type: str,
    phase: str,
    message: str,
    **payload: Any,
) -> None:
    event_log = state.setdefault("event_log", [])
    event_payload: dict[str, Any] = {
        "step": len(event_log) + 1,
        "phase": phase,
        "message": message,
        "turn_id": state.get("turn_id", ""),
        "trace_id": state.get("trace_id", ""),
    }
    if event_payload["trace_id"]:
        event_payload["correlation_id"] = f"{event_payload['trace_id']}:{event_payload['step']}"
    event_payload.update(_AUDIT_OUTPUT_POLICY.sanitize_for_audit(payload))
    event_log.append({"type": event_type, "payload": event_payload})

    # Real-time push to SSE queue so the frontend receives events as they happen
    event_queue: asyncio.Queue | None = state.get("_event_queue")
    if event_queue is not None:
        session_id: str = state.get("session_id", "")
        event = ExecutionEvent(
            type=event_type,
            session_id=session_id,
            timestamp=datetime.now(timezone.utc),
            payload=event_payload,
        )
        try:
            event_queue.put_nowait(event)
            state["_streamed_event_count"] = state.get("_streamed_event_count", 0) + 1
        except asyncio.QueueFull:
            pass
