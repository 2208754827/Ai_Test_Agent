from __future__ import annotations

import re

from src.graph.state import AgentGraphState
from src.application.security.output_safety_policy import OutputSafetyPolicy
from src.runtime.execution_logging import append_graph_event, truncate_text

# Pattern matching bare artifact download URLs that the LLM may output as
# plain text instead of markdown links.  The responder converts these into
# proper markdown links so the frontend can render clickable download buttons.
# Negative lookbehind for `](` ensures we don't double-wrap URLs that are
# already part of a markdown link like `[text](url)`.
_ARTIFACT_URL_RE = re.compile(
    r"(?<!\]\()"                                      # not preceded by ](markdown link)
    r"(/api/v1/sessions/[a-f0-9-]+/artifacts/[a-f0-9-]+/content)"
    r"(?!\))",                                         # not followed by )(end of markdown link)
    re.IGNORECASE,
)


def responder(state: AgentGraphState) -> AgentGraphState:
    if state["continue_loop"] or not state["final_response"].strip():
        return state

    plan_text = "\n".join(f"{index}. {item}" for index, item in enumerate(state["plan_steps"], start=1))
    tool_text = (
        "\n".join(f"- {item['tool_key']}: {item['status']} - {item['summary']}" for item in state["tool_results"])
        if state["tool_results"]
        else "- No tools selected for this turn."
    )
    skill_text = ", ".join(state["resolved_skill_keys"]) or "none"
    approval_text = (
        "Pending tool approvals exist. The framework has paused sensitive tool execution until approval is resolved."
        if state["pending_approvals"]
        else "No pending approvals. The runtime skeleton completed this turn without blocking tools."
    )

    sanitized_response, redacted = OutputSafetyPolicy().sanitize_text(state["final_response"].strip())

    # Convert bare artifact download URLs to markdown links so the frontend
    # renders them as clickable download buttons.  The LLM (especially
    # GLM-5.1) often outputs the URL as plain text despite SKILL.md
    # instructions, so we enforce the correct format here.
    sanitized_response = _linkify_artifact_urls(sanitized_response)

    state["final_response"] = sanitized_response
    append_graph_event(
        state,
        "graph.response_ready",
        "responder",
        "Assistant response payload has been finalized for the client.",
        agent_key=state["selected_agent_key"],
        model_key=state["selected_model_key"],
        agent_name=state["selected_agent_name"],
        model_name=state["selected_model_name"],
        resolved_skills=skill_text,
        available_tools=",".join(state["available_tool_keys"]) or "none",
        model_visible_tools=",".join(state["model_visible_tool_keys"]) or "none",
        allowed_tools=",".join(state["allowed_tool_keys"]) or "none",
        execution_plan=plan_text,
        tool_status=tool_text,
        approval_status=approval_text,
        pending_approval_count=len(state["pending_approvals"]),
        sensitive_output_redacted=redacted,
        response_preview=truncate_text(state["final_response"], 180),
    )
    return state


def _linkify_artifact_urls(text: str) -> str:
    """Convert bare artifact download URLs to markdown links.

    If the LLM outputs a URL like
        /api/v1/sessions/{id}/artifacts/{id}/content
    as plain text (not already inside a markdown link), this function wraps
    it into ``[⬇ 点击下载]({url})`` so the frontend renders a clickable
    download button.
    """
    def _replace(match: re.Match) -> str:
        url = match.group(1)
        return f"[⬇ 点击下载]({url})"
    return _ARTIFACT_URL_RE.sub(_replace, text)
