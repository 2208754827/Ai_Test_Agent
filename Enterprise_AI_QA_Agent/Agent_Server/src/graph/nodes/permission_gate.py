from __future__ import annotations

from src.application.permissions.permission_service import PermissionPolicyContext, PermissionService
from src.graph.state import AgentGraphState
from src.registry.tools import ToolRegistry
from src.runtime.execution_logging import append_graph_event
from src.schemas.session import MessageKind, RuntimeMode, SessionMode


def build_permission_gate(
    permission_service: PermissionService,
    tool_registry: ToolRegistry,
):
    def permission_gate(state: AgentGraphState) -> AgentGraphState:
        # On loop iterations, skip permission re-evaluation — permissions stay the same within a turn.
        if state.get("skip_routing") and state["loop_iteration"] > 0:
            append_graph_event(
                state,
                "graph.permission_gate_skipped",
                "permission_gate",
                "Permission gate skipped on loop iteration (skip_routing=True).",
                loop_iteration=state["loop_iteration"],
            )
            return state

        tool_descriptors = tool_registry.get_many(state["available_tool_keys"])
        input_envelope = dict(state.get("context_bundle", {}).get("input_envelope") or {})
        input_routing = dict(state.get("context_bundle", {}).get("input_routing") or {})
        safety_assessment = dict(state.get("context_bundle", {}).get("safety_assessment") or {})

        # Extract child tool whitelist from context (set by coordinator dispatch → input_orchestrator)
        child_tool_whitelist: list[str] | None = None
        context_bundle = state.get("context_bundle") or {}
        # Primary location: context_bundle.allowed_tool_keys (set by input_orchestrator from session.metadata)
        whitelist_raw = context_bundle.get("allowed_tool_keys")
        # Fallback: context_bundle.session_resources.allowed_tool_keys
        if not isinstance(whitelist_raw, list) or not whitelist_raw:
            session_resources = context_bundle.get("session_resources") or {}
            if isinstance(session_resources, dict):
                whitelist_raw = session_resources.get("allowed_tool_keys")
        if isinstance(whitelist_raw, list) and whitelist_raw:
            child_tool_whitelist = [str(key).strip() for key in whitelist_raw if str(key).strip()]

        policy_context = PermissionPolicyContext(
            session_mode=SessionMode(state["session_mode"]),
            runtime_mode=RuntimeMode(state["runtime_mode"]),
            selected_agent_key=state["selected_agent_key"],
            message_kind=MessageKind(input_envelope.get("message_kind", MessageKind.user_input.value)),
            submit_mode=str(input_envelope.get("submit_mode") or "immediate"),
            execution_lane=str(input_routing.get("execution_lane") or "conversation_turn"),
            source=str(input_envelope.get("source") or "session.send_message"),
            active_mode_key=str(state.get("mode_key") or "default"),
            workflow_mode_key=str(state.get("mode_key") or "default"),
            safety_decision=str(safety_assessment.get("decision") or "allow"),
            safety_risk_level=str(safety_assessment.get("risk_level") or "low"),
            authorization_status=str(safety_assessment.get("authorization_status") or "not_required"),
            environment=str(safety_assessment.get("environment") or "unknown"),
            child_tool_whitelist=child_tool_whitelist,
        )
        evaluation = permission_service.evaluate(
            policy_context=policy_context,
            tools=tool_descriptors,
        )

        state["allowed_tool_keys"] = evaluation.allowed_tool_keys
        state["approval_required_tool_keys"] = evaluation.approval_required_tool_keys
        state["denied_tool_keys"] = evaluation.denied_tool_keys
        state["model_visible_tool_keys"] = evaluation.model_visible_tool_keys
        state["permission_decisions"] = [item.to_payload() for item in evaluation.decisions]
        state["pending_approvals"] = []
        append_graph_event(
            state,
            "graph.permission_evaluated",
            "permission_gate",
            "Tool permissions have been evaluated for this turn.",
            policy_session_mode=policy_context.session_mode.value,
            policy_runtime_mode=policy_context.runtime_mode.value,
            policy_message_kind=policy_context.message_kind.value,
            policy_execution_lane=policy_context.execution_lane,
            available_tools=",".join(state["available_tool_keys"]) or "none",
            model_visible_tools=",".join(state["model_visible_tool_keys"]) or "none",
            allowed_tools=",".join(state["allowed_tool_keys"]) or "none",
            approval_required_tools=",".join(state["approval_required_tool_keys"]) or "none",
            denied_tools=",".join(state["denied_tool_keys"]) or "none",
            hidden_tools=",".join(evaluation.hidden_tool_keys) or "none",
            model_visible_tool_count=len(state["model_visible_tool_keys"]),
            allowed_tool_count=len(state["allowed_tool_keys"]),
            approval_required_count=len(state["approval_required_tool_keys"]),
            denied_tool_count=len(state["denied_tool_keys"]),
        )
        return state

    return permission_gate
