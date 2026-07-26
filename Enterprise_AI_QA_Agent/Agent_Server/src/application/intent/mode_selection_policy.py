from __future__ import annotations

from src.registry.modes import ModeRegistry
from src.schemas.intent import IntentDecision, ModeSelectionDecision, SafetyAssessment


class ModeSelectionPolicy:
    """Resolve a mode while preserving explicit UI/session choices."""

    def __init__(self, mode_registry: ModeRegistry) -> None:
        self._mode_registry = mode_registry

    RISK_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}

    def resolve(
        self,
        *,
        payload_mode_key: str | None,
        session_mode_key: str | None,
        intent: IntentDecision,
        safety: SafetyAssessment,
    ) -> ModeSelectionDecision:
        if payload_mode_key is not None:
            requested = self._mode_registry.resolve(payload_mode_key)
            return ModeSelectionDecision(
                requested_mode_key=requested.key,
                requested_mode_source="frontend_explicit",
                candidate_mode_key=intent.candidate_mode_key,
                active_mode_key=requested.key,
                activation_policy=requested.activation_policy,
                reason="The frontend explicitly selected the active mode.",
            )
        session_mode = self._mode_registry.resolve(session_mode_key)
        if session_mode.key != "default":
            return ModeSelectionDecision(
                requested_mode_key=session_mode.key,
                requested_mode_source="session_locked",
                candidate_mode_key=intent.candidate_mode_key,
                active_mode_key=session_mode.key,
                activation_policy=session_mode.activation_policy,
                reason="The existing non-default session mode remains active.",
            )

        candidate_key = intent.candidate_mode_key
        if not candidate_key:
            return ModeSelectionDecision(
                requested_mode_key="default",
                requested_mode_source="session_default",
                active_mode_key="default",
                activation_policy=session_mode.activation_policy,
                reason="No specialized mode intent was recognized.",
            )
        candidate = self._mode_registry.get(candidate_key)
        can_auto_select = (
            candidate.activation_policy == "auto"
            and not intent.needs_clarification
            and safety.decision not in {"deny", "require_authorization"}
            and self.RISK_ORDER.get(safety.risk_level, 3)
            <= self.RISK_ORDER.get(candidate.maximum_auto_risk_level, 0)
        )
        if can_auto_select:
            return ModeSelectionDecision(
                requested_mode_key="default",
                requested_mode_source="ai_auto",
                candidate_mode_key=candidate.key,
                active_mode_key=candidate.key,
                activation_policy=candidate.activation_policy,
                ai_selected=True,
                reason="The recognized mode permits automatic activation.",
            )
        return ModeSelectionDecision(
            requested_mode_key="default",
            requested_mode_source="ai_suggestion",
            candidate_mode_key=candidate.key,
            active_mode_key="default",
            activation_policy=candidate.activation_policy,
            needs_confirmation=True,
            reason=(
                "The recognized mode requires explicit selection or confirmation."
                if candidate.activation_policy != "auto"
                else "The intent or safety assessment prevents automatic mode activation."
            ),
        )
