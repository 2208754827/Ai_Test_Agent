from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


EffectLevel = Literal[
    "read_only",
    "external_read",
    "resource_write",
    "state_change",
    "destructive",
    "high_load",
    "security_probe",
    "credential_access",
    "code_execution",
    "data_export",
    "financial_action",
    "communication_send",
]
SafetyDecision = Literal[
    "allow",
    "allow_with_limits",
    "clarify",
    "require_confirmation",
    "require_authorization",
    "deny",
]
RiskLevel = Literal["low", "medium", "high", "critical"]
ActivationPolicy = Literal["auto", "confirm", "explicit_only"]
InputProvenance = Literal[
    "system",
    "user",
    "frontend_control",
    "attachment",
    "retrieved_document",
    "memory",
    "tool_output",
]


class IntentDecision(BaseModel):
    target_kind: str = "general"
    objectives: list[str] = Field(default_factory=list)
    requested_actions: list[str] = Field(default_factory=list)
    required_capabilities: list[str] = Field(default_factory=list)
    candidate_mode_key: str | None = None
    confidence: float = 0.0
    needs_clarification: bool = False
    evidence: list[str] = Field(default_factory=list)
    parameters: dict[str, object] = Field(default_factory=dict)


class SafetyAssessment(BaseModel):
    effect_levels: list[EffectLevel] = Field(default_factory=lambda: ["read_only"])
    risk_level: RiskLevel = "low"
    target_scope_status: str = "unknown"
    authorization_status: str = "not_required"
    environment: str = "unknown"
    data_sensitivity: str = "internal"
    direct_injection_signals: list[str] = Field(default_factory=list)
    indirect_injection_signals: list[str] = Field(default_factory=list)
    decision: SafetyDecision = "allow"
    required_approvals: list[str] = Field(default_factory=list)
    restrictions: list[str] = Field(default_factory=list)
    reason_codes: list[str] = Field(default_factory=list)


class ModeSelectionDecision(BaseModel):
    requested_mode_key: str = "default"
    requested_mode_source: str = "session_default"
    candidate_mode_key: str | None = None
    active_mode_key: str = "default"
    activation_policy: ActivationPolicy = "explicit_only"
    ai_selected: bool = False
    needs_confirmation: bool = False
    reason: str = ""


class ToolSafetyDecision(BaseModel):
    behavior: Literal["allow", "ask", "deny"] = "allow"
    reason: str = ""
    reason_code: str = "execution_policy_allow"
    restrictions: list[str] = Field(default_factory=list)


class ContentSafetyAssessment(BaseModel):
    provenance: InputProvenance
    direct_injection_signals: list[str] = Field(default_factory=list)
    indirect_injection_signals: list[str] = Field(default_factory=list)
    restrictions: list[str] = Field(default_factory=list)
    reason_codes: list[str] = Field(default_factory=list)

    @property
    def has_injection_signals(self) -> bool:
        return bool(self.direct_injection_signals or self.indirect_injection_signals)


class SemanticIntentCandidate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target_kind: Literal["general", "api", "ui", "code", "service"] = "general"
    objectives: list[str] = Field(default_factory=list, max_length=8)
    requested_actions: list[str] = Field(default_factory=list, max_length=8)
    required_capabilities: list[str] = Field(default_factory=list, max_length=12)
    candidate_mode_key: Literal[
        "default",
        "api_testing",
        "ui_automation",
        "performance_testing",
        "security_testing",
        "compatibility_testing",
        "smoke_testing",
        "code_review",
    ] | None = None
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    needs_clarification: bool = False
    evidence: list[str] = Field(default_factory=list, max_length=8)
