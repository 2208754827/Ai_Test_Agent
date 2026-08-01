"""Security Testing Mode campaign and runtime state models.

All state is Pydantic-serializable so it can be persisted in
``session.metadata`` and restored across turns.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


logger = logging.getLogger("uvicorn.error.security_testing_mode.campaign_state")


# ---------------------------------------------------------------------------
# Request interpretation
# ---------------------------------------------------------------------------


class SecurityTestingRequestState(BaseModel):
    """Interpretation of the user's security testing intent."""

    model_config = ConfigDict(extra="allow")

    objective: str = ""
    target_url: str = ""
    target_host: str = ""
    target_network: str = ""
    target_type: str = ""  # url / host / network / domain
    scope_preference: str = ""  # full / limited / passive_only
    auth_hint: str = ""
    credentials: dict[str, str] = Field(default_factory=dict)
    focus_areas: list[str] = Field(default_factory=list)
    excluded_areas: list[str] = Field(default_factory=list)
    risk_tolerance: str = "medium"  # low / medium / high
    target_fingerprint: str = ""
    platform_label: str = ""
    access_constraints: list[str] = Field(default_factory=list)
    report_recipients: list[str] = Field(default_factory=list)
    raw_message: str = ""


# ---------------------------------------------------------------------------
# Target and asset models
# ---------------------------------------------------------------------------


class TargetCandidate(BaseModel):
    """A resolved target for security testing."""

    target_id: str = ""
    target_type: str = ""  # url / host / ip / network / domain
    value: str = ""  # the actual URL, IP, domain, or CIDR
    label: str = ""
    fingerprint: str = ""
    resolved_ip: str = ""
    resolved_domain: str = ""
    port: int | None = None
    protocol: str = ""
    notes: str = ""


class AssetNode(BaseModel):
    """A discovered asset (host, service, endpoint, etc.)."""

    asset_id: str = ""
    asset_type: str = ""  # host / service / web_app / api_endpoint / domain
    address: str = ""  # IP or URL
    hostname: str = ""
    port: int | None = None
    protocol: str = ""
    service_name: str = ""
    service_version: str = ""
    os_hint: str = ""
    technologies: list[str] = Field(default_factory=list)
    discovered_by: str = ""  # task_id that discovered this
    confidence: float = 1.0
    notes: str = ""


class NetworkServiceFingerprint(BaseModel):
    """Fingerprint of a network service."""

    host: str = ""
    port: int = 0
    protocol: str = "tcp"
    service_name: str = ""
    service_version: str = ""
    banner: str = ""
    state: str = "open"  # open / closed / filtered
    cpe: str = ""
    os_hint: str = ""


# ---------------------------------------------------------------------------
# Credential session
# ---------------------------------------------------------------------------


class CredentialSession(BaseModel):
    """Resolved credentials or login state for the current campaign."""

    credential_session_id: str = ""
    auth_type: str = "none"  # none / bearer / basic / cookie / api_key
    username: str = ""
    token: str = ""
    cookie_jar: dict[str, str] = Field(default_factory=dict)
    headers: dict[str, str] = Field(default_factory=dict)
    expires_at: str = ""
    source: str = ""  # user_input / auto_login / dynamic
    login_url: str = ""
    notes: str = ""


# ---------------------------------------------------------------------------
# Security objective and task
# ---------------------------------------------------------------------------


class SecurityObjective(BaseModel):
    """High-level security testing objective."""

    objective_id: str = ""
    title: str = ""
    description: str = ""
    surface_type: str = ""
    priority: int = 0
    status: str = "pending"


class SecuritySubtask(BaseModel):
    """PentAGI-style structured subtask derived from executable tasks."""

    subtask_id: str = ""
    task_id: str = ""
    title: str = ""
    description: str = ""
    allowed_profiles: list[str] = Field(default_factory=list)
    risk_level: str = "low"
    success_criteria: list[str] = Field(default_factory=list)
    stop_conditions: list[str] = Field(default_factory=list)
    status: str = "planned"
    worker_agent_key: str = ""
    tool_family: str = ""
    target: str = ""
    result_summary: str = ""
    failure_category: str = ""
    notes: list[str] = Field(default_factory=list)


class SecurityTask(BaseModel):
    """One executable security testing task inside a campaign."""

    task_id: str
    name: str = ""
    description: str = ""
    surface_type: str = ""  # network / host / web / api / credential / service
    tool_family: str = ""  # network_recon / web_scan / service_audit / ...
    command_profile: str = ""  # profile key from command_profiles registry
    target: str = ""  # specific target for this task (IP, URL, etc.)
    target_port: int | None = None
    depends_on: list[str] = Field(default_factory=list)
    risk_level: str = "low"  # info / low / medium / high / critical
    requires_approval: bool = False
    resource_locks: list[str] = Field(default_factory=list)
    timeout_seconds: int = 300
    max_retries: int = 2

    # Runtime-managed fields
    status: str = "pending"
    attempts: int = 0
    # S2 scheduling-loop bookkeeping.
    reflect_attempts: int = 0  # times the Reflector re-sent this task for structured output
    refine_origin: str = ""  # id/label of the refinement pass that produced this task
    started_at: str = ""
    completed_at: str = ""
    worker_session_id: str = ""
    worker_status: str = ""
    worker_agent_key: str = ""
    worker_execution_mode: str = ""
    result_summary: str = ""
    raw_output: str = ""
    last_error: str = ""
    failure_analysis: dict[str, Any] = Field(default_factory=dict)
    artifacts: list[str] = Field(default_factory=list)
    observations: list[str] = Field(default_factory=list)
    finding_refs: list[str] = Field(default_factory=list)
    parsed_result: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Execution record
# ---------------------------------------------------------------------------


class ToolExecutionRecord(BaseModel):
    """Record of a single tool execution within a task."""

    record_id: str = ""
    task_id: str = ""
    tool_name: str = ""
    command: str = ""
    started_at: str = ""
    completed_at: str = ""
    duration_seconds: float = 0.0
    exit_code: int | None = None
    stdout_summary: str = ""
    stderr_summary: str = ""
    success: bool = False
    error: str = ""
    artifacts: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Finding and evidence
# ---------------------------------------------------------------------------


class FindingRecord(BaseModel):
    """A security finding (vulnerability, misconfiguration, etc.)."""

    finding_id: str = ""
    title: str = ""
    category: str = ""  # vulnerability / misconfiguration / information_disclosure / ...
    surface_type: str = ""
    severity: str = "info"  # info / low / medium / high / critical
    confidence: str = "medium"  # low / medium / high / confirmed
    cvss_score: float | None = None
    cve_id: str = ""
    affected_target: str = ""
    affected_port: int | None = None
    affected_service: str = ""
    description: str = ""
    evidence_summary: str = ""
    reproduction_steps: list[str] = Field(default_factory=list)
    recommendation: str = ""
    references: list[str] = Field(default_factory=list)
    source_task_ids: list[str] = Field(default_factory=list)
    raw_evidence: str = ""
    verified: bool = False
    false_positive: bool = False
    # When True, the severity is trusted as-is and SeverityEvaluator skips
    # the impact/exploitability promotion math. Use for trivially-verifiable
    # baseline checks (e.g. "missing X-Frame-Options header") that pentesters
    # conventionally rate as low/info regardless of category baseline.
    is_baseline_check: bool = False


class EvidenceArtifact(BaseModel):
    """An evidence artifact attached to a finding or task."""

    artifact_id: str = ""
    artifact_type: str = ""  # screenshot / log / output / pcap / report
    filename: str = ""
    content_type: str = ""
    content: str = ""  # base64 or text content
    size_bytes: int = 0
    source_task_id: str = ""
    finding_id: str = ""
    created_at: str = ""


# ---------------------------------------------------------------------------
# Agent activity record
# ---------------------------------------------------------------------------


class AgentActivityRecord(BaseModel):
    """Record of an agent's activity during the campaign."""

    activity_id: str = ""
    agent_key: str = ""
    agent_name: str = ""
    task_id: str = ""
    action: str = ""  # dispatched / completed / failed / reflected
    summary: str = ""
    started_at: str = ""
    completed_at: str = ""
    duration_seconds: float = 0.0
    execution_mode: str = ""
    tool_calls: list[str] = Field(default_factory=list)
    notes: str = ""


# ---------------------------------------------------------------------------
# Campaign
# ---------------------------------------------------------------------------


class SecurityCampaign(BaseModel):
    """Represents one security testing campaign."""

    campaign_id: str = ""
    objective: str = ""
    target_fingerprint: str = ""
    targets: list[TargetCandidate] = Field(default_factory=list)
    assets: list[AssetNode] = Field(default_factory=list)
    fingerprints: list[NetworkServiceFingerprint] = Field(default_factory=list)
    credential_session: CredentialSession | None = None
    objectives: list[SecurityObjective] = Field(default_factory=list)
    subtasks: list[SecuritySubtask] = Field(default_factory=list)
    tasks: list[SecurityTask] = Field(default_factory=list)
    findings: list[FindingRecord] = Field(default_factory=list)
    evidence: list[EvidenceArtifact] = Field(default_factory=list)
    activities: list[AgentActivityRecord] = Field(default_factory=list)
    execution_records: list[ToolExecutionRecord] = Field(default_factory=list)
    scope_notes: str = ""
    operational_constraints: list[str] = Field(default_factory=list)
    risk_tolerance: str = "medium"
    max_workers: int = 3
    created_at: str = ""
    updated_at: str = ""


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------


class SecurityReport(BaseModel):
    """Aggregated security testing report."""

    campaign_id: str = ""
    title: str = ""
    target_summary: str = ""
    scope_description: str = ""
    executive_summary: str = ""
    total_tasks: int = 0
    completed_tasks: int = 0
    failed_tasks: int = 0
    skipped_tasks: int = 0
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    findings: list[FindingRecord] = Field(default_factory=list)
    activities: list[AgentActivityRecord] = Field(default_factory=list)
    assets_discovered: int = 0
    services_discovered: int = 0
    evidence_count: int = 0
    execution_record_count: int = 0
    duration_seconds: float = 0.0
    tested_at: str = ""
    generated_at: str = ""
    recommendations: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    artifacts: list[dict[str, Any]] = Field(default_factory=list)
    verification_result: dict[str, Any] = Field(default_factory=dict)
    evaluation_result: dict[str, Any] = Field(default_factory=dict)


class ReportDeliveryRecord(BaseModel):
    """Delivery status for the generated security report."""

    channel: str = "email"
    status: str = "not_requested"  # not_requested / awaiting_confirmation / sent / failed / skipped
    recipients: list[str] = Field(default_factory=list)
    subject: str = ""
    summary: str = ""
    sent: bool = False
    provider: str = ""
    from_email: str = ""
    recipient_count: int = 0
    confirmation_required: bool = False
    confirmation_token: str = ""
    confirmation_summary: str = ""
    artifact_paths: list[str] = Field(default_factory=list)
    error: str = ""
    delivered_at: str = ""


class SecurityTaskEventRecord(BaseModel):
    """A checkpoint event emitted while a security campaign is executing."""

    event_id: str = ""
    event_type: str = ""  # task_running / task_completed / task_failed / task_skipped
    task_id: str = ""
    task_name: str = ""
    command_profile: str = ""
    tool_family: str = ""
    target: str = ""
    status: str = ""
    phase: str = ""
    attempts: int = 0
    worker_agent_key: str = ""
    worker_session_id: str = ""
    execution_mode: str = ""
    runner_key: str = ""
    summary: str = ""
    error: str = ""
    at: str = ""


# ---------------------------------------------------------------------------
# Full state machine
# ---------------------------------------------------------------------------


class SecurityTestingState(BaseModel):
    """Top-level state captured per session for the security testing mode."""

    session_id: str = ""
    trace_id: str = ""
    phase: str = "request_resolved"
    previous_phase: str = ""
    selected_agent: str = ""
    selected_tools: list[str] = Field(default_factory=list)
    context_refs: list[dict[str, Any]] = Field(default_factory=list)
    recalled_patterns: list[dict[str, Any]] = Field(default_factory=list)
    request: SecurityTestingRequestState = Field(default_factory=SecurityTestingRequestState)
    targets: list[TargetCandidate] = Field(default_factory=list)
    campaign: SecurityCampaign | None = None
    report: SecurityReport | None = None
    report_markdown: str = ""
    report_html: str = ""
    execution_strategy: str = ""
    artifacts: list[dict[str, Any]] = Field(default_factory=list)
    verification_result: dict[str, Any] = Field(default_factory=dict)
    evaluation_result: dict[str, Any] = Field(default_factory=dict)
    execution_checkpoint: dict[str, Any] = Field(default_factory=dict)
    task_events: list[SecurityTaskEventRecord] = Field(default_factory=list)
    delivery: ReportDeliveryRecord | None = None
    last_updated_at: str = ""
    history: list[dict[str, Any]] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
    errors: list[dict[str, Any]] = Field(default_factory=list)
    error: str = ""

    def record_phase_transition(self, new_phase: str, reason: str = "") -> None:
        """Record a phase change and keep track of the previous one."""
        old_phase = self.phase
        if self.phase != new_phase:
            self.previous_phase = self.phase
        self.phase = new_phase
        self.last_updated_at = datetime.now(timezone.utc).isoformat()
        if reason:
            self.history.append(
                {
                    "phase": new_phase,
                    "reason": reason,
                    "at": self.last_updated_at,
                }
            )
        logger.info(
            "security_phase_transition %s",
            json.dumps(
                {
                    "session_id": self.session_id,
                    "trace_id": self.trace_id,
                    "campaign_id": self.campaign.campaign_id if self.campaign else "",
                    "from_phase": old_phase,
                    "to_phase": new_phase,
                    "reason": reason,
                },
                ensure_ascii=False,
                separators=(",", ":"),
            ),
        )


__all__ = [
    "SecurityTestingRequestState",
    "TargetCandidate",
    "AssetNode",
    "NetworkServiceFingerprint",
    "CredentialSession",
    "SecurityObjective",
    "SecuritySubtask",
    "SecurityTask",
    "ToolExecutionRecord",
    "FindingRecord",
    "EvidenceArtifact",
    "AgentActivityRecord",
    "SecurityCampaign",
    "SecurityReport",
    "ReportDeliveryRecord",
    "SecurityTaskEventRecord",
    "SecurityTestingState",
]
