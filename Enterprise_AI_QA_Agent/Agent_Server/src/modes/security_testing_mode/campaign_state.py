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


class ScenarioFact(BaseModel):
    """One scenario statement with explicit provenance and confidence."""

    fact_id: str = ""
    statement: str = ""
    source_type: str = "observed"  # observed / user_declared / model_inference
    evidence_ids: list[str] = Field(default_factory=list)
    confidence: float = 0.0


class SecurityScenarioProfile(BaseModel):
    """Evidence-backed business and trust-boundary model for one target."""

    scenario_id: str = ""
    target: str = ""
    product_type: str = "unknown"
    business_capabilities: list[str] = Field(default_factory=list)
    technologies: list[str] = Field(default_factory=list)
    entry_points: list[str] = Field(default_factory=list)
    auth_flows: list[str] = Field(default_factory=list)
    roles: list[str] = Field(default_factory=list)
    sensitive_data_types: list[str] = Field(default_factory=list)
    trust_boundaries: list[str] = Field(default_factory=list)
    external_dependencies: list[str] = Field(default_factory=list)
    facts: list[ScenarioFact] = Field(default_factory=list)
    assumptions: list[str] = Field(default_factory=list)
    unknowns: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)
    confidence: float = 0.0
    analyzed_at: str = ""


class ThreatHypothesis(BaseModel):
    """A testable threat derived from a scenario fact or stated assumption."""

    threat_id: str = ""
    scenario_id: str = ""
    asset_id: str = ""
    actor: str = "unauthenticated"
    entry_point: str = ""
    trust_boundary: str = ""
    technique: str = ""
    cwe_ids: list[str] = Field(default_factory=list)
    owasp_categories: list[str] = Field(default_factory=list)
    attack_references: list[str] = Field(default_factory=list)
    expected_impact: list[str] = Field(default_factory=list)
    supporting_fact_ids: list[str] = Field(default_factory=list)
    assumptions: list[str] = Field(default_factory=list)
    priority: int = 0
    confidence: float = 0.0


class ThreatIntelligenceRecord(BaseModel):
    """Provenanced security intelligence; never an executable command."""

    intelligence_id: str = ""
    source_url: str = ""
    source_type: str = ""
    title: str = ""
    published_at: str = ""
    retrieved_at: str = ""
    content_hash: str = ""
    applicable_products: list[str] = Field(default_factory=list)
    applicable_versions: list[str] = Field(default_factory=list)
    prerequisites: list[str] = Field(default_factory=list)
    cve_ids: list[str] = Field(default_factory=list)
    cwe_ids: list[str] = Field(default_factory=list)
    confidence: str = "unverified"
    validation_status: str = "pending"
    evidence_ids: list[str] = Field(default_factory=list)


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


class CredentialReference(BaseModel):
    """Redacted credential metadata that is safe for graph/report persistence."""

    credential_ref_id: str = ""
    auth_type: str = "none"
    principal_hint: str = ""
    source: str = ""
    expires_at: str = ""
    secret_present: bool = False


class AccessProof(BaseModel):
    """Evidence-backed access state; never stores a credential secret."""

    proof_id: str = ""
    target: str = ""
    principal: str = ""
    privilege: str = "unknown"
    source_attempt_id: str = ""
    evidence_ids: list[str] = Field(default_factory=list)
    expires_at: str = ""
    credential_ref_id: str = ""
    observed_at: str = ""


class AssetRelation(BaseModel):
    """A time-bounded, evidence-backed relation between two assets."""

    relation_id: str = ""
    source_asset_id: str = ""
    relation: str = ""  # reaches / trusts / authenticates_to / hosts
    target_asset_id: str = ""
    discovered_by: str = ""
    evidence_ids: list[str] = Field(default_factory=list)
    confidence: float = 0.0
    observed_at: str = ""


class CallbackLeaseState(BaseModel):
    """Auditable P3 loopback callback lease; no callback payload is retained."""

    lease_id: str = ""
    campaign_id: str = ""
    target: str = ""
    protocol: str = "http"
    callback_url: str = ""
    port: int = 0
    approval_scope_hash: str = ""
    status: str = "planned"  # active / expired / released / denied
    created_at: str = ""
    expires_at: str = ""
    released_at: str = ""
    release_reason: str = ""
    callback_count: int = 0
    callback_sources: list[str] = Field(default_factory=list)
    cleanup_complete: bool = False


class SecurityGraphPersistenceState(BaseModel):
    """Outcome of optional graph persistence; failure must not break campaign."""

    status: str = "not_requested"  # disabled / unavailable / completed / failed
    backend: str = ""
    detail: str = ""
    node_count: int = 0
    relation_count: int = 0
    persisted_at: str = ""


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
    planning_rationale: str = ""
    scenario_fact_refs: list[str] = Field(default_factory=list)
    threat_hypothesis_ids: list[str] = Field(default_factory=list)


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


class SecurityShellCommandState(BaseModel):
    """Auditable result of one command in a P1 campaign session."""

    command_id: str = ""
    step: str = ""
    command: str = ""
    target: str = ""
    container_name: str = ""
    started_at: str = ""
    completed_at: str = ""
    exit_code: int | None = None
    timed_out: bool = False
    stdout_summary: str = ""
    stderr_summary: str = ""
    evidence_ids: list[str] = Field(default_factory=list)


class SecurityShellSessionState(BaseModel):
    """Serialized P1 campaign-scoped persistent session state."""

    session_id: str = ""
    campaign_id: str = ""
    container_name: str = ""
    target_allowlist: list[str] = Field(default_factory=list)
    approval_scope_hash: str = ""
    status: str = "not_requested"
    created_at: str = ""
    closed_at: str = ""
    close_reason: str = ""
    heartbeat_ok: bool = False
    cleanup_complete: bool = False
    commands: list[SecurityShellCommandState] = Field(default_factory=list)


class ExploitWorkspaceState(BaseModel):
    """Serialized P2 verifier generation, compilation and execution result."""

    workspace_id: str = ""
    hypothesis_id: str = ""
    target: str = ""
    language: str = "python"
    filename: str = "verifier.py"
    status: str = "not_requested"
    failure_category: str = ""
    failure_reason: str = ""
    next_route: str = ""
    source_summary: str = ""
    source_hash: str = ""
    artifact_hash: str = ""
    static_check_status: str = "pending"
    static_check_findings: list[str] = Field(default_factory=list)
    compile_command: str = ""
    compile_exit_code: int | None = None
    compile_stdout: str = ""
    compile_stderr: str = ""
    execute_command: str = ""
    execute_exit_code: int | None = None
    execute_stdout: str = ""
    execute_stderr: str = ""
    impact_verdict: str = "not_evaluated"
    result_class: str = "confirmed"
    container_name: str = ""
    workspace_path: str = ""
    created_at: str = ""
    completed_at: str = ""
    cleanup_complete: bool = False


class ToolBootstrapState(BaseModel):
    """Auditable P4 temporary-tool readiness and execution record."""

    bootstrap_id: str = ""
    campaign_id: str = ""
    profile_key: str = ""
    tool_name: str = ""
    package_name: str = ""
    requested_version: str = ""
    resolved_version: str = ""
    image_ref: str = ""
    image_digest: str = ""
    repository_id: str = ""
    network_name: str = ""
    approval_scope_hash: str = ""
    status: str = "not_requested"  # waiting_approval / already_available / completed / failed / cleaned
    failure_category: str = ""
    failure_reason: str = ""
    command_template_id: str = ""
    readiness_command: str = ""
    install_command: str = ""
    profile_command: str = ""
    readiness_exit_code: int | None = None
    install_exit_code: int | None = None
    profile_exit_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    manifest_path: str = ""
    container_name: str = ""
    created_at: str = ""
    completed_at: str = ""
    cleanup_complete: bool = False


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
    cvss_vector: str = ""
    cvss_rationale: str = ""
    cve_id: str = ""
    cwe_ids: list[str] = Field(default_factory=list)
    owasp_categories: list[str] = Field(default_factory=list)
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
    verification_level: str = "observed"  # observed / confirmed / exploitable / impact_verified
    evidence_ids: list[str] = Field(default_factory=list)
    # Impact proof is explicit structured evidence, not an inference from a
    # vulnerability title. Values are redacted/normalized before persistence.
    exposed_data_types: list[str] = Field(default_factory=list)
    exposed_record_estimate: int | None = None
    confidentiality_impact: str = "none"
    integrity_impact: str = "none"
    availability_impact: str = "none"
    false_positive: bool = False
    # When True, the severity is trusted as-is and SeverityEvaluator skips
    # the impact/exploitability promotion math. Use for trivially-verifiable
    # baseline checks (e.g. "missing X-Frame-Options header") that pentesters
    # conventionally rate as low/info regardless of category baseline.
    is_baseline_check: bool = False


class VulnerabilityHypothesis(BaseModel):
    """Evidence-backed candidate that may enter controlled verification."""

    hypothesis_id: str = ""
    finding_id: str = ""
    title: str = ""
    target: str = ""
    attack_surface: str = ""
    preconditions: list[str] = Field(default_factory=list)
    proposed_profiles: list[str] = Field(default_factory=list)
    expected_proof: list[str] = Field(default_factory=list)
    risk_level: str = "medium"
    status: str = "proposed"  # proposed / approved / running / verified / rejected / blocked
    approval_id: str = ""
    approval_status: str = "not_evaluated"  # not_required / required / approved / denied
    authorization_scope_hash: str = ""
    attempt_ids: list[str] = Field(default_factory=list)
    result_class: str = "detected"
    failure_reason: str = ""
    created_at: str = ""
    updated_at: str = ""


class VerificationAttempt(BaseModel):
    """One auditable, bounded verification action for one or more hypotheses."""

    attempt_id: str = ""
    hypothesis_id: str = ""
    hypothesis_ids: list[str] = Field(default_factory=list)
    finding_ids: list[str] = Field(default_factory=list)
    task_id: str = ""
    profile_key: str = ""
    target: str = ""
    status: str = "planned"  # planned / running / succeeded / failed / blocked / cancelled
    attempt_number: int = 1
    command: str = ""
    exit_code: int | None = None
    stdout_summary: str = ""
    stderr_summary: str = ""
    evidence_ids: list[str] = Field(default_factory=list)
    failure_category: str = ""
    next_route: str = ""
    cleanup_status: str = "pending"
    approval_required: bool = False
    approval_status: str = "not_required"
    result_class: str = "detected"
    started_at: str = ""
    completed_at: str = ""


class SecurityBugEvidenceRef(BaseModel):
    """Globally traceable evidence reference for a Security Bug occurrence."""

    campaign_id: str = ""
    session_id: str = ""
    attempt_id: str = ""
    artifact_id: str = ""
    source_task_id: str = ""
    created_at: str = ""


class SecurityBugRetestRecord(BaseModel):
    """One immutable initial-confirmation or retest result."""

    retest_id: str = ""
    campaign_id: str = ""
    session_id: str = ""
    attempt_id: str = ""
    outcome: str = "reproduced"  # reproduced / not_reproduced / inconclusive
    verification_level: str = "confirmed"
    actual_result: str = ""
    evidence_refs: list[SecurityBugEvidenceRef] = Field(default_factory=list)
    tested_at: str = ""


class SecurityBugRecord(BaseModel):
    """Persistent, deduplicated and independently reproducible security defect."""

    bug_id: str = ""
    fingerprint: str = ""
    title: str = ""
    status: str = "confirmed"  # confirmed / fixed / retest_failed / closed / false_positive
    verification_level: str = "confirmed"
    severity: str = "info"
    cvss_score: float | None = None
    cvss_vector: str = ""
    cvss_rationale: str = ""
    cve_ids: list[str] = Field(default_factory=list)
    cwe_ids: list[str] = Field(default_factory=list)
    owasp_categories: list[str] = Field(default_factory=list)
    target_fingerprint: str = ""
    affected_target: str = ""
    affected_component: str = ""
    affected_versions: list[str] = Field(default_factory=list)
    auth_required: bool = False
    required_role: str = ""
    preconditions: list[str] = Field(default_factory=list)
    reproduction_steps: list[str] = Field(default_factory=list)
    reproduction_request: str = ""
    expected_result: str = ""
    actual_result: str = ""
    evidence_ids: list[str] = Field(default_factory=list)
    evidence_refs: list[SecurityBugEvidenceRef] = Field(default_factory=list)
    exposed_data_types: list[str] = Field(default_factory=list)
    exposed_record_estimate: int | None = None
    confidentiality_impact: str = "none"
    integrity_impact: str = "none"
    availability_impact: str = "none"
    business_impact: str = ""
    remediation: str = ""
    regression_case_id: str = ""
    regression_profile: str = ""
    campaign_ids: list[str] = Field(default_factory=list)
    finding_ids: list[str] = Field(default_factory=list)
    attempt_ids: list[str] = Field(default_factory=list)
    occurrence_count: int = 0
    first_seen_at: str = ""
    last_seen_at: str = ""
    fixed_version: str = ""
    lifecycle_note: str = ""
    retest_history: list[SecurityBugRetestRecord] = Field(default_factory=list)


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


class CampaignSettlement(BaseModel):
    """Single source of truth for campaign terminal status."""

    status: str = "running"  # success / partial / blocked / failed
    reason: str = ""
    all_tasks_settled: bool = False
    all_chains_settled: bool = False
    report_ready: bool = False
    cleanup_complete: bool = False
    finalized_at: str = ""


class SecurityCampaign(BaseModel):
    """Represents one security testing campaign."""

    campaign_id: str = ""
    objective: str = ""
    target_fingerprint: str = ""
    targets: list[TargetCandidate] = Field(default_factory=list)
    assets: list[AssetNode] = Field(default_factory=list)
    fingerprints: list[NetworkServiceFingerprint] = Field(default_factory=list)
    credential_session: CredentialSession | None = None
    credential_references: list[CredentialReference] = Field(default_factory=list)
    access_proofs: list[AccessProof] = Field(default_factory=list)
    asset_relations: list[AssetRelation] = Field(default_factory=list)
    callback_leases: list[CallbackLeaseState] = Field(default_factory=list)
    graph_persistence: SecurityGraphPersistenceState | None = None
    objectives: list[SecurityObjective] = Field(default_factory=list)
    subtasks: list[SecuritySubtask] = Field(default_factory=list)
    tasks: list[SecurityTask] = Field(default_factory=list)
    findings: list[FindingRecord] = Field(default_factory=list)
    vulnerability_hypotheses: list[VulnerabilityHypothesis] = Field(default_factory=list)
    verification_attempts: list[VerificationAttempt] = Field(default_factory=list)
    security_bugs: list[SecurityBugRecord] = Field(default_factory=list)
    attack_loop_count: int = 0
    evidence: list[EvidenceArtifact] = Field(default_factory=list)
    activities: list[AgentActivityRecord] = Field(default_factory=list)
    execution_records: list[ToolExecutionRecord] = Field(default_factory=list)
    shell_session: SecurityShellSessionState | None = None
    exploit_workspaces: list[ExploitWorkspaceState] = Field(default_factory=list)
    tool_bootstraps: list[ToolBootstrapState] = Field(default_factory=list)
    scenario_profile: SecurityScenarioProfile | None = None
    threat_hypotheses: list[ThreatHypothesis] = Field(default_factory=list)
    # Append-only structured audit records. Keeping these as dictionaries
    # makes scenario changes visible in persisted session snapshots, reports,
    # and object-storage artifacts without reparsing JSON strings.
    scenario_replan_audit: list[dict[str, Any]] = Field(default_factory=list)
    threat_intelligence: list[ThreatIntelligenceRecord] = Field(default_factory=list)
    settlement: CampaignSettlement | None = None
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
    hypotheses: list[VulnerabilityHypothesis] = Field(default_factory=list)
    verification_attempts: list[VerificationAttempt] = Field(default_factory=list)
    security_bugs: list[SecurityBugRecord] = Field(default_factory=list)
    hypothesis_count: int = 0
    verification_attempt_count: int = 0
    security_bug_count: int = 0
    reproduced_bug_count: int = 0
    fixed_bug_count: int = 0
    retest_failed_bug_count: int = 0
    verified_exploitable_count: int = 0
    impact_verified_count: int = 0
    blocked_by_control_count: int = 0
    activities: list[AgentActivityRecord] = Field(default_factory=list)
    assets_discovered: int = 0
    services_discovered: int = 0
    evidence_count: int = 0
    execution_record_count: int = 0
    shell_session: SecurityShellSessionState | None = None
    exploit_workspaces: list[ExploitWorkspaceState] = Field(default_factory=list)
    exploit_workspace_count: int = 0
    exploit_workspace_completed_count: int = 0
    tool_bootstraps: list[ToolBootstrapState] = Field(default_factory=list)
    tool_bootstrap_count: int = 0
    tool_bootstrap_completed_count: int = 0
    threat_intelligence: list[ThreatIntelligenceRecord] = Field(default_factory=list)
    threat_intelligence_count: int = 0
    callback_leases: list[CallbackLeaseState] = Field(default_factory=list)
    callback_lease_count: int = 0
    graph_persistence: SecurityGraphPersistenceState | None = None
    duration_seconds: float = 0.0
    tested_at: str = ""
    generated_at: str = ""
    recommendations: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    artifacts: list[dict[str, Any]] = Field(default_factory=list)
    verification_result: dict[str, Any] = Field(default_factory=dict)
    evaluation_result: dict[str, Any] = Field(default_factory=dict)
    settlement: dict[str, Any] = Field(default_factory=dict)


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
    request_fingerprint: str = ""
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
    "ScenarioFact",
    "SecurityScenarioProfile",
    "ThreatHypothesis",
    "ThreatIntelligenceRecord",
    "TargetCandidate",
    "AssetNode",
    "NetworkServiceFingerprint",
    "CredentialSession",
    "CredentialReference",
    "AccessProof",
    "AssetRelation",
    "CallbackLeaseState",
    "SecurityGraphPersistenceState",
    "SecurityObjective",
    "SecuritySubtask",
    "SecurityTask",
    "ToolExecutionRecord",
    "SecurityShellCommandState",
    "SecurityShellSessionState",
    "ExploitWorkspaceState",
    "ToolBootstrapState",
    "FindingRecord",
    "VulnerabilityHypothesis",
    "VerificationAttempt",
    "SecurityBugEvidenceRef",
    "SecurityBugRetestRecord",
    "SecurityBugRecord",
    "EvidenceArtifact",
    "AgentActivityRecord",
    "SecurityCampaign",
    "CampaignSettlement",
    "SecurityReport",
    "ReportDeliveryRecord",
    "SecurityTaskEventRecord",
    "SecurityTestingState",
]
