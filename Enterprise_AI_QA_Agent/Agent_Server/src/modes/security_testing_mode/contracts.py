"""Security Testing Mode contracts.

Defines phase constants, task statuses, risk levels, surface types,
and other shared constants used across the security testing mode.
"""
from __future__ import annotations

from typing import Literal


# ---------------------------------------------------------------------------
# Phase machine
# ---------------------------------------------------------------------------

PHASE_REQUEST_RESOLVED = "request_resolved"
PHASE_TARGET_DISCOVERED = "target_discovered"
PHASE_SCOPE_CONFIRMED = "scope_confirmed"
PHASE_ASSET_DISCOVERED = "asset_discovered"
PHASE_RECON_RUNNING = "recon_running"
PHASE_RECON_COMPLETE = "recon_complete"
PHASE_AUTH_PREPARED = "auth_prepared"
PHASE_ATTACK_PLAN_READY = "attack_plan_ready"
PHASE_TASK_DISPATCHING = "task_dispatching"
PHASE_TASK_RUNNING = "task_running"
PHASE_RESULT_COLLECTION = "result_collection"
PHASE_FAILURE_ANALYSIS = "failure_analysis"
PHASE_REPORT_READY = "report_ready"
PHASE_EMAIL_DELIVERED = "email_delivered"
PHASE_INTERRUPTED = "interrupted"
PHASE_FAILED = "failed"

SecurityTestingPhase = Literal[
    "request_resolved",
    "target_discovered",
    "scope_confirmed",
    "asset_discovered",
    "recon_running",
    "recon_complete",
    "auth_prepared",
    "attack_plan_ready",
    "task_dispatching",
    "task_running",
    "result_collection",
    "failure_analysis",
    "report_ready",
    "email_delivered",
    "interrupted",
    "failed",
]

TERMINAL_PHASES = frozenset({PHASE_REPORT_READY, PHASE_EMAIL_DELIVERED, PHASE_INTERRUPTED, PHASE_FAILED})

AWAITING_PHASES = frozenset({PHASE_SCOPE_CONFIRMED})


# ---------------------------------------------------------------------------
# Task lifecycle
# ---------------------------------------------------------------------------

TASK_PENDING = "pending"
TASK_BLOCKED = "blocked"
TASK_READY = "ready"
TASK_RUNNING = "running"
TASK_COMPLETED = "completed"
TASK_FAILED = "failed"
TASK_SKIPPED = "skipped"

TaskStatus = Literal[
    "pending", "blocked", "ready", "running", "completed", "failed", "skipped"
]


# ---------------------------------------------------------------------------
# Risk / Severity levels
# ---------------------------------------------------------------------------

RISK_INFO = "info"
RISK_LOW = "low"
RISK_MEDIUM = "medium"
RISK_HIGH = "high"
RISK_CRITICAL = "critical"

RiskLevel = Literal["info", "low", "medium", "high", "critical"]

SEVERITY_ORDER: dict[str, int] = {
    RISK_INFO: 0,
    RISK_LOW: 1,
    RISK_MEDIUM: 2,
    RISK_HIGH: 3,
    RISK_CRITICAL: 4,
}


# ---------------------------------------------------------------------------
# Surface types
# ---------------------------------------------------------------------------

SURFACE_NETWORK = "network"
SURFACE_HOST = "host"
SURFACE_WEB = "web"
SURFACE_API = "api"
SURFACE_CREDENTIAL = "credential"
SURFACE_SERVICE = "service"

SurfaceType = Literal["network", "host", "web", "api", "credential", "service"]


# ---------------------------------------------------------------------------
# Tool families (maps to runner keys)
# ---------------------------------------------------------------------------

FAMILY_NETWORK_RECON = "network_recon"
FAMILY_WEB_SCAN = "web_scan"
FAMILY_SERVICE_AUDIT = "service_audit"
FAMILY_CREDENTIAL_ATTACK = "credential_attack"
FAMILY_TRAFFIC_ANALYSIS = "traffic_analysis"
FAMILY_EXPLOIT = "exploit"
FAMILY_GENERAL_SCAN = "general_scan"

ToolFamily = Literal[
    "network_recon",
    "web_scan",
    "service_audit",
    "credential_attack",
    "traffic_analysis",
    "exploit",
    "general_scan",
]

FAMILY_TO_RUNNER: dict[str, str] = {
    FAMILY_NETWORK_RECON: "network-recon-runner",
    FAMILY_WEB_SCAN: "web-scan-runner",
    FAMILY_SERVICE_AUDIT: "service-audit-runner",
    FAMILY_CREDENTIAL_ATTACK: "credential-attack-runner",
    FAMILY_TRAFFIC_ANALYSIS: "traffic-analysis-runner",
    FAMILY_EXPLOIT: "exploit-workbench-runner",
    FAMILY_GENERAL_SCAN: "security-scan-runner",
}


# ---------------------------------------------------------------------------
# Finding categories
# ---------------------------------------------------------------------------

FINDING_VULNERABILITY = "vulnerability"
FINDING_MISCONFIGURATION = "misconfiguration"
FINDING_INFORMATION_DISCLOSURE = "information_disclosure"
FINDING_WEAK_CREDENTIAL = "weak_credential"
FINDING_MISSING_CONTROL = "missing_control"
FINDING_OUTDATED_SOFTWARE = "outdated_software"

FindingCategory = Literal[
    "vulnerability",
    "misconfiguration",
    "information_disclosure",
    "weak_credential",
    "missing_control",
    "outdated_software",
]


# ---------------------------------------------------------------------------
# Campaign state key used inside session.metadata and context_bundle
# ---------------------------------------------------------------------------

STATE_METADATA_KEY = "security_testing_state"
REQUEST_CONTEXT_KEY = "security_testing_request"


# ---------------------------------------------------------------------------
# Worker agent keys
# ---------------------------------------------------------------------------

WORKER_RECON = "security-recon-worker"
WORKER_WEB_VERIFIER = "security-web-verifier"
WORKER_API_VERIFIER = "security-api-verifier"
WORKER_HOST_VERIFIER = "security-host-verifier"
WORKER_AUTH = "security-auth-worker"
WORKER_FAILURE_ANALYST = "security-failure-analyst"


# ---------------------------------------------------------------------------
# Max retries and limits
# ---------------------------------------------------------------------------

MAX_TASK_RETRIES = 2
MAX_CAMPAIGN_TASKS = 50
MAX_CONCURRENT_WORKERS = 3
TOOL_EXEC_TIMEOUT_SECONDS = 300


__all__ = [
    "PHASE_REQUEST_RESOLVED",
    "PHASE_TARGET_DISCOVERED",
    "PHASE_SCOPE_CONFIRMED",
    "PHASE_ASSET_DISCOVERED",
    "PHASE_RECON_RUNNING",
    "PHASE_RECON_COMPLETE",
    "PHASE_AUTH_PREPARED",
    "PHASE_ATTACK_PLAN_READY",
    "PHASE_TASK_DISPATCHING",
    "PHASE_TASK_RUNNING",
    "PHASE_RESULT_COLLECTION",
    "PHASE_FAILURE_ANALYSIS",
    "PHASE_REPORT_READY",
    "PHASE_EMAIL_DELIVERED",
    "PHASE_INTERRUPTED",
    "PHASE_FAILED",
    "TERMINAL_PHASES",
    "AWAITING_PHASES",
    "SecurityTestingPhase",
    "TASK_PENDING",
    "TASK_BLOCKED",
    "TASK_READY",
    "TASK_RUNNING",
    "TASK_COMPLETED",
    "TASK_FAILED",
    "TASK_SKIPPED",
    "TaskStatus",
    "RISK_INFO",
    "RISK_LOW",
    "RISK_MEDIUM",
    "RISK_HIGH",
    "RISK_CRITICAL",
    "RiskLevel",
    "SEVERITY_ORDER",
    "SURFACE_NETWORK",
    "SURFACE_HOST",
    "SURFACE_WEB",
    "SURFACE_API",
    "SURFACE_CREDENTIAL",
    "SURFACE_SERVICE",
    "SurfaceType",
    "FAMILY_NETWORK_RECON",
    "FAMILY_WEB_SCAN",
    "FAMILY_SERVICE_AUDIT",
    "FAMILY_CREDENTIAL_ATTACK",
    "FAMILY_TRAFFIC_ANALYSIS",
    "FAMILY_EXPLOIT",
    "FAMILY_GENERAL_SCAN",
    "ToolFamily",
    "FAMILY_TO_RUNNER",
    "FINDING_VULNERABILITY",
    "FINDING_MISCONFIGURATION",
    "FINDING_INFORMATION_DISCLOSURE",
    "FINDING_WEAK_CREDENTIAL",
    "FINDING_MISSING_CONTROL",
    "FINDING_OUTDATED_SOFTWARE",
    "FindingCategory",
    "STATE_METADATA_KEY",
    "REQUEST_CONTEXT_KEY",
    "WORKER_RECON",
    "WORKER_WEB_VERIFIER",
    "WORKER_API_VERIFIER",
    "WORKER_HOST_VERIFIER",
    "WORKER_AUTH",
    "WORKER_FAILURE_ANALYST",
    "MAX_TASK_RETRIES",
    "MAX_CAMPAIGN_TASKS",
    "MAX_CONCURRENT_WORKERS",
    "TOOL_EXEC_TIMEOUT_SECONDS",
]
