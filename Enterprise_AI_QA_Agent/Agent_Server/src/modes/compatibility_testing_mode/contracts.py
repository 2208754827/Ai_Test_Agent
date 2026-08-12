from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, Field


ProductType = Literal[
    "web",
    "h5",
    "android_app",
    "ios_app",
    "wechat_mini_program",
    "alipay_mini_program",
    "linux_app",
    "unknown",
]

CompatibilityPhase = Literal[
    "intake",
    "probe",
    "matrix_planned",
    "cases_planned",
    "awaiting_approval",
    "dispatching",
    "running",
    "aggregating",
    "report_ready",
    "completed",
    "failed",
    "cancelled",
]

EnvironmentAvailability = Literal["available", "missing_provider", "missing_runner", "planned_only"]
CompatibilityPriority = Literal["P0", "P1", "P2"]
CaseRiskLevel = Literal["low", "medium", "high"]


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(tzinfo=None).isoformat(timespec="seconds") + "Z"


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid4().hex[:12]}"


class AuthProfile(BaseModel):
    strategy: str = "unspecified"
    username_ref: str | None = None
    password_ref: str | None = None
    token_ref: str | None = None
    manual_steps: list[str] = Field(default_factory=list)


class ProductArtifact(BaseModel):
    kind: str = "entrypoint"
    uri: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)


class ProductEntrypoint(BaseModel):
    url: str | None = None
    package_name: str | None = None
    activity: str | None = None
    bundle_id: str | None = None
    mini_program_path: str | None = None
    command: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class ProductNetworkProfile(BaseModel):
    requires_vpn: bool = False
    base_api: str | None = None
    proxy: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class ProductTestScope(BaseModel):
    modules: list[str] = Field(default_factory=list)
    priority_flows: list[str] = Field(default_factory=list)
    exclude: list[str] = Field(default_factory=list)
    forbidden_actions: list[str] = Field(default_factory=list)
    data_policy: str = "unspecified"


class ProductAccessManifest(BaseModel):
    manifest_id: str = Field(default_factory=lambda: new_id("access"))
    schema_version: int = 1
    product_type: ProductType = "unknown"
    name: str = "未命名产品"
    version: str | None = None
    artifact: ProductArtifact | None = None
    entrypoint: ProductEntrypoint = Field(default_factory=ProductEntrypoint)
    auth: AuthProfile = Field(default_factory=AuthProfile)
    network: ProductNetworkProfile = Field(default_factory=ProductNetworkProfile)
    test_scope: ProductTestScope = Field(default_factory=ProductTestScope)
    metadata: dict[str, Any] = Field(default_factory=dict)


class ProductProfile(BaseModel):
    product_profile_id: str = Field(default_factory=lambda: new_id("product"))
    name: str = "未命名产品"
    product_type: ProductType = "unknown"
    entrypoint: str = ""
    artifacts: list[ProductArtifact] = Field(default_factory=list)
    access_manifest: ProductAccessManifest | None = None
    auth: AuthProfile = Field(default_factory=AuthProfile)
    test_scope: list[str] = Field(default_factory=list)
    priority_flows: list[str] = Field(default_factory=list)
    forbidden_actions: list[str] = Field(default_factory=list)
    data_policy: str = "unspecified"
    metadata: dict[str, Any] = Field(default_factory=dict)


class ProductProbeSummary(BaseModel):
    product_type: ProductType = "unknown"
    automation_capabilities: list[str] = Field(default_factory=list)
    required_providers: list[str] = Field(default_factory=list)
    manual_intervention_points: list[str] = Field(default_factory=list)
    blocking_requirements: list[str] = Field(default_factory=list)
    confidence: str = "medium"
    notes: list[str] = Field(default_factory=list)


class EnvironmentSpec(BaseModel):
    environment_id: str = Field(default_factory=lambda: new_id("env"))
    name: str
    priority: CompatibilityPriority = "P1"
    product_types: list[ProductType] = Field(default_factory=list)
    provider: str
    os: str | None = None
    os_version: str | None = None
    browser: str | None = None
    browser_version: str | None = None
    device: str | None = None
    viewport: str | None = None
    automation_driver: str | None = None
    availability: EnvironmentAvailability = "planned_only"
    unavailable_reason: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class CompatibilityStep(BaseModel):
    action: str
    target: str | None = None
    value_ref: str | None = None
    assertion: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class CompatibilityCase(BaseModel):
    case_id: str = Field(default_factory=lambda: new_id("case"))
    name: str
    priority: CompatibilityPriority = "P1"
    applicable_product_types: list[ProductType] = Field(default_factory=list)
    steps: list[CompatibilityStep] = Field(default_factory=list)
    assertions: list[str] = Field(default_factory=list)
    risk_level: CaseRiskLevel = "low"
    requires_manual_approval: bool = False
    notes: list[str] = Field(default_factory=list)


class CompatibilityRiskItem(BaseModel):
    risk_id: str = Field(default_factory=lambda: new_id("risk"))
    case_id: str | None = None
    action: str
    level: CaseRiskLevel = "medium"
    reason: str
    suggested_control: str


class CompatibilityPlan(BaseModel):
    plan_id: str = Field(default_factory=lambda: new_id("plan"))
    version: int = 1
    status: str = "awaiting_user_confirmation"
    product: ProductProfile
    probe: ProductProbeSummary
    environments: list[EnvironmentSpec] = Field(default_factory=list)
    cases: list[CompatibilityCase] = Field(default_factory=list)
    risks: list[CompatibilityRiskItem] = Field(default_factory=list)
    estimated_task_count: int = 0
    estimated_duration_minutes: int = 0
    created_at: str = Field(default_factory=utc_now)
    notes: list[str] = Field(default_factory=list)


class RunnerSelector(BaseModel):
    provider: str
    capabilities: list[str] = Field(default_factory=list)
    os: str | None = None
    os_version: str | None = None
    browser: str | None = None
    browser_version: str | None = None
    device: str | None = None


class CompatibilityModeCall(BaseModel):
    tool_key: str
    reason: str
    arguments: dict[str, Any] = Field(default_factory=dict)


class CompatibilityRunnerTask(BaseModel):
    task_id: str = Field(default_factory=lambda: new_id("compat_task"))
    environment_id: str
    case_ids: list[str] = Field(default_factory=list)
    runner_selector: RunnerSelector
    mode_calls: list[CompatibilityModeCall] = Field(default_factory=list)
    status: str = "ready_for_runner"
    skipped_reason: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class CompatibilityDispatchPlan(BaseModel):
    dispatch_id: str = Field(default_factory=lambda: new_id("dispatch"))
    plan_id: str
    plan_version: int = 1
    status: str = "ready_for_runner"
    tasks: list[CompatibilityRunnerTask] = Field(default_factory=list)
    skipped_environments: list[EnvironmentSpec] = Field(default_factory=list)
    total_case_runs: int = 0
    created_at: str = Field(default_factory=utc_now)
    notes: list[str] = Field(default_factory=list)


class ArtifactRef(BaseModel):
    artifact_id: str = Field(default_factory=lambda: new_id("artifact"))
    type: str
    uri: str
    mime_type: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class CaseRunResult(BaseModel):
    case_run_id: str = Field(default_factory=lambda: new_id("case_run"))
    case_id: str
    environment_id: str
    status: str = "pending"
    failure_type: str | None = None
    summary: str = ""
    artifacts: list[ArtifactRef] = Field(default_factory=list)


class EnvironmentRunResult(BaseModel):
    environment_run_id: str = Field(default_factory=lambda: new_id("env_run"))
    environment_id: str
    status: str = "pending"
    passed: int = 0
    failed: int = 0
    skipped: int = 0
    case_results: list[CaseRunResult] = Field(default_factory=list)
    artifacts: list[ArtifactRef] = Field(default_factory=list)


class CompatibilityRun(BaseModel):
    compatibility_run_id: str = Field(default_factory=lambda: new_id("compat_run"))
    session_id: str = ""
    phase: CompatibilityPhase = "intake"
    plan_id: str | None = None
    status: str = "draft"
    summary: str = ""
    environment_results: list[EnvironmentRunResult] = Field(default_factory=list)
    created_at: str = Field(default_factory=utc_now)
    updated_at: str = Field(default_factory=utc_now)
