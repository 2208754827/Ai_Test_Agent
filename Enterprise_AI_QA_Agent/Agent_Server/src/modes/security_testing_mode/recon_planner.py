"""Reconnaissance task planning for Security Testing Mode."""
from __future__ import annotations

from src.application.security.risk_policy import SecurityRiskPolicy
from src.application.security.tool_catalog import SecurityToolCatalog
from src.modes.security_testing_mode.agent import resolve_security_worker_agent
from src.modes.security_testing_mode.campaign_state import (
    SecurityTask,
    SecurityTestingRequestState,
    TargetCandidate,
)
from src.modes.security_testing_mode.contracts import FAMILY_GENERAL_SCAN


class SecurityReconPlanner:
    """Build Phase 1 recon and baseline scan tasks."""

    def __init__(
        self,
        *,
        tool_catalog: SecurityToolCatalog | None = None,
        risk_policy: SecurityRiskPolicy | None = None,
    ) -> None:
        self._tool_catalog = tool_catalog or SecurityToolCatalog()
        self._risk_policy = risk_policy or SecurityRiskPolicy()

    def build_campaign_tasks(
        self,
        targets: list[TargetCandidate],
        request: SecurityTestingRequestState,
        preferred_profile_keys: list[str] | None = None,
    ) -> list[SecurityTask]:
        tasks: list[SecurityTask] = []
        for target in targets:
            tasks.extend(
                self.build_tasks_for_target(
                    target,
                    request,
                    start_index=len(tasks) + 1,
                    preferred_profile_keys=preferred_profile_keys,
                )
            )
        return tasks

    def build_tasks_for_target(
        self,
        target: TargetCandidate,
        request: SecurityTestingRequestState,
        *,
        start_index: int = 1,
        preferred_profile_keys: list[str] | None = None,
    ) -> list[SecurityTask]:
        surface_type = self.surface_for_target(target)
        profile_keys = self.suggest_profile_keys(surface_type, target, request)
        recalled_profiles = self._compatible_recalled_profiles(
            preferred_profile_keys or [],
            surface_type,
            request,
        )
        profile_keys = list(dict.fromkeys([*recalled_profiles, *profile_keys]))
        tasks: list[SecurityTask] = []
        for offset, profile_key in enumerate(profile_keys):
            profile = self._tool_catalog.get_profile(profile_key)
            if profile is None:
                continue
            tool_family = profile.tool_family or FAMILY_GENERAL_SCAN
            task_index = start_index + offset
            tasks.append(
                SecurityTask(
                    task_id=f"sec_{task_index:02d}_{profile.profile_key}",
                    name=profile.description or profile.profile_key,
                    description=f"Run {profile.profile_key} against {target.value}.",
                    surface_type=surface_type,
                    tool_family=tool_family,
                    command_profile=profile.profile_key,
                    target=target.value,
                    target_port=target.port,
                    risk_level=profile.risk_level,
                    requires_approval=self._risk_policy.requires_approval(profile.profile_key),
                    resource_locks=[target.value],
                    timeout_seconds=profile.timeout_seconds,
                    max_retries=0 if profile.requires_approval else 1,
                    refine_origin="memory_recall" if profile_key in recalled_profiles else "",
                    worker_agent_key=resolve_security_worker_agent(
                        surface_type=surface_type,
                        tool_family=tool_family,
                        command_profile=profile.profile_key,
                    ),
                )
            )
        return tasks

    def _compatible_recalled_profiles(
        self,
        profile_keys: list[str],
        surface_type: str,
        request: SecurityTestingRequestState,
    ) -> list[str]:
        compatible: list[str] = []
        for profile_key in profile_keys:
            profile = self._tool_catalog.get_profile(profile_key)
            if profile is None or surface_type not in profile.surface_types:
                continue
            if request.risk_tolerance == "low" and profile.risk_level not in {"info", "low"}:
                continue
            compatible.append(profile.profile_key)
        return list(dict.fromkeys(compatible))

    def suggest_profile_keys(
        self,
        surface_type: str,
        target: TargetCandidate,
        request: SecurityTestingRequestState,
    ) -> list[str]:
        if surface_type in {"web", "api"}:
            profiles = ["httpx_probe", "whatweb_fingerprint", "http_headers_probe"]
            if request.risk_tolerance in {"medium", "high"}:
                profiles.append("nuclei_baseline")
            if target.protocol == "https":
                profiles.append("sslscan_tls_audit")
            return profiles
        if surface_type == "service":
            return ["sslscan_tls_audit"]
        return ["nmap_tcp_basic"]

    def surface_for_target(self, target: TargetCandidate) -> str:
        if target.target_type == "url":
            return "web"
        if target.target_type == "network":
            return "network"
        return "host"


__all__ = ["SecurityReconPlanner"]
