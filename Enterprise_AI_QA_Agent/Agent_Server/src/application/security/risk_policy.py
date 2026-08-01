"""Security Risk Policy.

Defines risk rules for security tool profiles and environments.
"""
from __future__ import annotations

from src.application.security.command_profiles import get_profile_registry

# Profiles that always require approval regardless of environment
ALWAYS_REQUIRE_APPROVAL: frozenset[str] = frozenset({
    "hydra_basic_login",
    "nmap_full_scan",
    "sqlmap_readonly_probe",
    "tcpdump_timed_capture",
    "searchsploit_exploit_lookup",
    "msf_module_info",
    "free_command",
})

# Max concurrent workers per profile risk level
RISK_PARALLELISM: dict[str, int] = {
    "info": 5,
    "low": 3,
    "medium": 2,
    "high": 1,
    "critical": 1,
}

# Profiles blocked in production environments
BLOCKED_IN_PRODUCTION: frozenset[str] = frozenset({
    "hydra_basic_login",
    "nmap_full_scan",
    "sqlmap_readonly_probe",
    "nuclei_cve_scan",
    "tcpdump_timed_capture",
    "msf_module_info",
    "free_command",
})


class SecurityRiskPolicy:
    """Evaluate risk rules for security tool execution."""

    def requires_approval(self, profile_key: str) -> bool:
        if profile_key in ALWAYS_REQUIRE_APPROVAL:
            return True
        profile = get_profile_registry().get(profile_key)
        if profile is None:
            return True  # Unknown profiles require approval
        return profile.requires_approval

    def is_allowed_in_environment(self, profile_key: str, env: str) -> bool:
        """Check if a profile is allowed in the given environment."""
        if env == "production" and profile_key in BLOCKED_IN_PRODUCTION:
            return False
        return True

    def max_parallelism_for_profile(self, profile_key: str) -> int:
        profile = get_profile_registry().get(profile_key)
        if profile is None:
            return 1
        return RISK_PARALLELISM.get(profile.risk_level, 1)

    def get_risk_level(self, profile_key: str) -> str:
        profile = get_profile_registry().get(profile_key)
        if profile is None:
            return "high"
        return profile.risk_level


__all__ = ["SecurityRiskPolicy"]
