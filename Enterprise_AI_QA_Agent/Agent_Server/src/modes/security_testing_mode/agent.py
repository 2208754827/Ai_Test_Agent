"""Security Testing Mode agent key constants."""
from __future__ import annotations


# Primary orchestrator
SECURITY_TESTING_AGENT_KEY = "security-testing-agent"

# Specialist workers
SECURITY_DOC_ANALYST_KEY = "security-doc-analyst"
ATTACK_SURFACE_PLANNER_KEY = "attack-surface-planner"
SECURITY_RECON_WORKER_KEY = "security-recon-worker"
SECURITY_AUTH_WORKER_KEY = "security-auth-worker"
SECURITY_WEB_VERIFIER_KEY = "security-web-verifier"
SECURITY_API_VERIFIER_KEY = "security-api-verifier"
SECURITY_HOST_VERIFIER_KEY = "security-host-verifier"
SECURITY_EXPLOIT_CODER_KEY = "security-exploit-coder"
SECURITY_FAILURE_ANALYST_KEY = "security-failure-analyst"

# Surface type to worker mapping
SURFACE_WORKER_MAP: dict[str, str] = {
    "network": SECURITY_RECON_WORKER_KEY,
    "host": SECURITY_HOST_VERIFIER_KEY,
    "web": SECURITY_WEB_VERIFIER_KEY,
    "api": SECURITY_API_VERIFIER_KEY,
    "credential": SECURITY_AUTH_WORKER_KEY,
    "service": SECURITY_HOST_VERIFIER_KEY,
    "url": SECURITY_WEB_VERIFIER_KEY,
}

PROFILE_WORKER_MAP: dict[str, str] = {
    "nmap_tcp_basic": SECURITY_RECON_WORKER_KEY,
    "nmap_service_detect": SECURITY_RECON_WORKER_KEY,
    "nmap_full_scan": SECURITY_RECON_WORKER_KEY,
    "nmap_os_detect": SECURITY_RECON_WORKER_KEY,
    # These profiles execute through web/service runner families. Route them
    # to agents that explicitly support those runner tools; otherwise the
    # generic tool exposure policy correctly hides the assigned runner and the
    # worker can never satisfy its execution contract.
    "httpx_probe": SECURITY_WEB_VERIFIER_KEY,
    "whatweb_fingerprint": SECURITY_WEB_VERIFIER_KEY,
    "sslscan_tls_audit": SECURITY_HOST_VERIFIER_KEY,
    "http_headers_probe": SECURITY_WEB_VERIFIER_KEY,
    "ffuf_common_dirs": SECURITY_WEB_VERIFIER_KEY,
    "gobuster_dirs": SECURITY_WEB_VERIFIER_KEY,
    "nikto_web_scan": SECURITY_WEB_VERIFIER_KEY,
    "nuclei_baseline": SECURITY_WEB_VERIFIER_KEY,
    "nuclei_cve_scan": SECURITY_WEB_VERIFIER_KEY,
    "sqlmap_readonly_probe": SECURITY_WEB_VERIFIER_KEY,
    "hydra_basic_login": SECURITY_AUTH_WORKER_KEY,
    "searchsploit_lookup": SECURITY_HOST_VERIFIER_KEY,
}

TOOL_FAMILY_WORKER_MAP: dict[str, str] = {
    "network_recon": SECURITY_RECON_WORKER_KEY,
    "web_scan": SECURITY_WEB_VERIFIER_KEY,
    "credential_attack": SECURITY_AUTH_WORKER_KEY,
    "service_audit": SECURITY_HOST_VERIFIER_KEY,
    "exploit_workbench": SECURITY_EXPLOIT_CODER_KEY,
    "traffic_analysis": SECURITY_HOST_VERIFIER_KEY,
}


def resolve_security_worker_agent(
    *,
    surface_type: str = "",
    tool_family: str = "",
    command_profile: str = "",
) -> str:
    normalized_surface = (surface_type or "").strip().lower()
    normalized_family = (tool_family or "").strip().lower()
    normalized_profile = (command_profile or "").strip().lower()

    if normalized_profile == "campaign_failure":
        return SECURITY_FAILURE_ANALYST_KEY

    if normalized_surface == "api":
        if normalized_profile == "hydra_basic_login":
            return SECURITY_AUTH_WORKER_KEY
        return SECURITY_API_VERIFIER_KEY

    if normalized_profile in PROFILE_WORKER_MAP:
        return PROFILE_WORKER_MAP[normalized_profile]

    if normalized_family in TOOL_FAMILY_WORKER_MAP:
        return TOOL_FAMILY_WORKER_MAP[normalized_family]

    return SURFACE_WORKER_MAP.get(normalized_surface, SECURITY_RECON_WORKER_KEY)


__all__ = [
    "SECURITY_TESTING_AGENT_KEY",
    "SECURITY_DOC_ANALYST_KEY",
    "ATTACK_SURFACE_PLANNER_KEY",
    "SECURITY_RECON_WORKER_KEY",
    "SECURITY_AUTH_WORKER_KEY",
    "SECURITY_WEB_VERIFIER_KEY",
    "SECURITY_API_VERIFIER_KEY",
    "SECURITY_HOST_VERIFIER_KEY",
    "SECURITY_EXPLOIT_CODER_KEY",
    "SECURITY_FAILURE_ANALYST_KEY",
    "PROFILE_WORKER_MAP",
    "SURFACE_WORKER_MAP",
    "TOOL_FAMILY_WORKER_MAP",
    "resolve_security_worker_agent",
]
