"""Asset discovery and enrichment for Security Testing Mode."""
from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from src.modes.security_testing_mode.campaign_state import (
    AgentActivityRecord,
    AssetNode,
    FindingRecord,
    NetworkServiceFingerprint,
    SecurityCampaign,
    SecurityTask,
    SecurityTestingRequestState,
    TargetCandidate,
)
from src.modes.security_testing_mode.agent import resolve_security_worker_agent
from src.modes.security_testing_mode.contracts import TASK_COMPLETED, TASK_FAILED, TASK_SKIPPED


class SecurityAssetDiscoveryService:
    """Create seed assets and merge parser output back into campaign state."""

    def seed_assets(
        self,
        targets: list[TargetCandidate],
        request: SecurityTestingRequestState,
    ) -> list[AssetNode]:
        assets: list[AssetNode] = []
        for target in targets:
            asset_type = "web_app" if target.target_type == "url" else "host"
            assets.append(
                AssetNode(
                    asset_id=f"asset_{len(assets) + 1}",
                    asset_type=asset_type,
                    address=target.value,
                    hostname=target.resolved_domain or target.value,
                    port=target.port,
                    protocol=target.protocol,
                    service_name="http" if target.protocol in {"http", "https"} else "",
                    confidence=0.9,
                    notes=f"Seed asset from resolved request target. Scope={request.scope_preference or 'limited'}.",
                )
            )
        return assets

    def hydrate_campaign_from_task_results(
        self,
        campaign: SecurityCampaign,
        *,
        profile_lookup: Any,
        finding_normalizer: Any,
        severity_evaluator: Any,
    ) -> None:
        findings: list[FindingRecord] = []
        fingerprints: list[NetworkServiceFingerprint] = list(campaign.fingerprints or [])
        assets: list[AssetNode] = list(campaign.assets or [])

        if not campaign.activities:
            campaign.activities = self.activities_from_tasks(campaign.tasks)

        for task in campaign.tasks:
            parsed = task.parsed_result or {}
            profile = profile_lookup(task.command_profile)
            parser_key = profile.parser_key if profile is not None else ""
            if parser_key:
                task_findings = finding_normalizer.normalize_batch(parser_key, parsed, task.task_id)
                # Backfill affected_target: parsers do not always extract the
                # URL/host from their output (e.g. http_headers parser may emit
                # missing-header findings without a `url` field if the runner
                # output omitted it). Use the task's known target as a
                # deterministic fallback so the report never shows
                # ``affected_target=unknown``.
                for finding in task_findings:
                    if not str(finding.affected_target or "").strip():
                        finding.affected_target = task.target
                    evidence_ids = [
                        item.artifact_id
                        for item in campaign.evidence
                        if item.source_task_id == task.task_id
                    ]
                    finding.evidence_ids = evidence_ids
                findings.extend(task_findings)
            if parser_key == "nmap":
                self.append_nmap_assets(parsed, task, fingerprints, assets)
            if parser_key in {"httpx", "whatweb"}:
                self.append_web_assets(parsed, task, assets)

        campaign.findings = self.dedupe_findings(severity_evaluator.evaluate_batch(findings))
        campaign.fingerprints = fingerprints
        campaign.assets = self.dedupe_assets(assets)

    def activities_from_tasks(self, tasks: list[SecurityTask]) -> list[AgentActivityRecord]:
        return [
            AgentActivityRecord(
                activity_id=f"act_{task.task_id}",
                agent_key=task.worker_agent_key or resolve_security_worker_agent(
                    surface_type=task.surface_type,
                    tool_family=task.tool_family,
                    command_profile=task.command_profile,
                ),
                agent_name=task.worker_agent_key or resolve_security_worker_agent(
                    surface_type=task.surface_type,
                    tool_family=task.tool_family,
                    command_profile=task.command_profile,
                ),
                task_id=task.task_id,
                action="completed" if task.status == TASK_COMPLETED else "failed" if task.status == TASK_FAILED else task.status,
                summary=task.result_summary or task.last_error,
                started_at=task.started_at,
                completed_at=task.completed_at,
                execution_mode=task.worker_execution_mode,
                tool_calls=[task.command_profile] if task.command_profile else [],
            )
            for task in tasks
            if task.status in {TASK_COMPLETED, TASK_FAILED, TASK_SKIPPED}
        ]

    def append_nmap_assets(
        self,
        parsed: dict[str, Any],
        task: SecurityTask,
        fingerprints: list[NetworkServiceFingerprint],
        assets: list[AssetNode],
    ) -> None:
        for port_info in parsed.get("open_ports", []):
            if not isinstance(port_info, dict):
                continue
            host = str(port_info.get("host") or task.target)
            port = int(port_info.get("port") or 0)
            service = str(port_info.get("service") or "")
            fingerprints.append(
                NetworkServiceFingerprint(
                    host=host,
                    port=port,
                    protocol=str(port_info.get("protocol") or "tcp"),
                    service_name=service,
                    service_version=str(port_info.get("version") or ""),
                    state=str(port_info.get("state") or "open"),
                )
            )
            assets.append(
                AssetNode(
                    asset_id=f"asset_{host}_{port}",
                    asset_type="service",
                    address=host,
                    port=port,
                    protocol=str(port_info.get("protocol") or "tcp"),
                    service_name=service,
                    service_version=str(port_info.get("version") or ""),
                    discovered_by=task.task_id,
                )
            )

    def append_web_assets(
        self,
        parsed: dict[str, Any],
        task: SecurityTask,
        assets: list[AssetNode],
    ) -> None:
        for item in parsed.get("results", []):
            if not isinstance(item, dict):
                continue
            url = str(item.get("url") or "")
            if not url:
                continue
            parsed_url = urlparse(url)
            assets.append(
                AssetNode(
                    asset_id=f"asset_web_{len(assets) + 1}",
                    asset_type="web_app",
                    address=url,
                    hostname=parsed_url.hostname or "",
                    port=parsed_url.port,
                    protocol=parsed_url.scheme,
                    technologies=[
                        str(tech)
                        for tech in (item.get("technologies") or [])
                        if str(tech).strip()
                    ],
                    discovered_by=task.task_id,
                )
            )

    def dedupe_findings(self, findings: list[FindingRecord]) -> list[FindingRecord]:
        seen: set[tuple[str, str, int | None]] = set()
        deduped: list[FindingRecord] = []
        for finding in findings:
            key = (finding.title, finding.affected_target, finding.affected_port)
            if key in seen:
                continue
            seen.add(key)
            deduped.append(finding)
        return deduped

    def dedupe_assets(self, assets: list[AssetNode]) -> list[AssetNode]:
        seen: set[tuple[str, int | None, str]] = set()
        deduped: list[AssetNode] = []
        for asset in assets:
            key = (asset.address, asset.port, asset.asset_type)
            if key in seen:
                continue
            seen.add(key)
            deduped.append(asset)
        return deduped


__all__ = ["SecurityAssetDiscoveryService"]
