"""Memory and observation persistence for Security Testing Mode."""
from __future__ import annotations

import json
import logging
from typing import Any
from uuid import uuid4

from src.modes.security_testing_mode.campaign_state import (
    FindingRecord,
    SecurityCampaign,
    SecurityTask,
)
from src.modes.security_testing_mode.contracts import TASK_FAILED
from src.runtime.execution_logging import truncate_text
from src.schemas.observation import ObservationRecord


logger = logging.getLogger("uvicorn.error.security_testing_mode.memory")


class SecurityMemoryService:
    """Build and persist compact observations from a security campaign."""

    async def persist_campaign_observations(
        self,
        *,
        campaign: SecurityCampaign,
        context: Any,
        memory_runtime_service: Any,
    ) -> list[str]:
        if memory_runtime_service is None:
            return []
        observations = self.build_campaign_observations(campaign, context)
        if not observations:
            return []
        return await memory_runtime_service.write_observations(observations)

    async def recall_successful_patterns(
        self,
        *,
        target_fingerprint: str,
        surface_types: list[str],
        context: Any,
        memory_runtime_service: Any,
        top_k: int = 8,
    ) -> list[dict[str, Any]]:
        """Recall successful profiles for the exact server-derived target fingerprint."""
        fingerprint = str(target_fingerprint or "").strip()
        if memory_runtime_service is None or not fingerprint:
            return []
        session_id = str(getattr(context, "session_id", "") or "") or None
        trace_id = str(getattr(context, "trace_id", "") or "")
        allowed_surfaces = {str(item).strip() for item in surface_types if str(item).strip()}
        try:
            result = await memory_runtime_service.retrieve_observation_context(
                session_id=session_id,
                trace_id=trace_id,
                query=(
                    "successful security tool execution profile for target fingerprint "
                    f"{fingerprint}"
                ),
                context={
                    "mode_key": "security_testing",
                    "security_memory_scope": "shared",
                    "allow_cross_session_memory": True,
                    "target_fingerprint": fingerprint,
                },
                top_k=max(1, min(int(top_k), 20)),
            )
        except Exception as exc:
            logger.warning(
                "security_memory_recall_failed target_fingerprint=%s error=%s",
                fingerprint,
                exc,
            )
            return []

        patterns: list[dict[str, Any]] = []
        seen_profiles: set[str] = set()
        for hit in getattr(result, "hits", []) or []:
            metadata = dict(getattr(hit, "metadata", {}) or {})
            tags = {str(item) for item in (getattr(hit, "tags", []) or [])}
            profile_key = str(metadata.get("profile_key") or "").strip()
            surface_type = str(metadata.get("surface_type") or "").strip()
            if not profile_key or profile_key in seen_profiles or "success" not in tags:
                continue
            if allowed_surfaces and surface_type and surface_type not in allowed_surfaces:
                continue
            seen_profiles.add(profile_key)
            patterns.append(
                {
                    "profile_key": profile_key,
                    "surface_type": surface_type,
                    "produced_finding": bool(metadata.get("produced_finding")),
                    "summary": str(getattr(hit, "summary", "") or ""),
                    "score": float(getattr(hit, "score", 0.0) or 0.0),
                    "source_session_id": str(getattr(hit, "session_id", "") or ""),
                }
            )
        patterns.sort(
            key=lambda item: (bool(item["produced_finding"]), float(item["score"])),
            reverse=True,
        )
        logger.info(
            "security_memory_recall_completed target_fingerprint=%s recalled_profiles=%s",
            fingerprint,
            [item["profile_key"] for item in patterns],
        )
        return patterns

    def build_campaign_observations(
        self,
        campaign: SecurityCampaign,
        context: Any,
    ) -> list[ObservationRecord]:
        session_id = str(getattr(context, "session_id", "") or "")
        turn_id = str(getattr(context, "turn_id", "") or "")
        trace_id = str(getattr(context, "trace_id", "") or "")
        observations = [
            self._campaign_observation(campaign, session_id, turn_id, trace_id),
        ]
        observations.extend(
            self._finding_observation(campaign, finding, session_id, turn_id, trace_id)
            for finding in campaign.findings[:20]
        )
        observations.extend(
            self._failed_task_observation(campaign, task, session_id, turn_id, trace_id)
            for task in campaign.tasks
            if task.status == TASK_FAILED
        )
        observations.extend(
            self._execution_observation(campaign, record, session_id, turn_id, trace_id)
            for record in campaign.execution_records[:20]
        )
        return observations

    def _campaign_observation(
        self,
        campaign: SecurityCampaign,
        session_id: str,
        turn_id: str,
        trace_id: str,
    ) -> ObservationRecord:
        completed = sum(1 for task in campaign.tasks if task.status == "completed")
        failed = sum(1 for task in campaign.tasks if task.status == "failed")
        title = f"Security campaign {campaign.campaign_id[:8] or 'summary'}"
        summary = (
            f"{len(campaign.tasks)} task(s), {completed} completed, {failed} failed, "
            f"{len(campaign.findings)} finding(s)."
        )
        content = {
            "campaign_id": campaign.campaign_id,
            "target_fingerprint": campaign.target_fingerprint,
            "objective": campaign.objective,
            "targets": [target.value for target in campaign.targets],
            "assets": len(campaign.assets),
            "services": len(campaign.fingerprints),
            "findings": len(campaign.findings),
            "evidence": len(campaign.evidence),
            "execution_records": len(campaign.execution_records),
            "risk_tolerance": campaign.risk_tolerance,
        }
        return self._observation(
            session_id=session_id,
            turn_id=turn_id,
            trace_id=trace_id,
            title=title,
            summary=summary,
            content=content,
            source=campaign.campaign_id,
            tags=["security", "security_testing", "campaign", "summary"],
        )

    def _finding_observation(
        self,
        campaign: SecurityCampaign,
        finding: FindingRecord,
        session_id: str,
        turn_id: str,
        trace_id: str,
    ) -> ObservationRecord:
        title = f"Security finding: {finding.title or finding.finding_id or 'untitled'}"
        content = {
            "campaign_id": campaign.campaign_id,
            "target_fingerprint": campaign.target_fingerprint,
            "finding_id": finding.finding_id,
            "title": finding.title,
            "severity": finding.severity,
            "category": finding.category,
            "affected_target": finding.affected_target,
            "affected_port": finding.affected_port,
            "affected_service": finding.affected_service,
            "description": finding.description,
            "evidence_summary": finding.evidence_summary,
            "recommendation": finding.recommendation,
            "source_task_ids": finding.source_task_ids,
        }
        return self._observation(
            session_id=session_id,
            turn_id=turn_id,
            trace_id=trace_id,
            title=title,
            summary=f"{finding.severity.upper()} {finding.category}: {finding.affected_target}",
            content=content,
            source=finding.affected_target or campaign.campaign_id,
            tags=[
                "security",
                "security_testing",
                "finding",
                f"severity:{finding.severity}",
                finding.category or "uncategorized",
            ],
        )

    def _failed_task_observation(
        self,
        campaign: SecurityCampaign,
        task: SecurityTask,
        session_id: str,
        turn_id: str,
        trace_id: str,
    ) -> ObservationRecord:
        content = {
            "campaign_id": campaign.campaign_id,
            "target_fingerprint": campaign.target_fingerprint,
            "task_id": task.task_id,
            "command_profile": task.command_profile,
            "target": task.target,
            "attempts": task.attempts,
            "last_error": task.last_error,
            "summary": task.result_summary,
        }
        return self._observation(
            session_id=session_id,
            turn_id=turn_id,
            trace_id=trace_id,
            title=f"Security task failed: {task.command_profile or task.task_id}",
            summary=truncate_text(task.last_error or task.result_summary or "Security task failed.", 180),
            content=content,
            source=task.target or campaign.campaign_id,
            tags=["security", "security_testing", "task_failure", task.command_profile or "unknown_profile"],
        )

    def _execution_observation(
        self,
        campaign: SecurityCampaign,
        record: Any,
        session_id: str,
        turn_id: str,
        trace_id: str,
    ) -> ObservationRecord:
        task = next((item for item in campaign.tasks if item.task_id == record.task_id), None)
        profile_key = str(task.command_profile if task is not None else record.tool_name or "")
        surface_type = str(task.surface_type if task is not None else "")
        produced_finding = any(record.task_id in finding.source_task_ids for finding in campaign.findings)
        content = {
            "campaign_id": campaign.campaign_id,
            "target_fingerprint": campaign.target_fingerprint,
            "record_id": record.record_id,
            "task_id": record.task_id,
            "tool_name": record.tool_name,
            "command": record.command,
            "exit_code": record.exit_code,
            "success": record.success,
            "error": record.error,
            "artifact_count": len(record.artifacts),
            "stdout_summary": record.stdout_summary,
            "stderr_summary": record.stderr_summary,
            "profile_key": profile_key,
            "surface_type": surface_type,
            "produced_finding": produced_finding,
        }
        status_tag = "success" if record.success else "failed"
        return self._observation(
            session_id=session_id,
            turn_id=turn_id,
            trace_id=trace_id,
            title=f"Security tool execution: {record.tool_name or record.task_id}",
            summary=truncate_text(record.stdout_summary or record.error or record.command, 180),
            content=content,
            source=record.artifacts[0] if record.artifacts else campaign.campaign_id,
            tags=["security", "security_testing", "tool_execution", status_tag, record.tool_name or "unknown_tool"],
            metadata={
                "profile_key": profile_key,
                "surface_type": surface_type,
                "produced_finding": produced_finding,
            },
        )

    def _observation(
        self,
        *,
        session_id: str,
        turn_id: str,
        trace_id: str,
        title: str,
        summary: str,
        content: dict[str, Any],
        source: str,
        tags: list[str],
        metadata: dict[str, Any] | None = None,
    ) -> ObservationRecord:
        return ObservationRecord(
            id=str(uuid4()),
            session_id=session_id,
            turn_id=turn_id,
            trace_id=trace_id,
            tool_key="security-scan-runner",
            status="completed",
            scope="artifact",
            category="tool_execution",
            title=truncate_text(title, 140),
            summary=truncate_text(summary, 180),
            content=truncate_text(json.dumps(content, ensure_ascii=False), 1800),
            source=source or None,
            tags=list(dict.fromkeys([item for item in tags if item])),
            metadata={
                "mode": "security_testing",
                "mode_key": "security_testing",
                "campaign_id": content.get("campaign_id"),
                "target_fingerprint": content.get("target_fingerprint"),
                "observation_kind": tags[2] if len(tags) > 2 else "security",
                **dict(metadata or {}),
            },
        )


__all__ = ["SecurityMemoryService"]
