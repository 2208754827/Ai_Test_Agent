"""Evidence-backed attack-chain planning and settlement."""
from __future__ import annotations

import hashlib
import json
import logging
from collections import defaultdict
from datetime import datetime, timezone
from typing import Iterable

from src.application.security.command_profiles import get_profile_registry
from src.application.security.risk_policy import SecurityRiskPolicy
from src.modes.security_testing_mode.agent import resolve_security_worker_agent
from src.modes.security_testing_mode.campaign_state import (
    FindingRecord,
    SecurityCampaign,
    SecurityTask,
    VerificationAttempt,
    VulnerabilityHypothesis,
)
from src.modes.security_testing_mode.contracts import (
    RISK_CRITICAL,
    RISK_HIGH,
    TASK_COMPLETED,
    TASK_FAILED,
    TASK_SKIPPED,
)


logger = logging.getLogger("uvicorn.error.security_testing_mode.attack_chain")

_TERMINAL_HYPOTHESIS_STATUSES = {"verified", "rejected", "blocked"}
_TERMINAL_ATTEMPT_STATUSES = {"succeeded", "failed", "blocked", "cancelled"}


class SecurityAttackChainService:
    """Turn evidence-backed findings into bounded verification work."""

    def __init__(self, *, risk_policy: SecurityRiskPolicy | None = None) -> None:
        self._risk_policy = risk_policy or SecurityRiskPolicy()
        self._profiles = get_profile_registry()

    def plan_next_attempts(
        self,
        campaign: SecurityCampaign,
        *,
        authorization_scope_hash: str = "",
        max_attempts: int = 30,
    ) -> list[SecurityTask]:
        """Create hypotheses and the smallest non-duplicative verification batch."""
        finding_by_id = {item.finding_id: item for item in campaign.findings}
        task_by_id = {item.task_id: item for item in campaign.tasks}
        hypothesis_by_finding = {
            item.finding_id: item for item in campaign.vulnerability_hypotheses
        }
        existing_attempt_tasks = {
            item.task_id for item in campaign.verification_attempts if item.task_id
        }

        candidates: list[tuple[VulnerabilityHypothesis, FindingRecord, SecurityTask]] = []
        for finding in campaign.findings:
            if finding.false_positive:
                continue
            source_task = self._source_task(finding, task_by_id)
            hypothesis = hypothesis_by_finding.get(finding.finding_id)
            if hypothesis is None:
                hypothesis = self._build_hypothesis(
                    finding,
                    authorization_scope_hash=authorization_scope_hash,
                    authorized_target=(source_task.target if source_task is not None else ""),
                )
                campaign.vulnerability_hypotheses.append(hypothesis)
                hypothesis_by_finding[finding.finding_id] = hypothesis
                self._log_event(
                    "security.hypothesis.created",
                    campaign=campaign,
                    hypothesis_id=hypothesis.hypothesis_id,
                    finding_id=finding.finding_id,
                    status=hypothesis.status,
                    target=hypothesis.target,
                )
            if hypothesis.status in _TERMINAL_HYPOTHESIS_STATUSES or hypothesis.attempt_ids:
                continue

            if not self._has_real_evidence(finding, source_task):
                self._block_hypothesis(
                    hypothesis,
                    "Finding has no traceable response evidence or completed source task.",
                )
                continue
            if source_task is None or not source_task.command_profile:
                self._block_hypothesis(
                    hypothesis,
                    "Finding has no registered source profile for a controlled replay.",
                )
                continue
            profile = self._profiles.get(source_task.command_profile)
            if profile is None:
                self._block_hypothesis(
                    hypothesis,
                    f"Source profile {source_task.command_profile!r} is not registered.",
                )
                continue
            candidates.append((hypothesis, finding, source_task))

        remaining_budget = max(0, int(max_attempts) - len(campaign.verification_attempts))
        if remaining_budget == 0:
            for hypothesis, _, _ in candidates:
                self._block_hypothesis(hypothesis, "Campaign verification-attempt budget is exhausted.")
            return []

        grouped: dict[tuple[str, str, str], list[tuple[VulnerabilityHypothesis, FindingRecord, SecurityTask]]] = defaultdict(list)
        for item in candidates:
            hypothesis, _, source_task = item
            # Parser output is produced inside Docker and may contain the
            # rewritten host.docker.internal address. That value is evidence,
            # not a new authorization target. Every replay inherits the exact
            # user-scoped target from its source task and lets the runner apply
            # the Docker rewrite again after target validation.
            target = source_task.target or hypothesis.target
            grouped[(source_task.task_id, source_task.command_profile, target)].append(item)

        verification_tasks: list[SecurityTask] = []
        for group_key in sorted(grouped):
            if len(verification_tasks) >= remaining_budget:
                for hypothesis, _, _ in grouped[group_key]:
                    self._block_hypothesis(
                        hypothesis,
                        "Campaign verification-attempt budget is exhausted.",
                    )
                continue
            source_task_id, profile_key, target = group_key
            task_id = self._verification_task_id(source_task_id, profile_key, target)
            if task_id in existing_attempt_tasks:
                continue
            group = grouped[group_key]
            profile = self._profiles.get(profile_key)
            if profile is None:
                continue
            finding_ids = [finding.finding_id for _, finding, _ in group]
            hypothesis_ids = [hypothesis.hypothesis_id for hypothesis, _, _ in group]
            approval_required = bool(
                self._risk_policy.requires_approval(profile_key)
                or any(finding.severity in {RISK_HIGH, RISK_CRITICAL} for _, finding, _ in group)
            )
            attempt_id = f"attempt_{self._stable_hash('|'.join(hypothesis_ids))}"
            attempt = VerificationAttempt(
                attempt_id=attempt_id,
                hypothesis_id=hypothesis_ids[0],
                hypothesis_ids=hypothesis_ids,
                finding_ids=finding_ids,
                task_id=task_id,
                profile_key=profile_key,
                target=target,
                approval_required=approval_required,
                approval_status="required" if approval_required else "not_required",
                result_class="detected",
            )
            campaign.verification_attempts.append(attempt)
            for hypothesis, _, _ in group:
                hypothesis.attempt_ids.append(attempt_id)
                hypothesis.proposed_profiles = self._unique(
                    [*hypothesis.proposed_profiles, profile_key]
                )
                hypothesis.approval_status = attempt.approval_status
                hypothesis.status = "proposed" if approval_required else "approved"
                hypothesis.updated_at = _utc_now()

            source_task = group[0][2]
            verification_tasks.append(
                SecurityTask(
                    task_id=task_id,
                    name=f"Verify {len(hypothesis_ids)} evidence-backed finding(s)",
                    description=(
                        f"Replay registered profile {profile_key} once to validate findings "
                        f"{', '.join(finding_ids)} without broadening scope or impact."
                    ),
                    surface_type=source_task.surface_type,
                    tool_family=source_task.tool_family,
                    command_profile=profile_key,
                    target=target,
                    target_port=source_task.target_port,
                    risk_level=profile.risk_level,
                    requires_approval=approval_required,
                    resource_locks=[f"verify:{target}:{profile_key}"],
                    timeout_seconds=profile.timeout_seconds,
                    max_retries=0,
                    refine_origin="attack_chain",
                    worker_agent_key=resolve_security_worker_agent(
                        surface_type=source_task.surface_type,
                        tool_family=source_task.tool_family,
                        command_profile=profile_key,
                    ),
                    finding_refs=finding_ids,
                    planning_rationale=(
                        "Evidence-backed verification replay using the same registered profile "
                        "that produced the source finding."
                    ),
                    scenario_fact_refs=list(source_task.scenario_fact_refs),
                    threat_hypothesis_ids=list(source_task.threat_hypothesis_ids),
                )
            )
        return verification_tasks

    def mark_attempts_running(
        self,
        campaign: SecurityCampaign,
        tasks: Iterable[SecurityTask],
    ) -> None:
        task_ids = {item.task_id for item in tasks}
        hypothesis_by_id = {
            item.hypothesis_id: item for item in campaign.vulnerability_hypotheses
        }
        for attempt in campaign.verification_attempts:
            if attempt.task_id not in task_ids or attempt.status != "planned":
                continue
            attempt.status = "running"
            attempt.started_at = _utc_now()
            for hypothesis_id in attempt.hypothesis_ids:
                hypothesis = hypothesis_by_id.get(hypothesis_id)
                if hypothesis is not None:
                    hypothesis.status = "running"
                    hypothesis.updated_at = attempt.started_at
            self._log_event(
                "security.attempt.started",
                campaign=campaign,
                attempt_id=attempt.attempt_id,
                task_id=attempt.task_id,
                hypothesis_ids=attempt.hypothesis_ids,
                profile_key=attempt.profile_key,
                target=attempt.target,
                approval_status=attempt.approval_status,
            )

    def settle_attempts(
        self,
        campaign: SecurityCampaign,
        tasks: Iterable[SecurityTask],
    ) -> None:
        task_by_id = {item.task_id: item for item in tasks}
        finding_by_id = {item.finding_id: item for item in campaign.findings}
        hypothesis_by_id = {
            item.hypothesis_id: item for item in campaign.vulnerability_hypotheses
        }
        execution_by_task = {
            item.task_id: item for item in campaign.execution_records
        }
        for attempt in campaign.verification_attempts:
            if attempt.status not in {"planned", "running"}:
                continue
            task = task_by_id.get(attempt.task_id)
            if task is None:
                continue
            execution = execution_by_task.get(task.task_id)
            evidence_ids = [
                item.artifact_id
                for item in campaign.evidence
                if item.source_task_id == task.task_id
            ]
            attempt.command = execution.command if execution is not None else task.command_profile
            attempt.exit_code = execution.exit_code if execution is not None else None
            attempt.stdout_summary = (
                execution.stdout_summary if execution is not None else task.raw_output
            )
            attempt.stderr_summary = (
                execution.stderr_summary if execution is not None else task.last_error
            )
            attempt.evidence_ids = self._unique([*attempt.evidence_ids, *evidence_ids])
            attempt.completed_at = task.completed_at or _utc_now()
            attempt.cleanup_status = (
                "completed"
                if execution is not None
                and bool(
                    execution.success
                    or execution.stdout_summary
                    or execution.stderr_summary
                    or execution.exit_code is not None
                )
                else "not_started"
            )

            if task.status == TASK_COMPLETED and evidence_ids:
                attempt.status = "succeeded"
                attempt.result_class = self._strongest_result_class(
                    finding_by_id.get(finding_id) for finding_id in attempt.finding_ids
                )
                for finding_id in attempt.finding_ids:
                    finding = finding_by_id.get(finding_id)
                    if finding is None:
                        continue
                    finding.evidence_ids = self._unique([*finding.evidence_ids, *evidence_ids])
                    if finding.verification_level == "observed":
                        finding.verification_level = "confirmed"
                    finding.verified = finding.verification_level in {
                        "exploitable",
                        "impact_verified",
                    }
                for hypothesis_id in attempt.hypothesis_ids:
                    hypothesis = hypothesis_by_id.get(hypothesis_id)
                    if hypothesis is None:
                        continue
                    hypothesis.status = "verified"
                    hypothesis.result_class = attempt.result_class
                    hypothesis.updated_at = attempt.completed_at
                event_type = "security.attempt.verified"
            else:
                attempt.failure_category = self._failure_category(task)
                blocked = attempt.failure_category in {
                    "approval_required",
                    "approval_or_policy",
                    "target_not_allowed",
                    "restricted_access",
                    "target_blocked",
                }
                attempt.status = "blocked" if blocked else "failed"
                attempt.result_class = "blocked_by_control" if blocked else "detected"
                attempt.next_route = self._next_route(attempt.failure_category)
                for hypothesis_id in attempt.hypothesis_ids:
                    hypothesis = hypothesis_by_id.get(hypothesis_id)
                    if hypothesis is None:
                        continue
                    hypothesis.status = "blocked"
                    hypothesis.result_class = attempt.result_class
                    hypothesis.failure_reason = task.last_error or task.result_summary
                    hypothesis.updated_at = attempt.completed_at
                event_type = "security.attempt.blocked" if blocked else "security.attempt.failed"
                if attempt.next_route:
                    self._log_event(
                        "security.attack_route_changed",
                        campaign=campaign,
                        attempt_id=attempt.attempt_id,
                        failure_category=attempt.failure_category,
                        next_route=attempt.next_route,
                    )
            self._log_event(
                event_type,
                campaign=campaign,
                attempt_id=attempt.attempt_id,
                task_id=attempt.task_id,
                status=attempt.status,
                result_class=attempt.result_class,
                evidence_ids=attempt.evidence_ids,
                cleanup_status=attempt.cleanup_status,
                failure_category=attempt.failure_category,
            )

    def all_chains_settled(self, campaign: SecurityCampaign) -> bool:
        return all(
            item.status in _TERMINAL_HYPOTHESIS_STATUSES
            for item in campaign.vulnerability_hypotheses
        ) and all(
            item.status in _TERMINAL_ATTEMPT_STATUSES
            for item in campaign.verification_attempts
        )

    def _build_hypothesis(
        self,
        finding: FindingRecord,
        *,
        authorization_scope_hash: str,
        authorized_target: str = "",
    ) -> VulnerabilityHypothesis:
        now = _utc_now()
        hypothesis_id = f"hyp_{self._stable_hash(finding.finding_id)}"
        return VulnerabilityHypothesis(
            hypothesis_id=hypothesis_id,
            finding_id=finding.finding_id,
            title=finding.title,
            target=authorized_target or finding.affected_target,
            attack_surface=finding.surface_type,
            preconditions=list(finding.reproduction_steps[:1]),
            expected_proof=[
                finding.evidence_summary or "Re-observe the finding with the registered source profile."
            ],
            risk_level=finding.severity,
            authorization_scope_hash=authorization_scope_hash,
            result_class=self._finding_result_class(finding),
            created_at=now,
            updated_at=now,
        )

    def _source_task(
        self,
        finding: FindingRecord,
        task_by_id: dict[str, SecurityTask],
    ) -> SecurityTask | None:
        for task_id in finding.source_task_ids:
            task = task_by_id.get(task_id)
            if task is not None and task.status == TASK_COMPLETED:
                return task
        return None

    def _has_real_evidence(
        self,
        finding: FindingRecord,
        source_task: SecurityTask | None,
    ) -> bool:
        return bool(
            finding.evidence_ids
            and source_task is not None
            and source_task.status == TASK_COMPLETED
            and (source_task.raw_output or source_task.parsed_result)
        )

    def _block_hypothesis(
        self,
        hypothesis: VulnerabilityHypothesis,
        reason: str,
    ) -> None:
        hypothesis.status = "blocked"
        hypothesis.failure_reason = reason
        hypothesis.updated_at = _utc_now()

    def _failure_category(self, task: SecurityTask) -> str:
        analysis = task.failure_analysis if isinstance(task.failure_analysis, dict) else {}
        category = str(analysis.get("failure_category") or "").strip().lower()
        if category:
            return category
        text = " ".join((task.last_error, task.result_summary)).lower()
        if "approval" in text or "policy" in text or "denied" in text:
            return "approval_or_policy"
        if "timeout" in text:
            return "execution_timeout"
        if task.status == TASK_SKIPPED:
            return "precondition_missing"
        return "execution_failed"

    def _next_route(self, category: str) -> str:
        return {
            "execution_timeout": "reduce_scope_or_manual_review",
            "profile_incompatible": "select_registered_alternative_profile",
            "tool_failure": "check_tool_readiness",
            "no_runner_output": "failure_analysis",
            "execution_failed": "failure_analysis",
        }.get(category, "")

    def _strongest_result_class(
        self,
        findings: Iterable[FindingRecord | None],
    ) -> str:
        classes = {
            self._finding_result_class(item)
            for item in findings
            if item is not None
        }
        for value in ("impact_verified", "verified_exploitable", "confirmed", "detected"):
            if value in classes:
                return value
        return "detected"

    def _finding_result_class(self, finding: FindingRecord) -> str:
        if finding.verification_level == "impact_verified":
            return "impact_verified"
        if finding.verification_level == "exploitable":
            return "verified_exploitable"
        if finding.verification_level == "confirmed":
            return "confirmed"
        return "detected"

    def _verification_task_id(self, source_task_id: str, profile_key: str, target: str) -> str:
        return f"verify_{self._stable_hash(f'{source_task_id}|{profile_key}|{target}')}"

    def _stable_hash(self, value: str) -> str:
        return hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]

    def _unique(self, values: Iterable[str]) -> list[str]:
        return list(dict.fromkeys(item for item in values if item))

    def _log_event(self, event_type: str, *, campaign: SecurityCampaign, **payload: object) -> None:
        logger.info(
            "%s %s",
            event_type,
            json.dumps(
                {"campaign_id": campaign.campaign_id, **payload},
                ensure_ascii=False,
                separators=(",", ":"),
                default=str,
            ),
        )


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


__all__ = ["SecurityAttackChainService"]
