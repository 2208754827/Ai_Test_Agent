"""Deterministic, evidence-backed scenario replanning between task batches."""
from __future__ import annotations

import hashlib
from typing import Any

from src.application.security.execution_monitor import SecurityExecutionMonitor
from src.application.security.risk_policy import SecurityRiskPolicy
from src.application.security.tool_catalog import SecurityToolCatalog
from src.modes.security_testing_mode.agent import resolve_security_worker_agent
from src.modes.security_testing_mode.campaign_state import (
    SecurityCampaign,
    SecurityScenarioProfile,
    SecurityTask,
    SecurityTestingRequestState,
    ThreatHypothesis,
)
from src.modes.security_testing_mode.contracts import (
    TASK_BLOCKED,
    TASK_PENDING,
    TASK_READY,
)
from src.modes.security_testing_mode.recon_planner import SecurityReconPlanner
from src.modes.security_testing_mode.scenario_analysis_service import (
    SecurityScenarioAnalysisService,
)
from src.modes.security_testing_mode.task_pool import SecurityTaskPool


class SecurityScenarioIncrementalPlanner:
    """Synchronize *future* tasks when new observed scenario facts arrive.

    The service intentionally has no free-form command generation path.  It
    recomputes the scenario from campaign evidence, then reconciles only the
    registered low/medium-risk profiles selected by ``SecurityReconPlanner``.
    Running and settled tasks remain immutable evidence.
    """

    _FUTURE_STATUSES = frozenset({TASK_PENDING, TASK_READY, TASK_BLOCKED})

    def __init__(
        self,
        *,
        scenario_analysis: SecurityScenarioAnalysisService | None = None,
        recon_planner: SecurityReconPlanner | None = None,
        tool_catalog: SecurityToolCatalog | None = None,
        risk_policy: SecurityRiskPolicy | None = None,
        execution_monitor: SecurityExecutionMonitor | None = None,
    ) -> None:
        self._scenario_analysis = scenario_analysis or SecurityScenarioAnalysisService()
        self._tool_catalog = tool_catalog or SecurityToolCatalog()
        self._risk_policy = risk_policy or SecurityRiskPolicy()
        self._recon_planner = recon_planner or SecurityReconPlanner(
            tool_catalog=self._tool_catalog,
            risk_policy=self._risk_policy,
        )
        self._execution_monitor = execution_monitor or SecurityExecutionMonitor()

    def replan(
        self,
        *,
        campaign: SecurityCampaign,
        request: SecurityTestingRequestState,
        pool: SecurityTaskPool,
        refinement_id: str,
    ) -> dict[str, Any]:
        """Apply one deterministic scenario reconciliation pass.

        Returns empty mutation lists when there is no new observed evidence.
        ``campaign.scenario_profile`` and ``campaign.threat_hypotheses`` are
        changed together only after the evidence delta is established.
        """
        previous = campaign.scenario_profile
        if previous is None or not campaign.targets:
            return self._empty_result(refinement_id)

        refreshed, refreshed_threats = self._scenario_analysis.analyze(
            request=request,
            targets=campaign.targets,
            assets=campaign.assets,
        )
        fact_delta = self._observed_fact_delta(previous, refreshed)
        semantic_changes = self._semantic_changes(previous, refreshed)
        if not fact_delta:
            return self._empty_result(refinement_id)

        campaign.scenario_profile = refreshed
        campaign.threat_hypotheses = refreshed_threats
        planned = self._planned_future_tasks(
            campaign=campaign,
            request=request,
            profile=refreshed,
            threats=refreshed_threats,
        )
        desired_by_signature = {self._signature(task): task for task in planned}
        for task in pool.all_tasks:
            desired_by_signature.pop(self._signature(task), None)

        removed: list[SecurityTask] = []
        updated: list[SecurityTask] = []
        for task in list(pool.all_tasks):
            if task.status not in self._FUTURE_STATUSES or not self._is_scenario_managed(task):
                continue
            desired = next(
                (
                    candidate
                    for candidate in planned
                    if self._signature(candidate) == self._signature(task)
                ),
                None,
            )
            if desired is None:
                removed_task = pool.remove_task(
                    task.task_id,
                    reason=(
                        f"Scenario replan {refinement_id} removed profile {task.command_profile}: "
                        "the profile is not applicable to the newly observed scenario."
                    ),
                )
                if removed_task is not None:
                    removed.append(removed_task)
                continue
            if self._sync_future_task(task, desired, refinement_id):
                updated.append(task)

        added: list[SecurityTask] = []
        for desired in desired_by_signature.values():
            candidate = self._new_task_for_replan(
                desired=desired,
                pool=pool,
                refinement_id=refinement_id,
            )
            if pool.add_task(candidate):
                added.append(candidate)

        audit = {
            "refinement_id": refinement_id,
            "previous_scenario_id": previous.scenario_id,
            "scenario_id": refreshed.scenario_id,
            "previous_product_type": previous.product_type,
            "product_type": refreshed.product_type,
            "new_observed_facts": fact_delta,
            "changed_dimensions": semantic_changes,
            "added_task_ids": [task.task_id for task in added],
            "removed_task_ids": [task.task_id for task in removed],
            "updated_task_ids": [task.task_id for task in updated],
            "immutable_task_ids": [
                task.task_id
                for task in pool.all_tasks
                if task.status not in self._FUTURE_STATUSES
            ],
        }
        self._append_audit(campaign, audit)
        return {
            **audit,
            "added_tasks": added,
            "removed_tasks": removed,
            "updated_tasks": updated,
            "replanned": True,
        }

    def _planned_future_tasks(
        self,
        *,
        campaign: SecurityCampaign,
        request: SecurityTestingRequestState,
        profile: SecurityScenarioProfile,
        threats: list[ThreatHypothesis],
    ) -> list[SecurityTask]:
        planned = self._recon_planner.build_campaign_tasks(
            campaign.targets,
            request,
            scenario_profile=profile,
            threat_hypotheses=threats,
        )
        return [
            task
            for task in planned
            if self._profile_is_permitted(task, request)
        ]

    def _profile_is_permitted(
        self,
        task: SecurityTask,
        request: SecurityTestingRequestState,
    ) -> bool:
        profile = self._tool_catalog.get_profile(task.command_profile)
        if profile is None:
            return False
        allowed, _ = self._execution_monitor.profile_allowed_for_risk(
            profile.profile_key,
            request.risk_tolerance,
        )
        return allowed

    def _sync_future_task(
        self,
        task: SecurityTask,
        desired: SecurityTask,
        refinement_id: str,
    ) -> bool:
        before = (
            task.planning_rationale,
            tuple(task.scenario_fact_refs),
            tuple(task.threat_hypothesis_ids),
            task.surface_type,
        )
        task.surface_type = desired.surface_type
        task.tool_family = desired.tool_family
        task.risk_level = desired.risk_level
        task.requires_approval = desired.requires_approval
        task.timeout_seconds = desired.timeout_seconds
        task.max_retries = desired.max_retries
        task.worker_agent_key = desired.worker_agent_key
        task.planning_rationale = desired.planning_rationale
        task.scenario_fact_refs = list(desired.scenario_fact_refs)
        task.threat_hypothesis_ids = list(desired.threat_hypothesis_ids)
        after = (
            task.planning_rationale,
            tuple(task.scenario_fact_refs),
            tuple(task.threat_hypothesis_ids),
            task.surface_type,
        )
        if before == after:
            return False
        task.observations.append(
            f"Scenario replan {refinement_id} refreshed this future task from observed evidence."
        )
        return True

    def _new_task_for_replan(
        self,
        *,
        desired: SecurityTask,
        pool: SecurityTaskPool,
        refinement_id: str,
    ) -> SecurityTask:
        stable = hashlib.sha1(
            f"{refinement_id}|{desired.command_profile}|{desired.target}|{desired.target_port}".encode(
                "utf-8"
            )
        ).hexdigest()[:12]
        candidate = desired.model_copy(deep=True)
        candidate.task_id = f"scenario_refine_{stable}"
        candidate.status = TASK_PENDING
        candidate.refine_origin = f"scenario_replan:{refinement_id}"
        candidate.depends_on = []
        candidate.worker_agent_key = candidate.worker_agent_key or resolve_security_worker_agent(
            surface_type=candidate.surface_type,
            tool_family=candidate.tool_family,
            command_profile=candidate.command_profile,
        )
        while pool.get(candidate.task_id) is not None:
            candidate.task_id = f"{candidate.task_id}_x"
        return candidate

    def _observed_fact_delta(
        self,
        previous: SecurityScenarioProfile,
        refreshed: SecurityScenarioProfile,
    ) -> list[str]:
        previous_statements = {
            self._normalized_fact(fact.statement)
            for fact in previous.facts
            if fact.source_type == "observed"
        }
        return [
            fact.statement
            for fact in refreshed.facts
            if fact.source_type == "observed"
            and self._normalized_fact(fact.statement) not in previous_statements
        ]

    def _semantic_changes(
        self,
        previous: SecurityScenarioProfile,
        refreshed: SecurityScenarioProfile,
    ) -> list[str]:
        fields = (
            "product_type",
            "technologies",
            "auth_flows",
            "entry_points",
            "trust_boundaries",
            "roles",
        )
        return [
            field
            for field in fields
            if getattr(previous, field) != getattr(refreshed, field)
        ]

    def _append_audit(self, campaign: SecurityCampaign, audit: dict[str, Any]) -> None:
        if not any(
            str(item.get("refinement_id") or "") == str(audit.get("refinement_id") or "")
            for item in campaign.scenario_replan_audit
            if isinstance(item, dict)
        ):
            campaign.scenario_replan_audit.append(dict(audit))

    def _empty_result(self, refinement_id: str) -> dict[str, Any]:
        return {
            "refinement_id": refinement_id,
            "added_tasks": [],
            "removed_tasks": [],
            "updated_tasks": [],
            "new_observed_facts": [],
            "changed_dimensions": [],
            "replanned": False,
        }

    def _signature(self, task: SecurityTask) -> tuple[str, str, int | None]:
        return (task.command_profile, task.target, task.target_port)

    def _is_scenario_managed(self, task: SecurityTask) -> bool:
        origin = str(task.refine_origin or "")
        return not origin or origin == "memory_recall" or origin.startswith("scenario_replan:")

    def _normalized_fact(self, statement: str) -> str:
        return " ".join(str(statement or "").strip().casefold().split())


__all__ = ["SecurityScenarioIncrementalPlanner"]
