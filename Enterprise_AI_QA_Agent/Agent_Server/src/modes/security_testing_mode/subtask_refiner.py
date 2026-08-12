"""PentAGI-style subtask refinement for Security Testing Mode."""
from __future__ import annotations

import hashlib
from typing import Any

from src.modes.security_testing_mode.campaign_state import (
    SecurityCampaign,
    SecuritySubtask,
    SecurityTask,
    SecurityTestingRequestState,
)
from src.modes.security_testing_mode.contracts import (
    MAX_CAMPAIGN_TASKS,
    TASK_COMPLETED,
    TASK_FAILED,
    TASK_PENDING,
    TASK_READY,
    TASK_BLOCKED,
)
from src.modes.security_testing_mode.agent import resolve_security_worker_agent
from src.modes.security_testing_mode.subtask_generator import SecuritySubtaskGenerator
from src.modes.security_testing_mode.task_pool import SecurityTaskPool


class SecuritySubtaskRefiner:
    """Update subtasks with execution outcomes and safe stop decisions."""

    def __init__(self) -> None:
        self._generator = SecuritySubtaskGenerator()

    def refine_after_execution(self, campaign: SecurityCampaign) -> tuple[list[SecuritySubtask], list[str]]:
        """Return updated subtasks plus human-readable refinement notes."""
        subtasks = list(campaign.subtasks)
        if not subtasks and campaign.tasks:
            subtasks = self._generator.generate(
                campaign,
                request=SecurityTestingRequestState(risk_tolerance=campaign.risk_tolerance),
            )

        task_by_id = {task.task_id: task for task in campaign.tasks}
        notes: list[str] = []
        refined: list[SecuritySubtask] = []
        for subtask in subtasks:
            task = task_by_id.get(subtask.task_id)
            if task is None:
                refined.append(subtask)
                continue

            subtask.status = task.status
            subtask.result_summary = task.result_summary
            if task.worker_agent_key and not subtask.worker_agent_key:
                subtask.worker_agent_key = task.worker_agent_key
            if task.tool_family and not subtask.tool_family:
                subtask.tool_family = task.tool_family
            if task.target and not subtask.target:
                subtask.target = task.target

            if task.status == TASK_FAILED:
                category = self._classify_failure(task.last_error or task.result_summary)
                subtask.failure_category = category
                self._append_unique(
                    subtask.notes,
                    f"Execution failed and was classified as {category}.",
                )
                self._append_unique(
                    subtask.stop_conditions,
                    self._stop_condition_for_category(category),
                )
                notes.append(
                    f"Subtask {subtask.subtask_id} failed as {category}; record it as a limitation instead of escalating tools."
                )
            elif task.result_summary:
                self._append_unique(subtask.notes, task.result_summary)

            refined.append(subtask)
        return refined, notes

    def refine_task_pool(
        self,
        *,
        pool: SecurityTaskPool,
        settled_tasks: list[SecurityTask],
        refinement_id: str,
        max_tasks: int = MAX_CAMPAIGN_TASKS,
    ) -> dict[str, Any]:
        """Apply deterministic, evidence-backed changes between execution batches."""
        removed = self._remove_duplicate_future_tasks(pool)
        added: list[SecurityTask] = []
        for task in settled_tasks:
            if task.status != TASK_COMPLETED:
                continue
            for candidate in self._tasks_from_open_ports(task, refinement_id):
                if pool.task_count >= max(1, int(max_tasks)):
                    break
                if self._has_equivalent_task(pool, candidate):
                    continue
                if pool.add_task(candidate):
                    added.append(candidate)
        return {
            "refinement_id": refinement_id,
            "added_tasks": added,
            "removed_tasks": removed,
            "task_count": pool.task_count,
        }

    def _tasks_from_open_ports(self, task: SecurityTask, refinement_id: str) -> list[SecurityTask]:
        parsed = task.parsed_result if isinstance(task.parsed_result, dict) else {}
        open_ports = parsed.get("open_ports")
        if not isinstance(open_ports, list):
            return []
        tasks: list[SecurityTask] = []
        for item in open_ports:
            if not isinstance(item, dict) or str(item.get("state") or "open") != "open":
                continue
            try:
                port = int(item.get("port") or 0)
            except (TypeError, ValueError):
                continue
            if port <= 0 or port > 65535:
                continue
            host = str(item.get("host") or task.target or "").strip()
            if not host:
                continue
            service = str(item.get("service") or "unknown").strip()
            stable = hashlib.sha1(f"{host}:{port}:nmap_service_detect".encode("utf-8")).hexdigest()[:10]
            tasks.append(
                SecurityTask(
                    task_id=f"refine_{stable}",
                    name=f"Refined service detection for {host}:{port}",
                    description=(
                        f"Open port {port}/tcp ({service}) was discovered by {task.task_id}; "
                        "run version detection before any vulnerability-specific work."
                    ),
                    surface_type="service",
                    tool_family="network_recon",
                    command_profile="nmap_service_detect",
                    target=host,
                    target_port=port,
                    depends_on=[task.task_id],
                    risk_level="low",
                    requires_approval=False,
                    resource_locks=[f"{host}:{port}"],
                    timeout_seconds=180,
                    max_retries=1,
                    refine_origin=refinement_id,
                    worker_agent_key=resolve_security_worker_agent(
                        surface_type="service",
                        tool_family="network_recon",
                        command_profile="nmap_service_detect",
                    ),
                )
            )
        return tasks

    def _remove_duplicate_future_tasks(self, pool: SecurityTaskPool) -> list[SecurityTask]:
        seen: set[tuple[str, str, int | None]] = set()
        removed: list[SecurityTask] = []
        future_states = {TASK_PENDING, TASK_READY, TASK_BLOCKED}
        for task in pool.all_tasks:
            signature = (task.command_profile, task.target, task.target_port)
            if signature not in seen:
                seen.add(signature)
                continue
            if task.status not in future_states:
                continue
            duplicate = pool.remove_task(
                task.task_id,
                reason=f"Refiner removed duplicate of {signature[0]} for {signature[1]}.",
            )
            if duplicate is not None:
                removed.append(duplicate)
        return removed

    def _has_equivalent_task(self, pool: SecurityTaskPool, candidate: SecurityTask) -> bool:
        return any(
            task.command_profile == candidate.command_profile
            and task.target == candidate.target
            and task.target_port == candidate.target_port
            for task in pool.all_tasks
        )

    def _classify_failure(self, message: str) -> str:
        normalized = message.lower()
        if "timeout" in normalized or "timed out" in normalized:
            return "timeout"
        if "exit_code=2" in normalized or "exit code 2" in normalized:
            return "profile_compatibility"
        if "exit_code=1" in normalized or "exit code 1" in normalized:
            return "tool_execution"
        if "approval" in normalized or "denied" in normalized:
            return "approval_or_policy"
        if "not configured" in normalized or "not installed" in normalized or "not found" in normalized:
            return "environment"
        return "execution"

    def _stop_condition_for_category(self, category: str) -> str:
        if category == "timeout":
            return "Execution timed out; record as limitation instead of escalating tools."
        if category == "profile_compatibility":
            return "Tool/profile compatibility failure; route to failure analysis before retrying."
        if category == "approval_or_policy":
            return "Approval or policy blocked execution; do not bypass with alternate tools."
        if category == "environment":
            return "Environment dependency is missing; report setup gap instead of free-form shell fallback."
        return "Execution failed; preserve evidence and let reporter judge impact."

    def _append_unique(self, values: list[str], value: str) -> None:
        if value and value not in values:
            values.append(value)

__all__ = ["SecuritySubtaskRefiner"]
