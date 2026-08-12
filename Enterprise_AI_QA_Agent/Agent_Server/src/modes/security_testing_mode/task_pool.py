"""Security Task Pool: lifecycle management for security testing tasks.

Maintains the state machine for each task and provides queries for the
coordinator to pick the next batch of ready tasks.
"""
from __future__ import annotations

from datetime import datetime, timezone

from src.modes.security_testing_mode.campaign_state import SecurityTask
from src.modes.security_testing_mode.contracts import (
    TASK_BLOCKED,
    TASK_COMPLETED,
    TASK_FAILED,
    TASK_PENDING,
    TASK_READY,
    TASK_RUNNING,
    TASK_SKIPPED,
    MAX_TASK_RETRIES,
)


class SecurityTaskPool:
    """In-memory task pool for one security testing campaign."""

    def __init__(self, tasks: list[SecurityTask] | None = None) -> None:
        self._tasks: dict[str, SecurityTask] = {}
        for task in tasks or []:
            self._tasks[task.task_id] = task
        # Initial resolution: tasks with no dependencies start as ready
        self._initialize_statuses()

    def _initialize_statuses(self) -> None:
        """Set initial statuses based on dependencies."""
        for task in self._tasks.values():
            if task.status != TASK_PENDING:
                continue
            if not task.depends_on:
                task.status = TASK_READY
            else:
                # Check if all dependencies exist
                has_valid_deps = any(
                    dep_id in self._tasks for dep_id in task.depends_on
                )
                if has_valid_deps:
                    task.status = TASK_BLOCKED
                else:
                    # Dependencies don't exist in pool, treat as ready
                    task.status = TASK_READY

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def all_tasks(self) -> list[SecurityTask]:
        return list(self._tasks.values())

    @property
    def is_complete(self) -> bool:
        return all(
            task.status in {TASK_COMPLETED, TASK_FAILED, TASK_SKIPPED}
            for task in self._tasks.values()
        )

    @property
    def has_running(self) -> bool:
        return any(task.status == TASK_RUNNING for task in self._tasks.values())

    @property
    def task_count(self) -> int:
        return len(self._tasks)

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def ready_tasks(self) -> list[SecurityTask]:
        """Return tasks that are ready to execute."""
        return [task for task in self._tasks.values() if task.status == TASK_READY]

    def blocked_tasks(self) -> list[SecurityTask]:
        return [task for task in self._tasks.values() if task.status == TASK_BLOCKED]

    def running_tasks(self) -> list[SecurityTask]:
        return [task for task in self._tasks.values() if task.status == TASK_RUNNING]

    def completed_tasks(self) -> list[SecurityTask]:
        return [task for task in self._tasks.values() if task.status == TASK_COMPLETED]

    def failed_tasks(self) -> list[SecurityTask]:
        return [task for task in self._tasks.values() if task.status == TASK_FAILED]

    def skipped_tasks(self) -> list[SecurityTask]:
        return [task for task in self._tasks.values() if task.status == TASK_SKIPPED]

    def get(self, task_id: str) -> SecurityTask | None:
        return self._tasks.get(task_id)

    def add_task(self, task: SecurityTask) -> bool:
        """Add a refined task and derive its initial state from dependencies."""
        if task.task_id in self._tasks:
            return False
        dependencies = [self._tasks[item] for item in task.depends_on if item in self._tasks]
        if any(item.status in {TASK_FAILED, TASK_SKIPPED} for item in dependencies):
            task.status = TASK_SKIPPED
            task.last_error = "Skipped: a refinement dependency already failed."
        elif dependencies and not all(item.status == TASK_COMPLETED for item in dependencies):
            task.status = TASK_BLOCKED
        else:
            task.status = TASK_READY
        self._tasks[task.task_id] = task
        return True

    def remove_task(self, task_id: str, reason: str = "") -> SecurityTask | None:
        """Remove only a future task; running or settled evidence is immutable."""
        task = self._tasks.get(task_id)
        if task is None or task.status not in {TASK_PENDING, TASK_READY, TASK_BLOCKED}:
            return None
        removed = self._tasks.pop(task_id)
        for dependent in self._tasks.values():
            if task_id not in dependent.depends_on:
                continue
            dependent.depends_on = [item for item in dependent.depends_on if item != task_id]
            if reason:
                dependent.observations.append(reason)
        self.resolve_blocked()
        return removed

    def downgrade_task(
        self,
        task_id: str,
        *,
        command_profile: str,
        tool_family: str,
        risk_level: str,
        requires_approval: bool,
        reason: str,
    ) -> bool:
        """Replace the execution strategy of a future task without changing identity."""
        task = self._tasks.get(task_id)
        if task is None or task.status not in {TASK_PENDING, TASK_READY, TASK_BLOCKED}:
            return False
        task.command_profile = command_profile
        task.tool_family = tool_family
        task.risk_level = risk_level
        task.requires_approval = requires_approval
        if reason:
            task.observations.append(reason)
        return True

    # ------------------------------------------------------------------
    # State transitions
    # ------------------------------------------------------------------

    def mark_running(self, task_id: str) -> None:
        task = self._tasks.get(task_id)
        if task is not None:
            task.status = TASK_RUNNING
            task.attempts += 1
            task.started_at = datetime.now(timezone.utc).isoformat()

    def mark_completed(self, task_id: str, result_summary: str = "") -> None:
        task = self._tasks.get(task_id)
        if task is not None:
            task.status = TASK_COMPLETED
            task.completed_at = datetime.now(timezone.utc).isoformat()
            if result_summary:
                task.result_summary = result_summary
            self._release_dependents(task_id)

    def mark_failed(self, task_id: str, error: str = "") -> None:
        task = self._tasks.get(task_id)
        if task is not None:
            task.status = TASK_FAILED
            task.completed_at = datetime.now(timezone.utc).isoformat()
            task.last_error = error
            self._skip_dependents(task_id)

    def mark_skipped(self, task_id: str, reason: str = "") -> None:
        task = self._tasks.get(task_id)
        if task is not None:
            task.status = TASK_SKIPPED
            task.last_error = reason
            self._skip_dependents(task_id)

    def resolve_blocked(self) -> int:
        """Promote blocked tasks to ready if all their dependencies are satisfied."""
        promoted = 0
        for task in list(self._tasks.values()):
            if task.status != TASK_BLOCKED:
                continue
            if self._dependencies_satisfied(task):
                task.status = TASK_READY
                promoted += 1
        return promoted

    def reset_for_retry(self, task_id: str) -> bool:
        """Reset a failed task for retry if within retry limit."""
        task = self._tasks.get(task_id)
        if task is None:
            return False
        if task.status != TASK_FAILED:
            return False
        if task.attempts >= task.max_retries + 1:
            return False
        task.status = TASK_READY
        task.last_error = ""
        task.worker_status = ""
        task.worker_session_id = ""
        task.raw_output = ""
        task.parsed_result = {}
        return True

    def retryable_tasks(self) -> list[SecurityTask]:
        """Return failed tasks that can still be retried."""
        return [
            task for task in self._tasks.values()
            if task.status == TASK_FAILED and task.attempts <= task.max_retries
        ]

    def interrupt_unsettled(self, reason: str) -> list[SecurityTask]:
        """Settle every non-terminal task without discarding completed evidence."""
        interrupted: list[SecurityTask] = []
        for task in self._tasks.values():
            if task.status in {TASK_COMPLETED, TASK_FAILED, TASK_SKIPPED}:
                continue
            task.status = TASK_SKIPPED
            task.last_error = str(reason or "Security campaign interrupted.")
            task.completed_at = datetime.now(timezone.utc).isoformat()
            interrupted.append(task)
        return interrupted

    def reset_for_reflect(self, task_id: str) -> bool:
        """Return a running task to READY so the Reflector can re-dispatch it (S2).

        Unlike ``reset_for_retry`` this is independent of the retry budget: the
        Reflector loop is bounded separately by ``reflect_attempts`` on the
        task. Worker session bookkeeping is cleared so the next dispatch starts
        clean, but ``attempts``/``reflect_attempts`` counters are preserved.
        """
        task = self._tasks.get(task_id)
        if task is None:
            return False
        task.status = TASK_READY
        task.worker_status = ""
        task.worker_session_id = ""
        task.last_error = ""
        task.raw_output = ""
        task.parsed_result = {}
        return True

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------

    def summary(self) -> dict[str, int]:
        counts: dict[str, int] = {
            TASK_PENDING: 0,
            TASK_BLOCKED: 0,
            TASK_READY: 0,
            TASK_RUNNING: 0,
            TASK_COMPLETED: 0,
            TASK_FAILED: 0,
            TASK_SKIPPED: 0,
        }
        for task in self._tasks.values():
            counts[task.status] = counts.get(task.status, 0) + 1
        return counts

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _dependencies_satisfied(self, task: SecurityTask) -> bool:
        for dep_id in task.depends_on:
            dep = self._tasks.get(dep_id)
            if dep is None:
                continue
            if dep.status != TASK_COMPLETED:
                return False
        return True

    def _release_dependents(self, completed_task_id: str) -> None:
        for task in self._tasks.values():
            if task.status != TASK_BLOCKED:
                continue
            if completed_task_id in task.depends_on:
                if self._dependencies_satisfied(task):
                    task.status = TASK_READY

    def _skip_dependents(self, failed_task_id: str) -> None:
        for task in self._tasks.values():
            if task.status in {TASK_BLOCKED, TASK_PENDING}:
                if failed_task_id in task.depends_on:
                    task.status = TASK_SKIPPED
                    task.last_error = f"Skipped: dependency {failed_task_id} failed."
                    self._skip_dependents(task.task_id)


__all__ = ["SecurityTaskPool"]
