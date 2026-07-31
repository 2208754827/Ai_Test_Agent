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
