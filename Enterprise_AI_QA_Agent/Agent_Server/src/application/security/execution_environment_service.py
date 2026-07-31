"""Execution environment for security command profiles.

The security runner can execute tools either on the local host or inside a
Docker container. Docker mode mirrors PentAGI's controlled command pattern:
start a pentest image, run ``docker exec sh -lc`` for the approved command
profile, then either keep the container for reuse or remove it as a temporary
runner.
"""
from __future__ import annotations

import asyncio
import logging
import os
import re
import shlex
import shutil
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class SecurityCommandExecutionResult:
    """Result returned by a security command execution backend."""

    backend: str
    command: str
    argv: list[str]
    cwd: str
    stdout: str
    stderr: str
    exit_code: int
    timed_out: bool
    started_at: datetime
    completed_at: datetime
    container_name: str = ""
    output_artifacts: list[dict[str, Any]] = field(default_factory=list)


class SecurityExecutionEnvironmentService:
    """Run security commands in a configured execution environment."""

    def __init__(
        self,
        *,
        settings: Any = None,
        workspace_root: Path | str | None = None,
    ) -> None:
        self._settings = settings
        self._workspace_root = Path(workspace_root or Path.cwd())

    async def execute(
        self,
        *,
        command: str,
        command_args: list[str],
        timeout_seconds: float,
        artifact_dir: Path,
        context: Any = None,
    ) -> SecurityCommandExecutionResult:
        # S6 defense-in-depth: refuse commands whose high-confidence network
        # target (URL / literal IP) falls outside the configured allowlist.
        # The precise per-task gate lives in the coordinator; this is the last
        # chokepoint that every worker-initiated command must pass through.
        self._enforce_target_allowlist(command_args)
        backend = self._get_str("security_runner_backend", "SECURITY_RUNNER_BACKEND", "local").lower()
        if backend in {"docker", "container"}:
            return await asyncio.to_thread(
                self._run_in_docker,
                command,
                command_args,
                timeout_seconds,
                artifact_dir,
                context,
            )
        if backend in {"local", "host"}:
            return await asyncio.to_thread(
                self._run_local,
                command,
                command_args,
                timeout_seconds,
            )
        raise ValueError(f"Unsupported security runner backend: {backend}")

    def _enforce_target_allowlist(self, command_args: list[str]) -> None:
        """Reject commands targeting hosts outside the allowlist (S6).

        No-op when no allowlist is configured. Only high-confidence targets
        (URLs and literal IPs) are inspected so a misparse never wrongly blocks
        a legitimate command (``宁可漏过、不可误杀``).
        """
        from src.application.security.target_guard import SecurityTargetGuard

        guard = SecurityTargetGuard(self._settings)
        if not guard.has_allowlist:
            return
        result = guard.evaluate_command(command_args)
        if result.ok:
            return
        logger.warning(
            "security_runner target denied by allowlist: %s (hosts=%s)",
            result.reason,
            result.checked_hosts,
        )
        raise ValueError(f"security_target_allowlist_denied: {result.reason}")

    def _run_local(
        self,
        command: str,
        command_args: list[str],
        timeout_seconds: float,
    ) -> SecurityCommandExecutionResult:
        if not command_args:
            raise ValueError("Security command rendered an empty argv.")

        executable = command_args[0]
        resolved_executable = shutil.which(executable)
        if resolved_executable is None:
            raise FileNotFoundError(f"Security tool '{executable}' is not installed or not on PATH.")

        started_at = _utc_now()
        try:
            completed = subprocess.run(
                [resolved_executable, *command_args[1:]],
                cwd=str(self._workspace_root),
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout_seconds,
            )
            stdout_text = completed.stdout or ""
            stderr_text = completed.stderr or ""
            exit_code = completed.returncode
            timed_out = False
        except subprocess.TimeoutExpired as exc:
            stdout_text = exc.stdout or ""
            stderr_text = exc.stderr or ""
            exit_code = -1
            timed_out = True

        return SecurityCommandExecutionResult(
            backend="local",
            command=command,
            argv=[resolved_executable, *command_args[1:]],
            cwd=str(self._workspace_root),
            stdout=stdout_text,
            stderr=stderr_text,
            exit_code=exit_code,
            timed_out=timed_out,
            started_at=started_at,
            completed_at=_utc_now(),
        )

    def _run_in_docker(
        self,
        command: str,
        command_args: list[str],
        timeout_seconds: float,
        artifact_dir: Path,
        context: Any,
    ) -> SecurityCommandExecutionResult:
        docker = shutil.which("docker")
        if docker is None:
            raise FileNotFoundError("Docker CLI is not installed or not on PATH.")

        image = self._get_str(
            "security_runner_docker_image",
            "SECURITY_RUNNER_DOCKER_IMAGE",
            "vxcontrol/kali-linux",
        )
        workdir = self._get_str(
            "security_runner_docker_workdir",
            "SECURITY_RUNNER_DOCKER_WORKDIR",
            "/work",
        )
        container_name = self._container_name(context)
        artifact_dir.mkdir(parents=True, exist_ok=True)
        host_workdir = self._host_workdir_for_container(artifact_dir)
        host_workdir.mkdir(parents=True, exist_ok=True)
        cleanup_after_run = self._cleanup_after_run_enabled()

        self._ensure_container(
            docker=docker,
            image=image,
            container_name=container_name,
            host_workdir=host_workdir,
            container_workdir=workdir,
        )

        started_at = _utc_now()
        shell_command = self._wrap_with_shell_timeout(command, timeout_seconds)
        docker_args = [
            docker,
            "exec",
            "-w",
            workdir,
            container_name,
            "sh",
            "-lc",
            shell_command,
        ]
        cleanup_error = ""
        try:
            try:
                completed = subprocess.run(
                    docker_args,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=timeout_seconds + 5,
                )
                stdout_text = completed.stdout or ""
                stderr_text = completed.stderr or ""
                exit_code = completed.returncode
                timed_out = exit_code == 124
            except subprocess.TimeoutExpired as exc:
                stdout_text = exc.stdout or ""
                stderr_text = exc.stderr or ""
                exit_code = -1
                timed_out = True
        finally:
            if cleanup_after_run:
                cleanup_error = self._remove_container(docker=docker, container_name=container_name)
        if cleanup_error:
            stderr_text = _append_stderr(stderr_text, cleanup_error)

        return SecurityCommandExecutionResult(
            backend="docker",
            command=command,
            argv=docker_args,
            cwd=workdir,
            stdout=stdout_text,
            stderr=stderr_text,
            exit_code=exit_code,
            timed_out=timed_out,
            started_at=started_at,
            completed_at=_utc_now(),
            container_name=container_name,
            output_artifacts=self._collect_output_artifacts(host_workdir),
        )

    def _cleanup_after_run_enabled(self) -> bool:
        return self._get_bool(
            "security_runner_docker_cleanup_after_run",
            "SECURITY_RUNNER_DOCKER_CLEANUP_AFTER_RUN",
            not self._container_reuse_enabled(),
        )

    def _container_reuse_enabled(self) -> bool:
        return self._get_bool("security_runner_container_reuse", "SECURITY_RUNNER_CONTAINER_REUSE", False)

    def _remove_container(self, *, docker: str, container_name: str) -> str:
        try:
            remove = subprocess.run(
                [docker, "rm", "-f", container_name],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=30,
            )
        except subprocess.TimeoutExpired:
            return f"Failed to remove security Docker container {container_name}: cleanup timed out."
        if remove.returncode == 0:
            return ""
        detail = (remove.stderr or remove.stdout or "").strip()
        return f"Failed to remove security Docker container {container_name}: {detail or 'unknown error'}"

    def _ensure_container(
        self,
        *,
        docker: str,
        image: str,
        container_name: str,
        host_workdir: Path,
        container_workdir: str,
    ) -> None:
        inspect = subprocess.run(
            [docker, "inspect", "-f", "{{.State.Running}}", container_name],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=15,
        )
        if inspect.returncode == 0:
            if (inspect.stdout or "").strip().lower() == "true":
                return
            if self._container_reuse_enabled():
                start = subprocess.run(
                    [docker, "start", container_name],
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=30,
                )
                if start.returncode != 0:
                    raise RuntimeError(
                        start.stderr.strip() or start.stdout.strip() or "Failed to start security Docker container."
                    )
                return
            self._remove_container(docker=docker, container_name=container_name)

        self._pull_image_if_needed(docker, image)
        run_args = [
            docker,
            "run",
            "-d",
            "--name",
            container_name,
            "--workdir",
            container_workdir,
        ]
        if self._get_bool("security_runner_docker_net_raw", "SECURITY_RUNNER_DOCKER_NET_RAW", True):
            run_args.extend(["--cap-add", "NET_RAW"])
        if self._get_bool("security_runner_docker_net_admin", "SECURITY_RUNNER_DOCKER_NET_ADMIN", False):
            run_args.extend(["--cap-add", "NET_ADMIN"])

        network = self._get_str("security_runner_docker_network", "SECURITY_RUNNER_DOCKER_NETWORK", "")
        if network:
            run_args.extend(["--network", network])

        mount_spec = f"{host_workdir.resolve()}:{container_workdir}"
        run_args.extend(["-v", mount_spec, image, "tail", "-f", "/dev/null"])
        run = subprocess.run(
            run_args,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=60,
        )
        if run.returncode != 0:
            raise RuntimeError(run.stderr.strip() or run.stdout.strip() or "Failed to create security Docker container.")

    def _pull_image_if_needed(self, docker: str, image: str) -> None:
        policy = self._get_str(
            "security_runner_docker_pull_policy",
            "SECURITY_RUNNER_DOCKER_PULL_POLICY",
            "never",
        ).lower()
        if policy == "never":
            return
        if policy == "missing":
            inspect = subprocess.run(
                [docker, "image", "inspect", image],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=15,
            )
            if inspect.returncode == 0:
                return
        if policy not in {"always", "missing"}:
            return
        pull = subprocess.run(
            [docker, "pull", image],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=1800,
        )
        if pull.returncode != 0:
            raise RuntimeError(pull.stderr.strip() or pull.stdout.strip() or f"Failed to pull Docker image {image}.")

    def _wrap_with_shell_timeout(self, command: str, timeout_seconds: float) -> str:
        if not self._get_bool("security_runner_wrap_timeout", "SECURITY_RUNNER_WRAP_TIMEOUT", True):
            return command
        inner_timeout = max(1, int(timeout_seconds) - 2)
        return f"timeout {inner_timeout}s sh -c {shlex.quote(command)}"

    def _container_name(self, context: Any) -> str:
        prefix = self._get_str(
            "security_runner_docker_container_prefix",
            "SECURITY_RUNNER_DOCKER_CONTAINER_PREFIX",
            "qa-security-runner",
        )
        session_id = getattr(context, "session_id", "") or "session"
        turn_id = getattr(context, "turn_id", "") or "turn"
        reuse = self._container_reuse_enabled()
        suffix = f"{_slug(session_id)}-{_slug(turn_id)}"
        if not reuse:
            suffix = f"{suffix}-{_utc_now().strftime('%Y%m%d%H%M%S')}"
        return f"{_slug(prefix)}-{suffix}"[:120].strip("-") or "qa-security-runner"

    def _host_workdir_for_container(self, artifact_dir: Path) -> Path:
        if self._container_reuse_enabled():
            return artifact_dir.parent / "_security_runner_work"
        return artifact_dir

    def _collect_output_artifacts(self, artifact_dir: Path) -> list[dict[str, Any]]:
        artifacts: list[dict[str, Any]] = []
        for path in sorted(artifact_dir.rglob("*")):
            if not path.is_file():
                continue
            artifacts.append(
                {
                    "type": "security_runner_output",
                    "label": path.name,
                    "path": str(path),
                    "size_bytes": path.stat().st_size,
                }
            )
        return artifacts

    def _get_str(self, attr: str, env_name: str, default: str) -> str:
        value = getattr(self._settings, attr, None) if self._settings is not None else None
        if value not in (None, ""):
            return str(value).strip()
        return str(os.getenv(env_name, default) or default).strip()

    def _get_bool(self, attr: str, env_name: str, default: bool) -> bool:
        value = getattr(self._settings, attr, None) if self._settings is not None else None
        if value is None:
            value = os.getenv(env_name)
        if value is None:
            return default
        if isinstance(value, bool):
            return value
        return str(value).strip().lower() in {"1", "true", "yes", "y", "on"}


def _slug(value: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9_.-]+", "-", str(value).strip().lower())
    return cleaned.strip("-_.") or "default"


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _append_stderr(stderr_text: str, extra: str) -> str:
    if not stderr_text:
        return extra
    return f"{stderr_text.rstrip()}\n{extra}"
