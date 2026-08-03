"""Controlled Security Bug retest executor."""
from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener
from uuid import uuid4

from src.application.security.finding_normalizer import FindingNormalizer
from src.application.security.target_guard import SecurityTargetGuard
from src.modes.security_testing_mode.campaign_state import (
    EvidenceArtifact,
    SecurityBugRecord,
    SecurityCampaign,
    SecurityTask,
    VerificationAttempt,
)
from src.modes.security_testing_mode.security_bug_service import SecurityBugService


logger = logging.getLogger("uvicorn.error.security_testing_mode.security_bug_retest")


class SecurityBugRetestExecutor:
    """Replay low-risk registered regression profiles for one Security Bug."""

    SUPPORTED_PROFILES = {"http_headers_probe"}

    def __init__(
        self,
        security_bug_service: SecurityBugService,
        *,
        settings: Any | None = None,
        timeout_seconds: int = 10,
    ) -> None:
        self._security_bug_service = security_bug_service
        self._target_guard = SecurityTargetGuard(settings)
        self._timeout_seconds = max(1, min(int(timeout_seconds or 10), 60))
        self._normalizer = FindingNormalizer()

    async def retest(self, bug_id: str) -> dict[str, Any]:
        bug = await self._security_bug_service.get(bug_id)
        if bug is None:
            raise KeyError(f"Security Bug not found: {bug_id}")
        if bug.regression_profile not in self.SUPPORTED_PROFILES:
            raise ValueError(
                f"Unsupported Security Bug regression profile: {bug.regression_profile or '<empty>'}"
            )
        guard = self._target_guard.evaluate_target(bug.affected_target)
        if not guard.ok:
            raise ValueError(f"security_target_allowlist_denied: {guard.reason}")
        campaign, parsed_result = await asyncio.to_thread(self._build_retest_campaign, bug)
        retested = await self._security_bug_service.sync_bug_retest(
            bug.bug_id,
            campaign,
            session_id=f"security-bug-retest-{bug.bug_id}",
        )
        outcome = self._outcome(before=bug, after=retested)
        logger.info(
            "security.bug.retest_executed %s",
            json.dumps(
                {
                    "bug_id": bug.bug_id,
                    "campaign_id": campaign.campaign_id,
                    "target": bug.affected_target,
                    "profile": bug.regression_profile,
                    "outcome": outcome,
                    "status": retested.status,
                },
                ensure_ascii=False,
                separators=(",", ":"),
            ),
        )
        return {
            "bug_id": bug.bug_id,
            "campaign_id": campaign.campaign_id,
            "session_id": f"security-bug-retest-{bug.bug_id}",
            "profile": bug.regression_profile,
            "target": bug.affected_target,
            "outcome": outcome,
            "parsed_result": parsed_result,
            "bug": retested.model_dump(mode="json"),
        }

    def _build_retest_campaign(
        self,
        bug: SecurityBugRecord,
    ) -> tuple[SecurityCampaign, dict[str, Any]]:
        now = _utc_now()
        campaign_id = f"campaign_retest_{uuid4()}"
        task_id = f"retest_{bug.bug_id}"
        parsed_result = self._execute_http_headers_probe(bug)
        raw_output = json.dumps(parsed_result, ensure_ascii=False, separators=(",", ":"))
        task = SecurityTask(
            task_id=task_id,
            name=f"Retest {bug.bug_id}",
            surface_type="web",
            tool_family="web_scan",
            command_profile=bug.regression_profile,
            target=bug.affected_target,
            status="completed",
            raw_output=raw_output,
            parsed_result=parsed_result,
            started_at=now,
            completed_at=now,
        )
        artifact = EvidenceArtifact(
            artifact_id=f"ev_{task_id}_raw_output",
            artifact_type="tool_output",
            content_type="application/json",
            source_task_id=task.task_id,
            content=raw_output,
            created_at=now,
        )
        findings = self._normalizer.from_http_headers_result(
            parsed_result,
            task_id=task.task_id,
        )
        for finding in findings:
            finding.evidence_ids = [artifact.artifact_id]
        attempt = VerificationAttempt(
            attempt_id=f"attempt_{bug.bug_id}",
            task_id=task.task_id,
            finding_ids=[finding.finding_id for finding in findings],
            status="succeeded",
            target=bug.affected_target,
            profile_key=bug.regression_profile,
            evidence_ids=[artifact.artifact_id],
            stdout_summary=(
                f"HTTP {parsed_result.get('status_code')} response headers recorded for "
                f"{bug.affected_target}."
            ),
            cleanup_status="completed",
            completed_at=now,
        )
        campaign = SecurityCampaign(
            campaign_id=campaign_id,
            target_fingerprint=bug.target_fingerprint,
            tasks=[task],
            findings=findings,
            verification_attempts=[attempt],
            evidence=[artifact],
        )
        return campaign, parsed_result

    def _execute_http_headers_probe(self, bug: SecurityBugRecord) -> dict[str, Any]:
        target = self._replay_url(bug)
        request = Request(
            target,
            method="GET",
            headers={
                "User-Agent": "Enterprise-AI-QA-Agent security-regression",
                "Connection": "close",
            },
        )
        opener = build_opener(_NoRedirectHandler)
        try:
            with opener.open(request, timeout=self._timeout_seconds) as response:
                status_code = int(response.getcode())
                headers = dict(response.headers.items())
        except HTTPError as exc:
            status_code = int(exc.code)
            headers = dict(exc.headers.items())
        except URLError as exc:
            raise RuntimeError(f"Security Bug retest could not reach target: {exc.reason}") from exc
        return {
            "url": bug.affected_target,
            "status_code": status_code,
            "headers": headers,
        }

    def _replay_url(self, bug: SecurityBugRecord) -> str:
        parsed = urlsplit(bug.affected_target)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError(f"Unsupported Security Bug target URL: {bug.affected_target}")
        request_line = str(bug.reproduction_request or "").splitlines()[0:1]
        if request_line:
            parts = request_line[0].split()
            if len(parts) >= 2 and parts[0].upper() == "GET" and parts[1].startswith("/"):
                return urlunsplit((parsed.scheme, parsed.netloc, parts[1], "", ""))
        return bug.affected_target

    def _outcome(self, *, before: SecurityBugRecord, after: SecurityBugRecord) -> str:
        if after.retest_history and after.retest_history[-1].outcome in {
            "reproduced",
            "not_reproduced",
            "inconclusive",
        }:
            return after.retest_history[-1].outcome
        if before.status == after.status:
            return "inconclusive"
        return "reproduced" if after.status == "retest_failed" else "not_reproduced"


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


__all__ = ["SecurityBugRetestExecutor"]
