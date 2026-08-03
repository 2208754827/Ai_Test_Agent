"""Security Bug generation, lifecycle tracking and evidence-backed retesting."""
from __future__ import annotations

import hashlib
import json
import logging
import re
from datetime import datetime, timezone
from urllib.parse import urlsplit, urlunsplit

from src.application.security.output_safety_policy import OutputSafetyPolicy
from src.modes.security_testing_mode.campaign_state import (
    FindingRecord,
    SecurityBugEvidenceRef,
    SecurityBugRecord,
    SecurityBugRetestRecord,
    SecurityCampaign,
    SecurityTask,
    VerificationAttempt,
)
from src.modes.security_testing_mode.contracts import TASK_COMPLETED
from src.modes.security_testing_mode.security_bug_store import SecurityBugStore


logger = logging.getLogger("uvicorn.error.security_testing_mode.security_bug")

_ALLOWED_MANUAL_TRANSITIONS = {
    "confirmed": {"fixed", "false_positive"},
    "retest_failed": {"fixed", "false_positive"},
    "fixed": {"confirmed", "false_positive"},
    "false_positive": {"confirmed"},
    "closed": {"confirmed"},
}
_VERIFICATION_ORDER = {
    "observed": 0,
    "confirmed": 1,
    "exploitable": 2,
    "impact_verified": 3,
}


class SecurityBugService:
    """Promote verified findings into persistent, reproducible Bug records."""

    def __init__(
        self,
        store: SecurityBugStore,
        *,
        reproduction_required: bool = True,
    ) -> None:
        self._store = store
        self._reproduction_required = reproduction_required
        self._output_safety = OutputSafetyPolicy()

    async def initialize(self) -> None:
        await self._store.initialize()

    async def sync_campaign(
        self,
        campaign: SecurityCampaign,
        *,
        session_id: str,
    ) -> list[SecurityBugRecord]:
        """Persist reproduced Bugs and settle evidence-backed fixed retests."""
        finding_by_id = {item.finding_id: item for item in campaign.findings}
        current: dict[str, SecurityBugRecord] = {}
        skipped_findings: list[str] = []
        for attempt in campaign.verification_attempts:
            if attempt.status != "succeeded" or not attempt.evidence_ids:
                continue
            for finding_id in attempt.finding_ids:
                finding = finding_by_id.get(finding_id)
                if finding is None:
                    continue
                candidate = self._build_candidate(
                    campaign=campaign,
                    finding=finding,
                    attempt=attempt,
                    session_id=session_id,
                )
                if candidate is None:
                    skipped_findings.append(finding.finding_id or finding.title)
                    continue
                stored, created = await self._store.upsert_observation(candidate)
                current[stored.fingerprint] = stored
                self._log_event(
                    "security.bug.created" if created else "security.bug.deduplicated",
                    stored,
                    campaign_id=campaign.campaign_id,
                    session_id=session_id,
                    occurrence_count=stored.occurrence_count,
                )
                if not created:
                    self._log_event(
                        "security.bug.retested",
                        stored,
                        campaign_id=campaign.campaign_id,
                        session_id=session_id,
                        outcome="reproduced",
                        status=stored.status,
                    )

        closed = await self._close_fixed_bugs_not_reproduced(
            campaign=campaign,
            session_id=session_id,
            current_fingerprints=set(current),
        )
        for item in closed:
            current[item.fingerprint] = item
        if skipped_findings:
            limitation = (
                f"P0-B reproduction gate kept {len(skipped_findings)} verified finding(s) as Findings "
                "because required Bug reproduction, mapping, CVSS, actual-result, or evidence fields were incomplete."
            )
            if limitation not in campaign.operational_constraints:
                campaign.operational_constraints.append(limitation)
            logger.warning(
                "security.bug.reproduction_blocked %s",
                json.dumps(
                    {
                        "campaign_id": campaign.campaign_id,
                        "finding_ids": skipped_findings,
                    },
                    ensure_ascii=False,
                    separators=(",", ":"),
                ),
            )
        campaign.security_bugs = sorted(current.values(), key=lambda item: item.bug_id)
        return list(campaign.security_bugs)

    async def get(self, bug_id: str) -> SecurityBugRecord | None:
        return await self._store.get(bug_id)

    async def list(
        self,
        *,
        target_fingerprint: str = "",
        status: str = "",
    ) -> list[SecurityBugRecord]:
        return await self._store.list(
            target_fingerprint=target_fingerprint,
            status=status,
        )

    async def transition(
        self,
        bug_id: str,
        *,
        status: str,
        fixed_version: str = "",
        note: str = "",
    ) -> SecurityBugRecord:
        """Apply an explicit lifecycle decision; close remains evidence-driven."""
        bug = await self._store.get(bug_id)
        if bug is None:
            raise KeyError(f"Security Bug not found: {bug_id}")
        requested = str(status or "").strip().lower()
        if requested == "closed":
            raise ValueError(
                "Security Bug closure requires a non-reproduced regression run with new evidence."
            )
        if requested not in _ALLOWED_MANUAL_TRANSITIONS.get(bug.status, set()):
            raise ValueError(f"Invalid Security Bug transition: {bug.status} -> {requested}")
        previous_status = bug.status
        bug.status = requested
        bug.fixed_version = str(fixed_version or "").strip()
        bug.lifecycle_note = self._sanitize_text(note, limit=1000)
        stored = await self._store.save(bug)
        self._log_event(
            "security.bug.lifecycle_changed",
            stored,
            from_status=previous_status,
            to_status=requested,
        )
        return stored

    async def sync_bug_retest(
        self,
        bug_id: str,
        campaign: SecurityCampaign,
        *,
        session_id: str,
    ) -> SecurityBugRecord:
        """Apply one retest campaign to one Bug without mutating unrelated Bugs."""
        bug = await self._store.get(bug_id)
        if bug is None:
            raise KeyError(f"Security Bug not found: {bug_id}")
        finding_by_id = {item.finding_id: item for item in campaign.findings}
        for attempt in campaign.verification_attempts:
            if attempt.status != "succeeded" or not attempt.evidence_ids:
                continue
            for finding_id in attempt.finding_ids:
                finding = finding_by_id.get(finding_id)
                if finding is None:
                    continue
                candidate = self._build_candidate(
                    campaign=campaign,
                    finding=finding,
                    attempt=attempt,
                    session_id=session_id,
                )
                if candidate is None or candidate.fingerprint != bug.fingerprint:
                    continue
                stored, _created = await self._store.upsert_observation(candidate)
                self._log_event(
                    "security.bug.retested",
                    stored,
                    campaign_id=campaign.campaign_id,
                    session_id=session_id,
                    outcome="reproduced",
                    status=stored.status,
                )
                campaign.security_bugs = [stored]
                return stored
        if bug.status == "fixed":
            closed = await self._close_one_fixed_bug_not_reproduced(
                bug=bug,
                campaign=campaign,
                session_id=session_id,
            )
            if closed is not None:
                campaign.security_bugs = [closed]
                return closed
        campaign.security_bugs = [bug]
        return bug

    def _build_candidate(
        self,
        *,
        campaign: SecurityCampaign,
        finding: FindingRecord,
        attempt: VerificationAttempt,
        session_id: str,
    ) -> SecurityBugRecord | None:
        if finding.false_positive or finding.verification_level == "observed":
            return None
        target = self._canonical_target(attempt.target or finding.affected_target)
        component = self._affected_component(finding)
        steps = self._reproduction_steps(finding, attempt, target, component)
        request = self._reproduction_request(attempt, target)
        actual_result = self._replace_evidence_target(
            self._sanitize_text(
                finding.evidence_summary or attempt.stdout_summary,
                limit=1800,
            ),
            target,
        )
        expected_result = self._expected_result(finding, component)
        cvss_vector, cvss_score, cvss_rationale = self._cvss(finding)
        cwe_ids, owasp_categories = self._mappings(finding)
        evidence_refs = self._evidence_refs(
            campaign=campaign,
            finding=finding,
            attempt=attempt,
            session_id=session_id,
        )
        impact = self._impact_details(finding)
        preconditions = [
            f"The verified authorization scope includes {target}.",
            "The approved isolated security runner can reach the target.",
        ]
        required = (
            target,
            component,
            steps,
            request,
            expected_result,
            actual_result,
            evidence_refs,
            cvss_vector,
            cvss_rationale,
            cwe_ids,
            owasp_categories,
            impact["proof_present"] if finding.verification_level == "impact_verified" else True,
        )
        if self._reproduction_required and not all(required):
            return None
        fingerprint = self._fingerprint(
            target=target,
            category=finding.category,
            component=component,
            trigger=self._normalized_trigger(finding),
        )
        now = attempt.completed_at or _utc_now()
        retest = SecurityBugRetestRecord(
            retest_id=f"retest_{self._stable_hash(f'{campaign.campaign_id}|{fingerprint}')}",
            campaign_id=campaign.campaign_id,
            session_id=session_id,
            attempt_id=attempt.attempt_id,
            outcome="reproduced",
            verification_level=finding.verification_level,
            actual_result=actual_result,
            evidence_refs=evidence_refs,
            tested_at=now,
        )
        evidence_ids = list(dict.fromkeys(
            [*finding.evidence_ids, *attempt.evidence_ids]
        ))
        return SecurityBugRecord(
            bug_id=f"sbug_{fingerprint[:20]}",
            fingerprint=fingerprint,
            title=finding.title,
            status="confirmed",
            verification_level=finding.verification_level,
            severity=finding.severity,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            cvss_rationale=cvss_rationale,
            cve_ids=[finding.cve_id] if finding.cve_id else [],
            cwe_ids=cwe_ids,
            owasp_categories=owasp_categories,
            target_fingerprint=campaign.target_fingerprint,
            affected_target=target,
            affected_component=component,
            preconditions=preconditions,
            reproduction_steps=steps,
            reproduction_request=request,
            expected_result=expected_result,
            actual_result=actual_result,
            evidence_ids=evidence_ids,
            evidence_refs=evidence_refs,
            exposed_data_types=impact["exposed_data_types"],
            exposed_record_estimate=impact["exposed_record_estimate"],
            confidentiality_impact=impact["confidentiality_impact"],
            integrity_impact=impact["integrity_impact"],
            availability_impact=impact["availability_impact"],
            business_impact=self._business_impact(finding),
            remediation=finding.recommendation,
            regression_case_id=f"reg_{fingerprint[:20]}",
            regression_profile=attempt.profile_key,
            campaign_ids=[campaign.campaign_id],
            finding_ids=[finding.finding_id],
            attempt_ids=[attempt.attempt_id],
            occurrence_count=1,
            first_seen_at=now,
            last_seen_at=now,
            retest_history=[retest],
        )

    async def _close_fixed_bugs_not_reproduced(
        self,
        *,
        campaign: SecurityCampaign,
        session_id: str,
        current_fingerprints: set[str],
    ) -> list[SecurityBugRecord]:
        if not campaign.target_fingerprint:
            return []
        fixed = await self._store.list(
            target_fingerprint=campaign.target_fingerprint,
            status="fixed",
        )
        closed: list[SecurityBugRecord] = []
        for bug in fixed:
            if bug.fingerprint in current_fingerprints:
                continue
            task = self._completed_regression_task(campaign.tasks, bug)
            if task is None:
                continue
            artifacts = [
                item
                for item in campaign.evidence
                if item.source_task_id == task.task_id
            ]
            if not artifacts or not (task.raw_output or task.parsed_result):
                continue
            now = task.completed_at or _utc_now()
            evidence_refs = [
                SecurityBugEvidenceRef(
                    campaign_id=campaign.campaign_id,
                    session_id=session_id,
                    artifact_id=item.artifact_id,
                    source_task_id=item.source_task_id,
                    created_at=item.created_at or now,
                )
                for item in artifacts
            ]
            retest = SecurityBugRetestRecord(
                retest_id=f"retest_{self._stable_hash(f'{campaign.campaign_id}|{bug.fingerprint}|closed')}",
                campaign_id=campaign.campaign_id,
                session_id=session_id,
                outcome="not_reproduced",
                verification_level=bug.verification_level,
                actual_result=(
                    f"Regression profile {bug.regression_profile} completed with new evidence; "
                    "the stored trigger was not reproduced."
                ),
                evidence_refs=evidence_refs,
                tested_at=now,
            )
            bug.status = "closed"
            bug.last_seen_at = now
            bug.campaign_ids = list(dict.fromkeys([*bug.campaign_ids, campaign.campaign_id]))
            bug.evidence_refs.extend(evidence_refs)
            bug.evidence_ids = list(dict.fromkeys(
                [*bug.evidence_ids, *(item.artifact_id for item in artifacts)]
            ))
            bug.retest_history.append(retest)
            stored = await self._store.save(bug)
            closed.append(stored)
            self._log_event(
                "security.bug.retested",
                stored,
                campaign_id=campaign.campaign_id,
                session_id=session_id,
                outcome="not_reproduced",
                status="closed",
            )
        return closed

    async def _close_one_fixed_bug_not_reproduced(
        self,
        *,
        bug: SecurityBugRecord,
        campaign: SecurityCampaign,
        session_id: str,
    ) -> SecurityBugRecord | None:
        task = self._completed_regression_task(campaign.tasks, bug)
        if task is None:
            return None
        artifacts = [
            item
            for item in campaign.evidence
            if item.source_task_id == task.task_id
        ]
        if not artifacts or not (task.raw_output or task.parsed_result):
            return None
        now = task.completed_at or _utc_now()
        evidence_refs = [
            SecurityBugEvidenceRef(
                campaign_id=campaign.campaign_id,
                session_id=session_id,
                artifact_id=item.artifact_id,
                source_task_id=item.source_task_id,
                created_at=item.created_at or now,
            )
            for item in artifacts
        ]
        retest = SecurityBugRetestRecord(
            retest_id=f"retest_{self._stable_hash(f'{campaign.campaign_id}|{bug.fingerprint}|closed')}",
            campaign_id=campaign.campaign_id,
            session_id=session_id,
            outcome="not_reproduced",
            verification_level=bug.verification_level,
            actual_result=(
                f"Regression profile {bug.regression_profile} completed with new evidence; "
                "the stored trigger was not reproduced."
            ),
            evidence_refs=evidence_refs,
            tested_at=now,
        )
        bug.status = "closed"
        bug.last_seen_at = now
        bug.campaign_ids = list(dict.fromkeys([*bug.campaign_ids, campaign.campaign_id]))
        bug.evidence_refs.extend(evidence_refs)
        bug.evidence_ids = list(dict.fromkeys(
            [*bug.evidence_ids, *(item.artifact_id for item in artifacts)]
        ))
        bug.retest_history.append(retest)
        stored = await self._store.save(bug)
        self._log_event(
            "security.bug.retested",
            stored,
            campaign_id=campaign.campaign_id,
            session_id=session_id,
            outcome="not_reproduced",
            status="closed",
        )
        return stored

    def _completed_regression_task(
        self,
        tasks: list[SecurityTask],
        bug: SecurityBugRecord,
    ) -> SecurityTask | None:
        for task in tasks:
            if (
                task.status == TASK_COMPLETED
                and task.command_profile == bug.regression_profile
                and self._canonical_target(task.target) == bug.affected_target
            ):
                return task
        return None

    def _evidence_refs(
        self,
        *,
        campaign: SecurityCampaign,
        finding: FindingRecord,
        attempt: VerificationAttempt,
        session_id: str,
    ) -> list[SecurityBugEvidenceRef]:
        artifact_ids = set([*finding.evidence_ids, *attempt.evidence_ids])
        return [
            SecurityBugEvidenceRef(
                campaign_id=campaign.campaign_id,
                session_id=session_id,
                attempt_id=(
                    attempt.attempt_id
                    if artifact.source_task_id == attempt.task_id
                    else ""
                ),
                artifact_id=artifact.artifact_id,
                source_task_id=artifact.source_task_id,
                created_at=artifact.created_at,
            )
            for artifact in campaign.evidence
            if artifact.artifact_id in artifact_ids
        ]

    def _reproduction_steps(
        self,
        finding: FindingRecord,
        attempt: VerificationAttempt,
        target: str,
        component: str,
    ) -> list[str]:
        if attempt.profile_key == "http_headers_probe":
            return [
                f"From an authorized test environment, send the request shown below to {target}.",
                "Record the HTTP status and response headers without following the redirect.",
                f"Confirm the response omits the {component} header.",
            ]
        return [
            self._replace_evidence_target(step, target)
            for step in finding.reproduction_steps
            if str(step or "").strip()
        ]

    def _reproduction_request(self, attempt: VerificationAttempt, target: str) -> str:
        parsed = urlsplit(target)
        if attempt.profile_key == "http_headers_probe" and parsed.scheme in {"http", "https"}:
            path = parsed.path or "/"
            if parsed.query:
                path = f"{path}?{parsed.query}"
            return (
                f"GET {path} HTTP/1.1\n"
                f"Host: {parsed.netloc}\n"
                "User-Agent: Enterprise-AI-QA-Agent security-regression\n"
                "Connection: close"
            )
        return f"Run registered profile {attempt.profile_key} against {target}."

    def _expected_result(self, finding: FindingRecord, component: str) -> str:
        if finding.category == "missing_control":
            return f"The HTTP response includes the {component} security header."
        return "The recorded security trigger is absent and the expected control remains effective."

    def _business_impact(self, finding: FindingRecord) -> str:
        if finding.category == "missing_control":
            return (
                "Browser-side defense in depth is reduced. The control absence is confirmed, "
                "but exploitability and direct confidentiality, integrity, or availability impact "
                "were not demonstrated by this non-destructive test."
            )
        if finding.verification_level == "impact_verified":
            exposed = ", ".join(finding.exposed_data_types) or "structured impact"
            records = (
                str(finding.exposed_record_estimate)
                if finding.exposed_record_estimate is not None
                else "an unquantified"
            )
            return (
                f"Impact was demonstrated by linked evidence: {exposed}; "
                f"approximately {records} record(s) were exposed. Review the redacted evidence "
                "and affected operations."
            )
        return "The defect is reproducible, but broader business impact was not demonstrated by this test."

    def _impact_details(self, finding: FindingRecord) -> dict[str, object]:
        exposed_data_types = list(
            dict.fromkeys(
                self._sanitize_text(item, limit=120)
                for item in finding.exposed_data_types
                if str(item or "").strip()
            )
        )[:20]
        estimate = finding.exposed_record_estimate
        if isinstance(estimate, bool) or not isinstance(estimate, int) or estimate < 0:
            estimate = None
        levels = {
            "confidentiality_impact": self._impact_level(finding.confidentiality_impact),
            "integrity_impact": self._impact_level(finding.integrity_impact),
            "availability_impact": self._impact_level(finding.availability_impact),
        }
        proof_present = bool(
            exposed_data_types
            or (estimate is not None and estimate > 0)
            or any(value != "none" for value in levels.values())
        )
        return {
            "exposed_data_types": exposed_data_types,
            "exposed_record_estimate": estimate,
            **levels,
            "proof_present": proof_present,
        }

    @staticmethod
    def _impact_level(value: str) -> str:
        normalized = str(value or "none").strip().lower()
        return normalized if normalized in {"none", "low", "medium", "high"} else "none"

    def _cvss(self, finding: FindingRecord) -> tuple[str, float | None, str]:
        if finding.cvss_vector:
            return (
                finding.cvss_vector,
                finding.cvss_score,
                finding.cvss_rationale or "CVSS vector supplied by the normalized finding evidence.",
            )
        if finding.is_baseline_check and finding.category == "missing_control":
            return (
                "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:N",
                0.0,
                "The response-control absence is confirmed, but no exploit or CIA impact was proven; "
                "C/I/A remain None, producing a 0.0 base score. The Finding remains a low-priority "
                "hardening Bug rather than an exploitable vulnerability.",
            )
        return "", finding.cvss_score, finding.cvss_rationale

    def _mappings(self, finding: FindingRecord) -> tuple[list[str], list[str]]:
        cwe_ids = list(finding.cwe_ids)
        owasp = list(finding.owasp_categories)
        if finding.category == "missing_control":
            cwe_ids = list(dict.fromkeys([*cwe_ids, "CWE-693"]))
            owasp = list(dict.fromkeys([*owasp, "OWASP-A05:2021-Security-Misconfiguration"]))
            if self._affected_component(finding) == "x-frame-options":
                cwe_ids = list(dict.fromkeys([*cwe_ids, "CWE-1021"]))
        return cwe_ids, owasp

    def _affected_component(self, finding: FindingRecord) -> str:
        match = re.search(
            r"(?:missing security header|缺少安全响应头)\s*[:：]\s*([a-z0-9-]+)",
            finding.description,
            re.I,
        )
        if match:
            return match.group(1).lower()
        evidence_match = re.search(
            r"\b(?:omitted|missing)\s+([a-z0-9-]+)(?:\s+response)?\s+header\b",
            finding.evidence_summary,
            re.I,
        )
        if evidence_match:
            return evidence_match.group(1).lower()
        if finding.affected_service:
            return finding.affected_service.strip().lower()
        if finding.affected_port:
            return f"port:{finding.affected_port}"
        return re.sub(r"\s+", "-", finding.title.strip().lower())[:120]

    def _normalized_trigger(self, finding: FindingRecord) -> str:
        return "|".join(
            (
                self._affected_component(finding),
                re.sub(r"\s+", " ", finding.description.strip().casefold()),
            )
        )

    def _fingerprint(self, *, target: str, category: str, component: str, trigger: str) -> str:
        value = "|".join((target.casefold(), category.casefold(), component.casefold(), trigger))
        return hashlib.sha256(value.encode("utf-8")).hexdigest()

    def _canonical_target(self, value: str) -> str:
        raw = str(value or "").strip()
        parsed = urlsplit(raw)
        if parsed.scheme and parsed.netloc:
            path = parsed.path.rstrip("/") or ""
            return urlunsplit((parsed.scheme.lower(), parsed.netloc.lower(), path, parsed.query, ""))
        return raw.rstrip("/").casefold()

    def _replace_evidence_target(self, step: str, target: str) -> str:
        value = re.sub(r"https?://host\.docker\.internal(?::\d+)?(?:/[^\s]*)?", target, str(step))
        return self._sanitize_text(value, limit=1000)

    def _sanitize_text(self, value: str, *, limit: int) -> str:
        sanitized, _ = self._output_safety.sanitize_text(str(value or ""))
        return sanitized[:limit]

    def _stable_hash(self, value: str) -> str:
        return hashlib.sha256(value.encode("utf-8")).hexdigest()[:20]

    def _log_event(self, event_type: str, bug: SecurityBugRecord, **payload: object) -> None:
        logger.info(
            "%s %s",
            event_type,
            json.dumps(
                {
                    "bug_id": bug.bug_id,
                    "fingerprint": bug.fingerprint,
                    "status": bug.status,
                    **payload,
                },
                ensure_ascii=False,
                separators=(",", ":"),
                default=str,
            ),
        )


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


__all__ = ["SecurityBugService"]
