"""Security Testing Mode verification policy.

The verification layer is intentionally separate from task execution. It checks
whether the campaign produced enough structured evidence to trust the report,
instead of accepting worker or scanner summaries at face value.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from src.modes.security_testing_mode.campaign_state import SecurityCampaign, SecurityReport, SecurityTask
from src.modes.security_testing_mode.contracts import TASK_COMPLETED, TASK_FAILED, TASK_SKIPPED


@dataclass
class SecurityVerificationRule:
    """One verification rule result."""

    rule_id: str
    name: str
    passed: bool
    severity: str = "error"  # error / warning / info
    expected: Any = None
    actual: Any = None
    description: str = ""
    affected_tasks: list[str] = field(default_factory=list)
    affected_findings: list[str] = field(default_factory=list)


@dataclass
class SecurityVerificationVerdict:
    """Final verification verdict for a security campaign."""

    passed: bool
    verdict: str  # approved / warning / rejected
    summary: str
    rules: list[SecurityVerificationRule] = field(default_factory=list)
    evidence_count: int = 0
    execution_record_count: int = 0
    total_rules: int = 0
    failed_rules: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "verdict": self.verdict,
            "summary": self.summary,
            "evidence_count": self.evidence_count,
            "execution_record_count": self.execution_record_count,
            "total_rules": self.total_rules,
            "failed_rules": self.failed_rules,
            "rules": [
                {
                    "rule_id": rule.rule_id,
                    "name": rule.name,
                    "passed": rule.passed,
                    "severity": rule.severity,
                    "expected": rule.expected,
                    "actual": rule.actual,
                    "description": rule.description,
                    "affected_tasks": rule.affected_tasks,
                    "affected_findings": rule.affected_findings,
                }
                for rule in self.rules
            ],
        }


class SecurityTestingVerificationPolicy:
    """Evaluate whether campaign evidence is sufficient for report conclusions."""

    def verify(
        self,
        *,
        campaign: SecurityCampaign,
        report: SecurityReport | None = None,
    ) -> SecurityVerificationVerdict:
        rules = [
            self._check_tasks_executed(campaign.tasks),
            self._check_execution_records(campaign),
            self._check_evidence_for_findings(campaign),
            self._check_security_bug_quality(campaign),
            self._check_exploit_workspace_quality(campaign),
            self._check_tool_bootstrap_quality(campaign),
            self._check_high_risk_findings_have_recommendations(campaign),
            self._check_failed_tasks_have_errors(campaign.tasks),
        ]
        error_rules = [rule for rule in rules if not rule.passed and rule.severity == "error"]
        warning_rules = [rule for rule in rules if not rule.passed and rule.severity == "warning"]
        if error_rules:
            verdict = "rejected"
            passed = False
        elif warning_rules:
            verdict = "warning"
            passed = True
        else:
            verdict = "approved"
            passed = True

        return SecurityVerificationVerdict(
            passed=passed,
            verdict=verdict,
            summary=self._build_summary(verdict, rules, campaign),
            rules=rules,
            evidence_count=len(campaign.evidence),
            execution_record_count=len(campaign.execution_records),
            total_rules=len(rules),
            failed_rules=len(error_rules),
        )

    def _check_tasks_executed(self, tasks: list[SecurityTask]) -> SecurityVerificationRule:
        executed = [task for task in tasks if task.status in {TASK_COMPLETED, TASK_FAILED, TASK_SKIPPED}]
        passed = bool(tasks) and len(executed) == len(tasks)
        return SecurityVerificationRule(
            rule_id="tasks_settled",
            name="All Planned Tasks Settled",
            passed=passed,
            severity="error",
            expected=len(tasks),
            actual=len(executed),
            description=(
                f"{len(executed)}/{len(tasks)} planned task(s) reached a terminal state."
                if tasks
                else "No security tasks were planned."
            ),
        )

    def _check_execution_records(self, campaign: SecurityCampaign) -> SecurityVerificationRule:
        terminal_task_ids = {
            task.task_id
            for task in campaign.tasks
            if task.status in {TASK_COMPLETED, TASK_FAILED}
        }
        recorded_task_ids = {record.task_id for record in campaign.execution_records}
        missing = sorted(terminal_task_ids - recorded_task_ids)
        return SecurityVerificationRule(
            rule_id="execution_records",
            name="Tool Execution Records",
            passed=not missing,
            severity="error",
            expected=f"records for {len(terminal_task_ids)} terminal task(s)",
            actual=f"{len(recorded_task_ids & terminal_task_ids)} recorded",
            description=(
                "Every completed or failed security task has an auditable tool execution record."
                if not missing
                else f"Missing execution records for task(s): {', '.join(missing)}."
            ),
            affected_tasks=missing,
        )

    def _check_evidence_for_findings(self, campaign: SecurityCampaign) -> SecurityVerificationRule:
        if not campaign.findings:
            return SecurityVerificationRule(
                rule_id="finding_evidence",
                name="Finding Evidence",
                passed=True,
                severity="info",
                description="No findings were produced, so finding evidence linkage is not required.",
            )
        evidence_task_ids = {item.source_task_id for item in campaign.evidence if item.source_task_id}
        missing = [
            finding.finding_id or finding.title
            for finding in campaign.findings
            if not finding.evidence_summary and not (set(finding.source_task_ids) & evidence_task_ids)
        ]
        return SecurityVerificationRule(
            rule_id="finding_evidence",
            name="Finding Evidence",
            passed=not missing,
            severity="error",
            expected="evidence summary or task evidence for every finding",
            actual=f"{len(campaign.findings) - len(missing)}/{len(campaign.findings)} linked",
            description=(
                "Every finding is linked to evidence or contains an evidence summary."
                if not missing
                else f"{len(missing)} finding(s) lack evidence linkage."
            ),
            affected_findings=[str(item) for item in missing],
        )

    def _check_high_risk_findings_have_recommendations(
        self,
        campaign: SecurityCampaign,
    ) -> SecurityVerificationRule:
        high_risk = [
            finding
            for finding in campaign.findings
            if finding.severity in {"critical", "high"}
        ]
        missing = [
            finding.finding_id or finding.title
            for finding in high_risk
            if not finding.recommendation.strip()
        ]
        return SecurityVerificationRule(
            rule_id="high_risk_remediation",
            name="High Risk Remediation Guidance",
            passed=not missing,
            severity="warning",
            expected="recommendation for every high/critical finding",
            actual=f"{len(high_risk) - len(missing)}/{len(high_risk)} with recommendation",
            description=(
                "High and critical findings include remediation guidance."
                if not missing
                else f"{len(missing)} high/critical finding(s) lack remediation guidance."
            ),
            affected_findings=[str(item) for item in missing],
        )

    def _check_security_bug_quality(
        self,
        campaign: SecurityCampaign,
    ) -> SecurityVerificationRule:
        eligible_finding_ids = {
            finding_id
            for attempt in campaign.verification_attempts
            if attempt.status == "succeeded" and attempt.evidence_ids
            for finding_id in attempt.finding_ids
        }
        if not eligible_finding_ids:
            return SecurityVerificationRule(
                rule_id="security_bug_quality",
                name="Reproducible Security Bug Quality",
                passed=True,
                severity="info",
                description=(
                    "No succeeded evidence-backed verification attempts were available for Bug promotion."
                ),
            )
        covered_finding_ids = {
            finding_id
            for bug in campaign.security_bugs
            for finding_id in bug.finding_ids
        }
        missing = sorted(eligible_finding_ids - covered_finding_ids)
        invalid: list[str] = []
        for bug in campaign.security_bugs:
            required_values = (
                bug.bug_id,
                bug.fingerprint,
                bug.affected_target,
                bug.affected_component,
                bug.preconditions,
                bug.reproduction_steps,
                bug.reproduction_request,
                bug.expected_result,
                bug.actual_result,
                bug.evidence_refs,
                bug.cvss_vector,
                bug.cvss_rationale,
                bug.cwe_ids,
                bug.owasp_categories,
                bug.regression_case_id,
                bug.retest_history,
            )
            if not all(required_values):
                invalid.append(bug.bug_id or bug.fingerprint or "unknown")
        passed = not missing and not invalid
        return SecurityVerificationRule(
            rule_id="security_bug_quality",
            name="Reproducible Security Bug Quality",
            passed=passed,
            severity="error",
            expected=(
                "every succeeded verified Finding has one complete, traceable, reproducible Bug record"
            ),
            actual=(
                f"{len(eligible_finding_ids) - len(missing)}/{len(eligible_finding_ids)} "
                f"finding(s) covered; {len(invalid)} invalid Bug record(s)"
            ),
            description=(
                "All promoted Security Bugs satisfy reproduction, mapping, CVSS, evidence and retest-history gates."
                if passed
                else (
                    f"Missing Bug coverage for {len(missing)} finding(s); "
                    f"{len(invalid)} Bug record(s) have incomplete required fields."
                )
            ),
            affected_findings=missing,
        )

    def _check_failed_tasks_have_errors(self, tasks: list[SecurityTask]) -> SecurityVerificationRule:
        failed = [task for task in tasks if task.status == TASK_FAILED]
        missing = [task.task_id for task in failed if not task.last_error and not task.result_summary]
        return SecurityVerificationRule(
            rule_id="failed_task_errors",
            name="Failed Task Error Classification",
            passed=not missing,
            severity="warning",
            expected="error or summary for every failed task",
            actual=f"{len(failed) - len(missing)}/{len(failed)} classified",
            description=(
                "Failed tasks include error summaries."
                if not missing
                else f"{len(missing)} failed task(s) lack error detail."
            ),
            affected_tasks=missing,
        )

    def _check_exploit_workspace_quality(
        self,
        campaign: SecurityCampaign,
    ) -> SecurityVerificationRule:
        if not campaign.exploit_workspaces:
            return SecurityVerificationRule(
                rule_id="exploit_workspace_quality",
                name="Exploit Workspace Quality",
                passed=True,
                severity="info",
                description="No P2 Exploit Coder workspace was requested or executed.",
            )
        invalid: list[str] = []
        for workspace in campaign.exploit_workspaces:
            if workspace.status == "completed":
                required = (
                    workspace.hypothesis_id,
                    workspace.target,
                    workspace.source_hash,
                    workspace.artifact_hash,
                    workspace.static_check_status == "passed",
                    workspace.compile_command,
                    workspace.compile_exit_code == 0,
                    workspace.execute_command,
                    workspace.execute_exit_code == 0,
                    workspace.impact_verdict,
                    workspace.cleanup_complete,
                )
            else:
                required = (
                    workspace.hypothesis_id,
                    workspace.failure_category,
                    workspace.failure_reason,
                    workspace.cleanup_complete,
                )
            if not all(required):
                invalid.append(workspace.workspace_id or workspace.hypothesis_id or "unknown")
        return SecurityVerificationRule(
            rule_id="exploit_workspace_quality",
            name="Exploit Workspace Quality",
            passed=not invalid,
            severity="error",
            expected="every P2 workspace has hashes or a classified failure and proves cleanup",
            actual=f"{len(campaign.exploit_workspaces) - len(invalid)}/{len(campaign.exploit_workspaces)} valid",
            description=(
                "P2 workspaces preserve source/build/execution evidence and cleanup proof."
                if not invalid
                else f"Invalid P2 workspace record(s): {', '.join(invalid)}."
            ),
        )

    def _check_tool_bootstrap_quality(
        self,
        campaign: SecurityCampaign,
    ) -> SecurityVerificationRule:
        records = list(campaign.tool_bootstraps or [])
        if not records:
            return SecurityVerificationRule(
                rule_id="tool_bootstrap_quality",
                name="P4 Tool Bootstrap Auditability",
                passed=True,
                severity="info",
                description="No P4 temporary-tool bootstrap was requested.",
            )
        invalid: list[str] = []
        for record in records:
            terminal = record.status in {"already_available", "completed", "failed"}
            has_manifest = bool(str(record.manifest_path or "").strip())
            if not terminal or not has_manifest or not record.cleanup_complete:
                invalid.append(record.bootstrap_id or record.tool_name or "unknown")
        return SecurityVerificationRule(
            rule_id="tool_bootstrap_quality",
            name="P4 Tool Bootstrap Auditability",
            passed=not invalid,
            severity="error",
            expected="terminal manifest-backed P4 record with completed cleanup",
            actual=f"{len(records) - len(invalid)}/{len(records)} compliant",
            description=(
                "Every P4 record is terminal, points to a manifest, and confirms temporary container cleanup."
                if not invalid
                else f"P4 records missing terminal audit/cleanup guarantees: {', '.join(invalid)}."
            ),
            affected_tasks=invalid,
        )

    def _build_summary(
        self,
        verdict: str,
        rules: list[SecurityVerificationRule],
        campaign: SecurityCampaign,
    ) -> str:
        passed_rules = sum(1 for rule in rules if rule.passed)
        finding_count = len(campaign.findings)
        if verdict == "approved":
            return f"Security campaign evidence approved: {passed_rules}/{len(rules)} rules passed; {finding_count} finding(s)."
        if verdict == "warning":
            return f"Security campaign evidence passed with warnings: {passed_rules}/{len(rules)} rules passed; {finding_count} finding(s)."
        failed = [rule.name for rule in rules if not rule.passed and rule.severity == "error"]
        return f"Security campaign evidence rejected: {', '.join(failed)} failed."


SECURITY_TESTING_VERIFICATION = {"policy": "security_evidence_quality_gate"}


__all__ = [
    "SecurityTestingVerificationPolicy",
    "SecurityVerificationRule",
    "SecurityVerificationVerdict",
    "SECURITY_TESTING_VERIFICATION",
]
