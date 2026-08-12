"""Security Testing Mode evaluation policy.

Evaluation turns raw scanner execution into a campaign-quality assessment. This
is not a "target is secure" grade; it is a confidence score for the test run.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from src.modes.security_testing_mode.campaign_state import SecurityCampaign, SecurityReport, SecurityTask
from src.modes.security_testing_mode.contracts import TASK_COMPLETED, TASK_FAILED, TASK_SKIPPED
from src.modes.security_testing_mode.verification import SecurityVerificationVerdict


@dataclass
class SecurityFailureClassification:
    """Structured classification for a failed security task."""

    task_id: str
    task_name: str
    severity: str
    category: str
    description: str
    command_profile: str = ""
    target: str = ""
    is_transient: bool = False


@dataclass
class SecurityCoverageMetrics:
    """Coverage of the planned security surface."""

    total_tasks: int = 0
    executed_tasks: int = 0
    completed_tasks: int = 0
    coverage_rate: float = 0.0
    surface_types: list[str] = field(default_factory=list)
    tool_families: list[str] = field(default_factory=list)


@dataclass
class SecurityQualityScore:
    """Confidence score for the campaign execution quality."""

    overall: float = 0.0
    execution: float = 0.0
    evidence: float = 0.0
    verification: float = 0.0
    coverage: float = 0.0
    grade: str = "F"


@dataclass
class SecurityEvaluationResult:
    """Complete security campaign evaluation output."""

    campaign_id: str
    quality_score: SecurityQualityScore
    coverage: SecurityCoverageMetrics
    failure_classifications: list[SecurityFailureClassification] = field(default_factory=list)
    risk_summary: dict[str, int] = field(default_factory=dict)
    verification_verdict: SecurityVerificationVerdict | None = None
    recommendations: list[str] = field(default_factory=list)
    summary: str = ""

    def to_dict(self) -> dict[str, Any]:
        overall_rounded = round(self.quality_score.overall, 1)
        return {
            "campaign_id": self.campaign_id,
            "quality_score": {
                # ``score`` is an alias of ``overall`` so UI consumers that
                # look for the conventional ``score`` field find it. Keep
                # ``overall`` for backward compatibility with existing
                # callers/tests.
                "score": overall_rounded,
                "overall": overall_rounded,
                "execution": round(self.quality_score.execution, 1),
                "evidence": round(self.quality_score.evidence, 1),
                "verification": round(self.quality_score.verification, 1),
                "coverage": round(self.quality_score.coverage, 1),
                "grade": self.quality_score.grade,
            },
            "coverage": {
                "total_tasks": self.coverage.total_tasks,
                "executed_tasks": self.coverage.executed_tasks,
                "completed_tasks": self.coverage.completed_tasks,
                "coverage_rate": round(self.coverage.coverage_rate, 4),
                "surface_types": self.coverage.surface_types,
                "tool_families": self.coverage.tool_families,
            },
            "failure_classifications": [
                {
                    "task_id": item.task_id,
                    "task_name": item.task_name,
                    "severity": item.severity,
                    "category": item.category,
                    "description": item.description,
                    "command_profile": item.command_profile,
                    "target": item.target,
                    "is_transient": item.is_transient,
                }
                for item in self.failure_classifications
            ],
            "risk_summary": dict(self.risk_summary),
            "verification_verdict": self.verification_verdict.to_dict() if self.verification_verdict else None,
            "recommendations": self.recommendations,
            "summary": self.summary,
        }


class SecurityTestingEvaluationPolicy:
    """Evaluate execution quality, coverage, and failure categories."""

    def evaluate(
        self,
        *,
        campaign: SecurityCampaign,
        report: SecurityReport | None = None,
        verification_verdict: SecurityVerificationVerdict | None = None,
    ) -> SecurityEvaluationResult:
        classifications = self._classify_failures(campaign.tasks)
        coverage = self._compute_coverage(campaign.tasks)
        risk_summary = self._risk_summary(campaign)
        quality_score = self._compute_quality_score(
            campaign=campaign,
            coverage=coverage,
            verification_verdict=verification_verdict,
        )
        recommendations = self._recommendations(
            campaign=campaign,
            classifications=classifications,
            quality_score=quality_score,
        )
        summary = self._summary(quality_score, coverage, risk_summary, classifications)
        return SecurityEvaluationResult(
            campaign_id=campaign.campaign_id,
            quality_score=quality_score,
            coverage=coverage,
            failure_classifications=classifications,
            risk_summary=risk_summary,
            verification_verdict=verification_verdict,
            recommendations=recommendations,
            summary=summary,
        )

    def _classify_failures(self, tasks: list[SecurityTask]) -> list[SecurityFailureClassification]:
        classifications: list[SecurityFailureClassification] = []
        for task in tasks:
            if task.status != TASK_FAILED:
                continue
            category, severity, transient = self._categorize_failure(task)
            classifications.append(
                SecurityFailureClassification(
                    task_id=task.task_id,
                    task_name=task.name,
                    severity=severity,
                    category=category,
                    description=task.last_error or task.result_summary or "Security task failed.",
                    command_profile=task.command_profile,
                    target=task.target,
                    is_transient=transient,
                )
            )
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        classifications.sort(key=lambda item: order.get(item.severity, 5))
        return classifications

    def _categorize_failure(self, task: SecurityTask) -> tuple[str, str, bool]:
        analysis = task.failure_analysis if isinstance(task.failure_analysis, dict) else {}
        analysis_category = str(analysis.get("failure_category") or "").strip().lower()
        if analysis_category in {
            "environment_limited",
            "environment",
            "network_unreachable",
            "target_unreachable",
            "网络不可达",
        }:
            return "environment_limited", "low", False
        text = " ".join(
            str(value or "")
            for value in (
                task.last_error,
                task.result_summary,
                task.raw_output,
                analysis.get("root_cause"),
                analysis.get("notes"),
            )
        ).lower()
        if "approval" in text or "denied" in text:
            return "approval_or_policy", "high", False
        if "timeout" in text or "timed out" in text:
            return "timeout", "medium", True
        if any(
            token in text
            for token in (
                "network is unreachable",
                "connection refused",
                "could not connect",
                "failed to connect",
                "no route to host",
                "name or service not known",
                "target_response_not_observed",
                "网络不可达",
            )
        ):
            return "environment_limited", "low", False
        if "not installed" in text or "not on path" in text or "docker" in text:
            return "environment", "medium", True
        if "parser" in text or "parse" in text:
            return "parser", "low", False
        if "exit_code" in text or "exit code" in text:
            return "tool_exit", "medium", True
        return "unknown", "medium", False

    def _compute_coverage(self, tasks: list[SecurityTask]) -> SecurityCoverageMetrics:
        terminal = [task for task in tasks if task.status in {TASK_COMPLETED, TASK_FAILED, TASK_SKIPPED}]
        completed = [task for task in tasks if task.status == TASK_COMPLETED]
        total = len(tasks)
        return SecurityCoverageMetrics(
            total_tasks=total,
            executed_tasks=len([task for task in terminal if task.status != TASK_SKIPPED]),
            completed_tasks=len(completed),
            coverage_rate=(len(terminal) / total) if total else 0.0,
            surface_types=sorted({task.surface_type for task in tasks if task.surface_type}),
            tool_families=sorted({task.tool_family for task in tasks if task.tool_family}),
        )

    def _risk_summary(self, campaign: SecurityCampaign) -> dict[str, int]:
        severities = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for finding in campaign.findings:
            key = finding.severity if finding.severity in severities else "info"
            severities[key] += 1
        return severities

    def _compute_quality_score(
        self,
        *,
        campaign: SecurityCampaign,
        coverage: SecurityCoverageMetrics,
        verification_verdict: SecurityVerificationVerdict | None,
    ) -> SecurityQualityScore:
        total = max(1, len(campaign.tasks))
        completed = sum(1 for task in campaign.tasks if task.status == TASK_COMPLETED)
        execution = (completed / total) * 35.0
        evidence = min(25.0, (len(campaign.evidence) / total) * 25.0)
        verification = 25.0 if verification_verdict and verification_verdict.passed else 0.0
        coverage_score = coverage.coverage_rate * 15.0
        overall = max(0.0, min(100.0, execution + evidence + verification + coverage_score))
        return SecurityQualityScore(
            overall=overall,
            execution=execution,
            evidence=evidence,
            verification=verification,
            coverage=coverage_score,
            grade=self._grade(overall),
        )

    def _grade(self, score: float) -> str:
        if score >= 90:
            return "A"
        if score >= 80:
            return "B"
        if score >= 70:
            return "C"
        if score >= 60:
            return "D"
        return "F"

    def _recommendations(
        self,
        *,
        campaign: SecurityCampaign,
        classifications: list[SecurityFailureClassification],
        quality_score: SecurityQualityScore,
    ) -> list[str]:
        recommendations: list[str] = []
        if classifications:
            transient = sum(1 for item in classifications if item.is_transient)
            if transient:
                recommendations.append(f"Retry or re-run {transient} transient security task failure(s) after checking environment/tool availability.")
            policy = [item for item in classifications if item.category == "approval_or_policy"]
            if policy:
                recommendations.append("Review approval and risk policy settings before enabling higher-risk security profiles.")
        if campaign.findings:
            recommendations.append("Prioritize remediation by severity and validate high/critical findings with evidence before remediation tracking.")
        if quality_score.evidence < 15:
            recommendations.append("Increase evidence capture or parser coverage so every task contributes auditable output.")
        if not recommendations:
            recommendations.append("Security campaign evidence quality is acceptable; archive report artifacts and monitor for drift.")
        return recommendations

    def _summary(
        self,
        quality_score: SecurityQualityScore,
        coverage: SecurityCoverageMetrics,
        risk_summary: dict[str, int],
        classifications: list[SecurityFailureClassification],
    ) -> str:
        return (
            f"Security campaign confidence score: {quality_score.overall:.0f}/100 "
            f"(grade {quality_score.grade}); coverage {coverage.coverage_rate:.0%}; "
            f"critical/high findings: {risk_summary.get('critical', 0)}/{risk_summary.get('high', 0)}; "
            f"failed tasks classified: {len(classifications)}."
        )


SECURITY_TESTING_EVALUATION = {"policy": "security_campaign_quality_score"}


__all__ = [
    "SecurityTestingEvaluationPolicy",
    "SecurityEvaluationResult",
    "SecurityQualityScore",
    "SecurityCoverageMetrics",
    "SecurityFailureClassification",
    "SECURITY_TESTING_EVALUATION",
]
