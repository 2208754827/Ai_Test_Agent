"""HTML rendering helpers for Security Testing Mode reports."""
from __future__ import annotations

from typing import Any

from src.application.reporting.report_template_service import ReportTemplateService
from src.modes.security_testing_mode.campaign_state import SecurityReport


class SecurityReportTemplate:
    """Render a security report through the shared report template service."""

    template_key = "security_testing_full"

    def __init__(self, template_service: ReportTemplateService | None = None) -> None:
        self._template_service = template_service or ReportTemplateService()

    def render(
        self,
        *,
        report: SecurityReport,
        markdown_content: str,
        sender: str = "security-testing-agent",
    ) -> str:
        """Return a complete HTML report for the given security report."""
        return self._template_service.render_report_html(
            title=report.title or "安全测试报告",
            time_label=report.generated_at or report.tested_at,
            sender=sender,
            markdown_content=markdown_content,
            template_key=self.template_key,
            template_context=self.build_template_context(report),
        )

    def build_template_context(self, report: SecurityReport) -> dict[str, Any]:
        """Build presentation metrics consumed by the HTML template."""
        return {
            "campaign_id": report.campaign_id,
            "target_summary": report.target_summary,
            "scope_description": report.scope_description,
            "total_tasks": report.total_tasks,
            "completed_tasks": report.completed_tasks,
            "failed_tasks": report.failed_tasks,
            "skipped_tasks": report.skipped_tasks,
            "total_findings": report.total_findings,
            "security_bug_count": report.security_bug_count,
            "reproduced_bug_count": report.reproduced_bug_count,
            "fixed_bug_count": report.fixed_bug_count,
            "critical_count": report.critical_count,
            "high_count": report.high_count,
            "medium_count": report.medium_count,
            "low_count": report.low_count,
            "info_count": report.info_count,
            "assets_discovered": report.assets_discovered,
            "services_discovered": report.services_discovered,
            "evidence_count": report.evidence_count,
            "execution_record_count": report.execution_record_count,
            "duration_seconds": report.duration_seconds,
        }


__all__ = ["SecurityReportTemplate"]
