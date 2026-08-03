"""Security Testing Mode report builder."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from src.modes.security_testing_mode.campaign_state import (
    FindingRecord,
    SecurityBugRecord,
    SecurityCampaign,
    SecurityReport,
)
from src.modes.security_testing_mode.contracts import (
    RISK_CRITICAL,
    RISK_HIGH,
    RISK_INFO,
    RISK_LOW,
    RISK_MEDIUM,
    SEVERITY_ORDER,
    TASK_COMPLETED,
    TASK_FAILED,
    TASK_SKIPPED,
)


class SecurityReportBuilder:
    """Build structured, Markdown, and artifact security reports."""

    def build_report(self, campaign: SecurityCampaign) -> SecurityReport:
        findings = list(campaign.findings or [])
        hypotheses = list(campaign.vulnerability_hypotheses or [])
        attempts = list(campaign.verification_attempts or [])
        security_bugs = list(campaign.security_bugs or [])
        tasks = list(campaign.tasks or [])
        tool_bootstraps = list(campaign.tool_bootstraps or [])
        threat_intelligence = list(campaign.threat_intelligence or [])

        completed = sum(1 for task in tasks if task.status == TASK_COMPLETED)
        failed = sum(1 for task in tasks if task.status == TASK_FAILED)
        skipped = sum(1 for task in tasks if task.status == TASK_SKIPPED)

        severity_counts = {
            RISK_CRITICAL: sum(1 for item in findings if item.severity == RISK_CRITICAL),
            RISK_HIGH: sum(1 for item in findings if item.severity == RISK_HIGH),
            RISK_MEDIUM: sum(1 for item in findings if item.severity == RISK_MEDIUM),
            RISK_LOW: sum(1 for item in findings if item.severity == RISK_LOW),
            RISK_INFO: sum(1 for item in findings if item.severity == RISK_INFO),
        }

        duration = self._duration_seconds(campaign.created_at, campaign.updated_at)
        target_summary = self._target_summary(campaign)
        recommendations = self._build_recommendations(findings)
        limitations = self._build_limitations(
            failed_tasks=[task for task in tasks if task.status == TASK_FAILED],
            skipped=skipped,
            operational_constraints=list(campaign.operational_constraints or []),
            findings=findings,
            hypotheses=hypotheses,
            attempts=attempts,
        )

        return SecurityReport(
            campaign_id=campaign.campaign_id,
            title=f"安全测试报告 - {target_summary[:80] or campaign.campaign_id[:8]}",
            target_summary=target_summary,
            scope_description=campaign.scope_notes or campaign.objective,
            executive_summary=self._build_executive_summary(
                findings=findings,
                completed=completed,
                failed=failed,
                critical=severity_counts[RISK_CRITICAL],
                high=severity_counts[RISK_HIGH],
                medium=severity_counts[RISK_MEDIUM],
                hypotheses=hypotheses,
                attempts=attempts,
                security_bugs=security_bugs,
            ),
            total_tasks=len(tasks),
            completed_tasks=completed,
            failed_tasks=failed,
            skipped_tasks=skipped,
            total_findings=len(findings),
            critical_count=severity_counts[RISK_CRITICAL],
            high_count=severity_counts[RISK_HIGH],
            medium_count=severity_counts[RISK_MEDIUM],
            low_count=severity_counts[RISK_LOW],
            info_count=severity_counts[RISK_INFO],
            findings=findings,
            hypotheses=hypotheses,
            verification_attempts=attempts,
            security_bugs=security_bugs,
            hypothesis_count=len(hypotheses),
            verification_attempt_count=len(attempts),
            security_bug_count=len(security_bugs),
            reproduced_bug_count=sum(
                1 for item in security_bugs if item.status in {"confirmed", "retest_failed"}
            ),
            fixed_bug_count=sum(1 for item in security_bugs if item.status == "closed"),
            retest_failed_bug_count=sum(
                1 for item in security_bugs if item.status == "retest_failed"
            ),
            verified_exploitable_count=sum(
                1 for item in hypotheses if item.result_class == "verified_exploitable"
            ),
            impact_verified_count=sum(
                1 for item in hypotheses if item.result_class == "impact_verified"
            ),
            blocked_by_control_count=sum(
                1 for item in attempts if item.result_class == "blocked_by_control"
            ),
            activities=list(campaign.activities or []),
            assets_discovered=len(campaign.assets or []),
            services_discovered=len(campaign.fingerprints or []),
            evidence_count=len(campaign.evidence or []),
            execution_record_count=len(campaign.execution_records or []),
            shell_session=campaign.shell_session,
            exploit_workspaces=list(campaign.exploit_workspaces or []),
            exploit_workspace_count=len(campaign.exploit_workspaces or []),
            exploit_workspace_completed_count=sum(
                1 for item in campaign.exploit_workspaces or [] if item.status == "completed"
            ),
            tool_bootstraps=tool_bootstraps,
            tool_bootstrap_count=len(tool_bootstraps),
            tool_bootstrap_completed_count=sum(
                1 for item in tool_bootstraps if item.status in {"already_available", "completed"}
            ),
            threat_intelligence=threat_intelligence,
            threat_intelligence_count=len(threat_intelligence),
            callback_leases=list(campaign.callback_leases or []),
            callback_lease_count=len(campaign.callback_leases or []),
            graph_persistence=campaign.graph_persistence,
            duration_seconds=duration,
            tested_at=campaign.created_at,
            generated_at=datetime.now(timezone.utc).isoformat(),
            recommendations=recommendations,
            limitations=limitations,
        )

    def build_markdown(self, report: SecurityReport) -> str:
        lines: list[str] = [
            f"# {report.title}",
            "",
            f"**报告名称**：{report.title}",
            f"**生成日期**：{self._date_part(report.generated_at)}",
            f"**生成时间**：{self._time_part(report.generated_at)}",
            f"**测试目标**：{report.target_summary}",
            f"**执行耗时**：{report.duration_seconds:.0f} 秒",
            "",
            "## 执行摘要",
            "",
            report.executive_summary or "本次运行未生成摘要。",
            "",
            "## 测试结果",
            "",
            f"- 任务总数：{report.total_tasks}",
            f"- 已完成：{report.completed_tasks}",
            f"- 失败：{report.failed_tasks}",
            f"- 跳过：{report.skipped_tasks}",
            f"- 发现资产：{report.assets_discovered}",
            f"- 发现服务：{report.services_discovered}",
            f"- 执行记录：{report.execution_record_count}",
            f"- 证据产物：{report.evidence_count}",
            f"- 漏洞假设：{report.hypothesis_count}",
            f"- 验证尝试：{report.verification_attempt_count}",
            f"- Security Bug：{report.security_bug_count}",
            f"- 复测仍存在：{report.reproduced_bug_count}",
            f"- 复测已关闭：{report.fixed_bug_count}",
            "",
            "## 风险等级概览",
            "",
            "| 风险等级 | 数量 |",
            "|---|---:|",
            f"| 严重 | {report.critical_count} |",
            f"| 高危 | {report.high_count} |",
            f"| 中危 | {report.medium_count} |",
            f"| 低危 | {report.low_count} |",
            f"| 信息 | {report.info_count} |",
            "",
            "## Agent 执行情况",
            "",
        ]

        if report.activities:
            lines.extend([
                f"执行策略：{self._execution_strategy(report.activities)}",
                "",
                "| Agent | 任务 | 动作 | 执行模式 | 执行内容 |",
                "|---|---|---|---|---|",
            ])
            for activity in report.activities:
                lines.append(
                    f"| {activity.agent_name or activity.agent_key} | "
                    f"{activity.task_id} | {activity.action} | "
                    f"{activity.execution_mode or 'unknown'} | "
                    f"{self._table_text(activity.summary or activity.notes)} |"
                )
        else:
            lines.append("未记录到 worker 执行活动。")

        lines.extend(["", "## 发现、风险与错误", ""])
        if report.findings:
            for index, finding in enumerate(self._sort_findings(report.findings), start=1):
                lines.extend(self._render_finding_markdown(index, finding))
                lines.append("")
        else:
            lines.append("本次运行未产生已验证的安全发现。")
            lines.append("")

        lines.extend(["## 攻击链验证", ""])
        if report.verification_attempts:
            lines.extend([
                "| Attempt | Hypothesis | Profile | 状态 | 结论 | 审批 | 清理 | Evidence |",
                "|---|---|---|---|---|---|---|---:|",
            ])
            for attempt in report.verification_attempts:
                lines.append(
                    f"| {attempt.attempt_id} | {', '.join(attempt.hypothesis_ids)} | "
                    f"{attempt.profile_key} | {attempt.status} | {attempt.result_class} | "
                    f"{attempt.approval_status} | {attempt.cleanup_status} | "
                    f"{len(attempt.evidence_ids)} |"
                )
        elif report.hypotheses:
            lines.append("已生成漏洞假设，但没有可执行且通过证据门的验证尝试。")
        else:
            lines.append("本次运行没有证据支持的漏洞假设，因此未执行验证尝试。")
        lines.append("")

        lines.extend(["## Exploit Coder 与影响验证", ""])
        if report.exploit_workspaces:
            lines.extend([
                f"- Workspace 数量：{report.exploit_workspace_count}",
                f"- 成功完成：{report.exploit_workspace_completed_count}",
                "",
                "| Workspace | Hypothesis | 状态 | 静态检查 | 编译退出码 | 执行退出码 | Source Hash | Artifact Hash | Impact | 清理 |",
                "|---|---|---|---|---:|---:|---|---|---|---|",
            ])
            for workspace in report.exploit_workspaces:
                lines.append(
                    f"| {workspace.workspace_id} | {workspace.hypothesis_id} | {workspace.status} | "
                    f"{workspace.static_check_status} | {workspace.compile_exit_code if workspace.compile_exit_code is not None else ''} | "
                    f"{workspace.execute_exit_code if workspace.execute_exit_code is not None else ''} | "
                    f"`{workspace.source_hash[:16]}` | `{workspace.artifact_hash[:16]}` | "
                    f"{self._table_text(workspace.impact_verdict)} | "
                    f"{'完成' if workspace.cleanup_complete else '未完成'} |"
                )
                if workspace.failure_reason:
                    lines.append(f"  - 失败分类：`{workspace.failure_category}`；{self._table_text(workspace.failure_reason)}")
        else:
            lines.append("本次运行未请求或未执行 P2 Exploit Coder 工作区。")
        lines.append("")

        lines.extend(["## 安全情报与假设来源", ""])
        if report.threat_intelligence:
            lines.extend([
                f"- 情报记录：{report.threat_intelligence_count}",
                "- 情报只作为风险依据或候选假设来源；未达到 `lab_verified + evidence` 前不得直接执行。",
                "",
                "| Intelligence | 来源 | 类型 | 可信度 | 匹配状态 | CVE/CWE | Hash |",
                "|---|---|---|---|---|---|---|",
            ])
            for record in report.threat_intelligence:
                references = ", ".join([*record.cve_ids, *record.cwe_ids])
                lines.append(
                    f"| {self._table_text(record.title)} | {self._table_text(record.source_url)} | "
                    f"{record.source_type or 'unknown'} | {record.confidence} | "
                    f"{record.validation_status} | {self._table_text(references)} | "
                    f"`{record.content_hash[:16]}` |"
                )
        else:
            lines.append("本次运行未摄取结构化安全情报。")
        lines.append("")

        lines.extend(["## P3 回连 Broker 与安全图谱", ""])
        if report.callback_leases:
            lines.extend([
                f"- Callback lease 数量：{report.callback_lease_count}",
                "",
                "| Lease | 协议 | 端口 | 状态 | 回连次数 | 清理 |",
                "|---|---|---:|---|---:|---|",
            ])
            for lease in report.callback_leases:
                lines.append(
                    f"| {lease.lease_id} | {lease.protocol} | {lease.port} | {lease.status} | "
                    f"{lease.callback_count} | {'完成' if lease.cleanup_complete else '未完成'} |"
                )
        else:
            lines.append("本次运行未请求 P3 loopback callback lease。")
        if report.graph_persistence is not None:
            graph = report.graph_persistence
            lines.extend([
                "",
                (
                    f"- 图谱持久化：{graph.status}（{graph.backend or 'unknown'}；"
                    f"节点 {graph.node_count}，关系 {graph.relation_count}）"
                ),
            ])
            if graph.detail:
                lines.append(f"- 图谱说明：{self._table_text(graph.detail)}")
        lines.append("")

        lines.extend(["## P4 工具装配审计", ""])
        if report.tool_bootstraps:
            lines.extend([
                f"- 装配记录：{report.tool_bootstrap_count}",
                f"- 已完成/已就绪：{report.tool_bootstrap_completed_count}",
                "",
                "| Bootstrap | Profile | Tool/Package | 状态 | Readiness | Install | Image digest | 清理 | Manifest |",
                "|---|---|---|---|---:|---:|---|---|---|",
            ])
            for bootstrap in report.tool_bootstraps:
                lines.append(
                    f"| {bootstrap.bootstrap_id} | {bootstrap.profile_key} | "
                    f"{bootstrap.tool_name}/{bootstrap.package_name} | {bootstrap.status} | "
                    f"{bootstrap.readiness_exit_code if bootstrap.readiness_exit_code is not None else ''} | "
                    f"{bootstrap.install_exit_code if bootstrap.install_exit_code is not None else ''} | "
                    f"`{bootstrap.image_digest[:32]}` | "
                    f"{'完成' if bootstrap.cleanup_complete else '未完成'} | "
                    f"{self._table_text(bootstrap.manifest_path)} |"
                )
                if bootstrap.failure_reason:
                    lines.append(
                        f"  - 失败分类：`{bootstrap.failure_category}`；"
                        f"{self._table_text(bootstrap.failure_reason)}"
                    )
        else:
            lines.append("本次运行未请求 P4 临时工具装配。")
        lines.append("")

        lines.extend(["## 持久隔离攻击会话", ""])
        if report.shell_session is not None:
            shell = report.shell_session
            lines.extend([
                f"- Session ID：{shell.session_id}",
                f"- Campaign ID：{shell.campaign_id}",
                f"- Container：{shell.container_name}",
                f"- 状态：{shell.status}",
                f"- 心跳：{'正常' if shell.heartbeat_ok else '失败'}",
                f"- 清理：{'完成' if shell.cleanup_complete else '未完成'}",
                f"- 命令数：{len(shell.commands)}",
                "",
            ])
            if shell.commands:
                lines.extend([
                    "| Step | Command | Exit | Timeout | Evidence |",
                    "|---|---|---:|---|---:|",
                ])
                for command in shell.commands:
                    lines.append(
                        f"| {command.step} | {self._table_text(command.command)} | "
                        f"{command.exit_code if command.exit_code is not None else ''} | "
                        f"{'yes' if command.timed_out else 'no'} | {len(command.evidence_ids)} |"
                    )
        else:
            lines.append("本次运行未请求 P1 持久隔离攻击会话。")
        lines.append("")

        lines.extend(["## 可复现 Security Bug", ""])
        if report.security_bugs:
            for index, bug in enumerate(report.security_bugs, start=1):
                lines.extend(self._render_security_bug_markdown(index, bug))
                lines.append("")
        else:
            lines.append("本次运行没有满足证据与复现质量门的 Security Bug。")
            lines.append("")

        lines.extend(["## 修复建议", ""])
        if report.recommendations:
            for index, recommendation in enumerate(report.recommendations, start=1):
                lines.append(f"{index}. {recommendation}")
        else:
            lines.append("本次运行未生成额外修复建议。")

        if report.limitations:
            lines.extend(["", "## 测试限制", ""])
            for limitation in report.limitations:
                lines.append(f"- {limitation}")

        lines.extend(["", "---", "由安全测试模式生成。"])
        return "\n".join(lines)

    def build_json_payload(self, report: SecurityReport) -> dict[str, Any]:
        return report.model_dump(mode="json")

    def build_artifacts(
        self,
        report: SecurityReport,
        markdown_report: str,
        html_report: str = "",
    ) -> list[dict[str, Any]]:
        artifacts: list[dict[str, Any]] = [
            {
                "type": "report_markdown",
                "filename": f"security_report_{report.campaign_id[:8]}.md",
                "label": "安全测试报告（Markdown）",
                "content_type": "text/markdown",
                "content": markdown_report,
            },
            {
                "type": "report_json",
                "filename": f"security_report_{report.campaign_id[:8]}.json",
                "label": "安全测试报告（JSON）",
                "content_type": "application/json",
                "content": json.dumps(self.build_json_payload(report), ensure_ascii=False, indent=2),
            },
        ]
        if html_report:
            artifacts.append(
                {
                    "type": "report_html",
                    "filename": f"security_report_{report.campaign_id[:8]}.html",
                    "label": "安全测试报告（HTML）",
                    "content_type": "text/html",
                    "content": html_report,
                }
            )
        return artifacts

    def _build_executive_summary(
        self,
        *,
        findings: list[FindingRecord],
        completed: int,
        failed: int,
        critical: int,
        high: int,
        medium: int,
        hypotheses: list[Any],
        attempts: list[Any],
        security_bugs: list[SecurityBugRecord],
    ) -> str:
        if not findings:
            return (
                f"本次安全测试完成 {completed} 个任务，未产生已验证的安全发现。"
                "在将目标视为无风险前，请先查看测试限制部分。"
            )

        summary = [
            f"本次安全测试完成 {completed} 个任务，产生 {len(findings)} 个发现。",
        ]
        if hypotheses:
            succeeded = sum(1 for item in attempts if item.status == "succeeded")
            blocked = sum(1 for item in attempts if item.status == "blocked")
            summary.append(
                f"攻击链阶段生成 {len(hypotheses)} 个证据支持的假设，"
                f"{succeeded} 个验证尝试成功，{blocked} 个被控制措施阻断。"
            )
        if security_bugs:
            deduplicated = sum(1 for item in security_bugs if item.occurrence_count > 1)
            summary.append(
                f"P0-B 生成或复用 {len(security_bugs)} 个可复现 Security Bug，"
                f"其中 {deduplicated} 个已关联跨 Campaign 复测历史。"
            )
        if critical:
            summary.append(f"其中 {critical} 个为严重风险，应立即处理。")
        elif high:
            summary.append(f"其中 {high} 个为高危风险，应优先处理。")
        elif medium:
            summary.append(f"其中 {medium} 个为中危风险，应纳入修复计划。")
        if failed:
            summary.append(f"有 {failed} 个任务执行失败，因此覆盖范围可能不完整。")
        return " ".join(summary)

    def _build_recommendations(self, findings: list[FindingRecord]) -> list[str]:
        recommendations: list[str] = []
        seen: set[str] = set()
        for finding in self._sort_findings(findings):
            recommendation = finding.recommendation.strip()
            if recommendation and recommendation not in seen:
                recommendations.append(recommendation)
                seen.add(recommendation)
        if findings and not recommendations:
            recommendations.append("逐项复核发现、验证暴露面，并修复受影响的服务或安全控制。")
        return recommendations[:10]

    def _build_limitations(
        self,
        *,
        failed_tasks: list[Any],
        skipped: int,
        operational_constraints: list[str],
        findings: list[FindingRecord],
        hypotheses: list[Any],
        attempts: list[Any],
    ) -> list[str]:
        limitations: list[str] = []
        for constraint in operational_constraints:
            value = str(constraint or "").strip()
            if value and value not in limitations:
                limitations.append(value)
        environment_limited = sum(
            1 for task in failed_tasks if self._is_environment_limited_task(task)
        )
        if environment_limited:
            limitations.append(
                f"环境限制（environment_limited）：{environment_limited} 个任务未能从隔离执行环境获得目标响应；"
                "未根据空响应生成漏洞发现。"
            )
        other_failures = len(failed_tasks) - environment_limited
        if other_failures:
            limitations.append(f"{other_failures} 个任务执行失败，相关覆盖范围可能不完整。")
        if skipped:
            limitations.append(f"{skipped} 个任务因依赖条件未满足而被跳过。")
        if findings and not hypotheses:
            limitations.append(
                "本次运行产生 Finding，但未形成漏洞假设；攻击链验证覆盖不完整。"
            )
        elif hypotheses and not attempts:
            limitations.append(
                "已生成漏洞假设，但没有通过证据、Profile 或预算门的验证尝试。"
            )
        blocked_attempts = sum(1 for item in attempts if item.status == "blocked")
        failed_attempts = sum(1 for item in attempts if item.status == "failed")
        if blocked_attempts:
            limitations.append(
                f"{blocked_attempts} 个验证尝试被审批、授权、访问或目标控制阻断。"
            )
        if failed_attempts:
            limitations.append(
                f"{failed_attempts} 个验证尝试执行失败，未据此提升漏洞验证等级。"
            )
        return limitations

    def _is_environment_limited_task(self, task: Any) -> bool:
        analysis = task.failure_analysis if isinstance(task.failure_analysis, dict) else {}
        category = str(analysis.get("failure_category") or "").strip().lower()
        if category in {
            "environment_limited",
            "environment",
            "network_unreachable",
            "target_unreachable",
            "网络不可达",
        }:
            return True
        signals = " ".join(
            str(value or "")
            for value in (
                task.last_error,
                task.result_summary,
                task.raw_output,
                analysis.get("root_cause"),
            )
        ).lower()
        return any(
            token in signals
            for token in (
                "network is unreachable",
                "connection refused",
                "could not connect",
                "failed to connect",
                "no route to host",
                "target_response_not_observed",
                "网络不可达",
            )
        )

    def _render_finding_markdown(self, index: int, finding: FindingRecord) -> list[str]:
        lines = [
            f"### {index}. {finding.title or '未命名发现'}",
            "",
            f"- **风险等级**：{self._severity_label(finding.severity)}",
            f"- **类别**：{finding.category or '未知'}",
            f"- **受影响目标**：{finding.affected_target or '未知'}",
            f"- **验证等级**：{finding.verification_level or 'observed'}",
        ]
        if finding.affected_port:
            lines.append(f"- **受影响端口**：{finding.affected_port}")
        if finding.affected_service:
            lines.append(f"- **受影响服务**：{finding.affected_service}")
        if finding.cve_id:
            lines.append(f"- **CVE**: {finding.cve_id}")
        if finding.cvss_score is not None:
            lines.append(f"- **CVSS**: {finding.cvss_score}")
        if finding.cvss_vector:
            lines.append(f"- **CVSS Vector**: `{finding.cvss_vector}`")
        if finding.cwe_ids:
            lines.append(f"- **CWE**: {', '.join(finding.cwe_ids)}")
        if finding.owasp_categories:
            lines.append(f"- **OWASP**: {', '.join(finding.owasp_categories)}")
        lines.extend([
            f"- **置信度**：{finding.confidence}",
            f"- **是否验证可利用**：{'是' if finding.verified else '否'}",
            "",
        ])
        if finding.description:
            lines.extend(["**描述**", "", finding.description, ""])
        if finding.evidence_summary:
            lines.extend(["**证据**", "", f"```text\n{finding.evidence_summary[:1200]}\n```", ""])
        lines.extend(["**复现方式**", ""])
        if finding.reproduction_steps:
            for step_index, step in enumerate(finding.reproduction_steps, start=1):
                lines.append(f"{step_index}. {step}")
        else:
            lines.append("未记录复现步骤。")
        if finding.recommendation:
            lines.extend(["", "**修复建议**", "", finding.recommendation])
        return lines

    def _render_security_bug_markdown(
        self,
        index: int,
        bug: SecurityBugRecord,
    ) -> list[str]:
        lines = [
            f"### BUG-{index}. {bug.title or '未命名 Security Bug'}",
            "",
            f"- **Bug ID**：{bug.bug_id}",
            f"- **Fingerprint**：`{bug.fingerprint}`",
            f"- **状态**：{bug.status}",
            f"- **验证等级**：{bug.verification_level}",
            f"- **风险等级**：{self._severity_label(bug.severity)}",
            f"- **受影响目标**：{bug.affected_target}",
            f"- **受影响组件**：{bug.affected_component}",
            f"- **出现次数**：{bug.occurrence_count}",
            f"- **回归用例**：{bug.regression_case_id} / {bug.regression_profile}",
            f"- **CVSS Vector**：`{bug.cvss_vector}`",
            f"- **CVSS Score**：{bug.cvss_score if bug.cvss_score is not None else '未计算'}",
            f"- **CWE**：{', '.join(bug.cwe_ids) or '无'}",
            f"- **OWASP**：{', '.join(bug.owasp_categories) or '无'}",
            f"- **CVE**：{', '.join(bug.cve_ids) or '无'}",
            "",
            "**CVSS 依据**",
            "",
            bug.cvss_rationale or "未记录。",
            "",
            "**前置条件**",
            "",
        ]
        lines.extend(
            f"{step_index}. {step}"
            for step_index, step in enumerate(bug.preconditions, start=1)
        )
        lines.extend(["", "**最小复现请求**", "", f"```http\n{bug.reproduction_request}\n```", ""])
        lines.extend(["**复现步骤**", ""])
        lines.extend(
            f"{step_index}. {step}"
            for step_index, step in enumerate(bug.reproduction_steps, start=1)
        )
        lines.extend([
            "",
            "**预期结果**",
            "",
            bug.expected_result or "未记录。",
            "",
            "**实际结果**",
            "",
            f"```text\n{bug.actual_result}\n```",
            "",
            "**证据引用**",
            "",
        ])
        for evidence in bug.evidence_refs:
            lines.append(
                f"- `{evidence.campaign_id}:{evidence.artifact_id}` "
                f"(task `{evidence.source_task_id}`, attempt `{evidence.attempt_id or '-'}`)"
            )
        lines.extend([
            "",
            "**数据与业务影响**",
            "",
            f"- 暴露数据类型：{', '.join(bug.exposed_data_types) or '无已证明数据暴露'}",
            f"- 记录数量估算：{bug.exposed_record_estimate if bug.exposed_record_estimate is not None else '未证明'}",
            f"- CIA：C={bug.confidentiality_impact}, I={bug.integrity_impact}, A={bug.availability_impact}",
            f"- 业务影响：{bug.business_impact or '未记录'}",
            "",
            "**修复建议**",
            "",
            bug.remediation or "未记录。",
            "",
            "**复测历史**",
            "",
            "| Campaign | 结果 | 验证等级 | Evidence | 时间 |",
            "|---|---|---|---:|---|",
        ])
        for retest in bug.retest_history:
            lines.append(
                f"| {retest.campaign_id} | {retest.outcome} | "
                f"{retest.verification_level} | {len(retest.evidence_refs)} | {retest.tested_at} |"
            )
        return lines

    def _target_summary(self, campaign: SecurityCampaign) -> str:
        parts = [
            f"{target.value} ({target.target_type})"
            for target in campaign.targets
            if target.value
        ]
        return ", ".join(parts) if parts else campaign.objective

    def _duration_seconds(self, started_at: str, completed_at: str) -> float:
        if not started_at:
            return 0.0
        try:
            start = datetime.fromisoformat(started_at)
            end = datetime.fromisoformat(completed_at) if completed_at else datetime.now(timezone.utc)
            return max(0.0, (end - start).total_seconds())
        except (TypeError, ValueError):
            return 0.0

    def _sort_findings(self, findings: list[FindingRecord]) -> list[FindingRecord]:
        return sorted(
            findings,
            key=lambda item: SEVERITY_ORDER.get(item.severity, 0),
            reverse=True,
        )

    def _date_part(self, value: str) -> str:
        return value.split("T", 1)[0] if value else ""

    def _time_part(self, value: str) -> str:
        if not value or "T" not in value:
            return ""
        return value.split("T", 1)[1].split(".", 1)[0]

    def _table_text(self, value: str) -> str:
        return str(value or "").replace("|", "\\|").replace("\n", " ")[:180]

    def _execution_strategy(self, activities: list[Any]) -> str:
        modes = sorted({
            str(getattr(activity, "execution_mode", "") or "").strip()
            for activity in activities
            if str(getattr(activity, "execution_mode", "") or "").strip()
        })
        if not modes:
            return "unknown"
        if len(modes) == 1:
            return modes[0]
        return ", ".join(modes)

    def _severity_label(self, severity: str) -> str:
        return {
            RISK_CRITICAL: "严重",
            RISK_HIGH: "高危",
            RISK_MEDIUM: "中危",
            RISK_LOW: "低危",
            RISK_INFO: "信息",
        }.get(str(severity or "").lower(), str(severity or "未知").upper())


__all__ = ["SecurityReportBuilder"]
