"""Downloadable, sanitized reproduction packages for Security Bug records."""
from __future__ import annotations

import hashlib
import json
from typing import Any

from src.application.security.output_safety_policy import OutputSafetyPolicy
from src.modes.security_testing_mode.campaign_state import SecurityBugRecord


class SecurityBugReproductionPackageService:
    """Build developer-facing replay material without leaking sensitive data."""

    def __init__(self, output_safety: OutputSafetyPolicy | None = None) -> None:
        self._output_safety = output_safety or OutputSafetyPolicy()

    def build_package(self, bug: SecurityBugRecord) -> dict[str, Any]:
        package = {
            "package_type": "security_bug_reproduction",
            "package_version": "1.0",
            "bug_id": bug.bug_id,
            "fingerprint": bug.fingerprint,
            "title": bug.title,
            "status": bug.status,
            "severity": bug.severity,
            "verification_level": bug.verification_level,
            "affected_target": bug.affected_target,
            "affected_component": bug.affected_component,
            "mappings": {
                "cvss_score": bug.cvss_score,
                "cvss_vector": bug.cvss_vector,
                "cvss_rationale": bug.cvss_rationale,
                "cve_ids": list(bug.cve_ids),
                "cwe_ids": list(bug.cwe_ids),
                "owasp_categories": list(bug.owasp_categories),
            },
            "impact": {
                "confidentiality": bug.confidentiality_impact,
                "integrity": bug.integrity_impact,
                "availability": bug.availability_impact,
                "business": bug.business_impact,
                "exposed_data_types": list(bug.exposed_data_types),
                "exposed_record_estimate": bug.exposed_record_estimate,
            },
            "reproduction": {
                "preconditions": list(bug.preconditions),
                "steps": list(bug.reproduction_steps),
                "request_template": bug.reproduction_request,
                "expected_result": bug.expected_result,
                "actual_result": bug.actual_result,
                "regression_case_id": bug.regression_case_id,
                "regression_profile": bug.regression_profile,
            },
            "evidence": [
                {
                    "campaign_id": ref.campaign_id,
                    "session_id": ref.session_id,
                    "attempt_id": ref.attempt_id,
                    "artifact_id": ref.artifact_id,
                    "source_task_id": ref.source_task_id,
                    "created_at": ref.created_at,
                }
                for ref in bug.evidence_refs
            ],
            "retest_history": [
                {
                    "retest_id": item.retest_id,
                    "campaign_id": item.campaign_id,
                    "session_id": item.session_id,
                    "attempt_id": item.attempt_id,
                    "outcome": item.outcome,
                    "verification_level": item.verification_level,
                    "actual_result": item.actual_result,
                    "tested_at": item.tested_at,
                    "evidence_refs": [
                        {
                            "campaign_id": ref.campaign_id,
                            "session_id": ref.session_id,
                            "attempt_id": ref.attempt_id,
                            "artifact_id": ref.artifact_id,
                            "source_task_id": ref.source_task_id,
                            "created_at": ref.created_at,
                        }
                        for ref in item.evidence_refs
                    ],
                }
                for item in bug.retest_history
            ],
            "remediation": bug.remediation,
            "fixed_version": bug.fixed_version,
            "lifecycle_note": bug.lifecycle_note,
        }
        sanitized = self._output_safety.sanitize_for_audit(package)
        sanitized["content_sha256"] = self._content_hash(sanitized)
        return sanitized

    def build_json_bytes(self, package: dict[str, Any]) -> bytes:
        return json.dumps(
            package,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        ).encode("utf-8")

    def build_markdown(self, package: dict[str, Any]) -> str:
        reproduction = package.get("reproduction") or {}
        mappings = package.get("mappings") or {}
        impact = package.get("impact") or {}
        lines = [
            "# Security Bug 复现包",
            "",
            f"- Bug ID：`{self._text(package.get('bug_id'))}`",
            f"- 标题：{self._text(package.get('title'))}",
            f"- 状态：`{self._text(package.get('status'))}`",
            f"- 严重级别：`{self._text(package.get('severity'))}`",
            f"- 验证级别：`{self._text(package.get('verification_level'))}`",
            f"- 受影响目标：`{self._text(package.get('affected_target'))}`",
            f"- 受影响组件：`{self._text(package.get('affected_component'))}`",
            "",
            "## 前置条件",
            "",
        ]
        preconditions = reproduction.get("preconditions") or []
        lines.extend(self._bullet_lines(preconditions))
        lines.extend(["", "## 复现步骤", ""])
        lines.extend(self._numbered_lines(reproduction.get("steps") or []))
        lines.extend(["", "## 最小复现请求模板", "", "```http"])
        lines.append(self._text(reproduction.get("request_template")))
        lines.extend(["```", "", "## 预期结果", "", self._text(reproduction.get("expected_result"))])
        lines.extend(["", "## 实际结果", "", self._text(reproduction.get("actual_result"))])
        lines.extend(["", "## 影响与映射", ""])
        lines.extend(
            [
                f"- CVSS：`{self._text(mappings.get('cvss_vector'))}` / `{self._text(mappings.get('cvss_score'))}`",
                f"- CWE：{', '.join(self._text(item) for item in mappings.get('cwe_ids') or []) or '未记录'}",
                f"- OWASP：{', '.join(self._text(item) for item in mappings.get('owasp_categories') or []) or '未记录'}",
                f"- 数据影响：C={self._text(impact.get('confidentiality'))}, I={self._text(impact.get('integrity'))}, A={self._text(impact.get('availability'))}",
                f"- 业务影响：{self._text(impact.get('business'))}",
            ]
        )
        lines.extend(["", "## Evidence 索引", ""])
        evidence = package.get("evidence") or []
        if evidence:
            for ref in evidence:
                lines.append(
                    "- "
                    f"`{self._text(ref.get('artifact_id'))}` "
                    f"(campaign `{self._text(ref.get('campaign_id'))}`, "
                    f"task `{self._text(ref.get('source_task_id'))}`)"
                )
        else:
            lines.append("- 无 Evidence 引用。")
        lines.extend(["", "## 复测历史", ""])
        history = package.get("retest_history") or []
        if history:
            for item in history:
                lines.append(
                    "- "
                    f"`{self._text(item.get('outcome'))}` at `{self._text(item.get('tested_at'))}` "
                    f"(campaign `{self._text(item.get('campaign_id'))}`)"
                )
        else:
            lines.append("- 无复测历史。")
        lines.extend(["", "## 修复建议", "", self._text(package.get("remediation"))])
        lines.extend(["", f"内容哈希：`{self._text(package.get('content_sha256'))}`", ""])
        return "\n".join(lines)

    def build_markdown_bytes(self, package: dict[str, Any]) -> bytes:
        return self.build_markdown(package).encode("utf-8")

    def _bullet_lines(self, values: list[Any]) -> list[str]:
        if not values:
            return ["- 未记录。"]
        return [f"- {self._text(value)}" for value in values]

    def _numbered_lines(self, values: list[Any]) -> list[str]:
        if not values:
            return ["1. 未记录。"]
        return [f"{index}. {self._text(value)}" for index, value in enumerate(values, start=1)]

    def _text(self, value: Any) -> str:
        sanitized, _ = self._output_safety.sanitize_text(str(value or ""))
        return sanitized

    def _content_hash(self, value: dict[str, Any]) -> str:
        payload = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


__all__ = ["SecurityBugReproductionPackageService"]
