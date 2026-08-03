"""Finding Normalizer.

Converts parsed tool output into standardized FindingRecord objects.
"""
from __future__ import annotations

import uuid
from typing import Any

from src.modes.security_testing_mode.campaign_state import FindingRecord


class FindingNormalizer:
    """Normalize tool parser output into FindingRecord objects."""

    def from_nmap(self, parsed: dict[str, Any], task_id: str = "") -> list[FindingRecord]:
        findings: list[FindingRecord] = []
        for port_info in parsed.get("open_ports", []):
            service = port_info.get("service", "")
            version = port_info.get("version", "")
            port = port_info.get("port", 0)
            host = port_info.get("host", "")

            # Flag potentially risky services
            risky_services = {
                "ftp": ("FTP 服务开放", "medium"),
                "telnet": ("Telnet 服务开放（明文传输）", "high"),
                "smtp": ("SMTP 服务开放", "low"),
                "snmp": ("SNMP 服务开放", "medium"),
                "rdp": ("RDP 服务开放", "medium"),
                "vnc": ("VNC 服务开放", "medium"),
                "ms-wbt-server": ("RDP 服务开放", "medium"),
            }

            severity = "info"
            title = f"开放端口: {port}/{port_info.get('protocol', 'tcp')} {service}"
            description = f"主机 {host} 的端口 {port} 处于开放状态，运行服务: {service} {version}".strip()
            recommendation = ""

            if service.lower() in risky_services:
                title, severity = risky_services[service.lower()]
                title = f"{title} ({host}:{port})"
                recommendation = f"评估是否需要对外暴露 {service} 服务，考虑限制访问来源"

            findings.append(FindingRecord(
                finding_id=str(uuid.uuid4())[:8],
                title=title,
                category="information_disclosure" if severity == "info" else "misconfiguration",
                surface_type="network",
                severity=severity,
                confidence="high",
                affected_target=host,
                affected_port=port,
                affected_service=service,
                description=description,
                evidence_summary=f"nmap 扫描结果: {port}/{port_info.get('protocol', 'tcp')} {service} {version}",
                recommendation=recommendation,
                source_task_ids=[task_id] if task_id else [],
                verification_level="observed",
                reproduction_steps=[
                    f"Run the authorized nmap profile against {host or '<target>'}.",
                    f"Confirm {port}/{port_info.get('protocol', 'tcp')} is reported open.",
                ],
            ))
        return findings

    def from_nuclei(self, parsed: dict[str, Any], task_id: str = "") -> list[FindingRecord]:
        findings: list[FindingRecord] = []
        for item in parsed.get("findings", []):
            severity = item.get("severity", "info")
            findings.append(FindingRecord(
                finding_id=str(uuid.uuid4())[:8],
                title=item.get("name") or item.get("template_id", "Nuclei Finding"),
                category="vulnerability",
                surface_type="web",
                severity=severity,
                confidence="high" if severity in ("critical", "high") else "medium",
                cve_id=item.get("cve", ""),
                affected_target=item.get("url", ""),
                description=item.get("description", ""),
                evidence_summary=f"Nuclei 模板 {item.get('template_id', '')} 触发",
                references=item.get("reference") or [],
                source_task_ids=[task_id] if task_id else [],
                verification_level="confirmed",
                reproduction_steps=[
                    f"Run the same Nuclei template against {item.get('url') or '<target>'}.",
                    "Compare the response with the template matcher and preserve the raw hit as evidence.",
                ],
            ))
        return findings

    def from_sqlmap(self, parsed: dict[str, Any], task_id: str = "") -> list[FindingRecord]:
        findings: list[FindingRecord] = []
        if not parsed.get("vulnerable"):
            return findings
        for injection in parsed.get("injections", []):
            findings.append(FindingRecord(
                finding_id=str(uuid.uuid4())[:8],
                title=f"SQL 注入漏洞 - 参数: {injection.get('parameter', '')}",
                category="vulnerability",
                surface_type="web",
                severity="high",
                confidence="confirmed",
                affected_target="",
                description=(
                    f"发现 SQL 注入漏洞，注入类型: {injection.get('type', '')}，"
                    f"数据库: {parsed.get('dbms', '未知')}"
                ),
                evidence_summary=f"sqlmap 确认注入点: {injection.get('parameter', '')}",
                recommendation="使用参数化查询或预编译语句，对所有用户输入进行严格验证",
                source_task_ids=[task_id] if task_id else [],
                verified=True,
                verification_level="exploitable",
                reproduction_steps=[
                    f"Send the recorded SQL injection probe to parameter {injection.get('parameter', '')}.",
                    "Verify the response demonstrates controlled query behavior without modifying data.",
                ],
            ))
        return findings

    def from_nikto(self, parsed: dict[str, Any], task_id: str = "") -> list[FindingRecord]:
        findings: list[FindingRecord] = []
        for item in parsed.get("findings", []):
            desc = item.get("description", "")
            severity = "medium"
            if any(kw in desc.lower() for kw in ["xss", "injection", "rce", "traversal"]):
                severity = "high"
            elif any(kw in desc.lower() for kw in ["header", "cookie", "version"]):
                severity = "low"
            findings.append(FindingRecord(
                finding_id=str(uuid.uuid4())[:8],
                title=f"Nikto 发现: {desc[:60]}",
                category="misconfiguration",
                surface_type="web",
                severity=severity,
                confidence="medium",
                affected_target=parsed.get("target", ""),
                description=desc,
                evidence_summary=f"nikto 扫描结果: {desc}",
                source_task_ids=[task_id] if task_id else [],
                reproduction_steps=[
                    f"Run the authorized Nikto profile against {parsed.get('target') or '<target>'}.",
                    "Verify the same response or configuration signal is present.",
                ],
            ))
        return findings

    def from_http_headers(
        self,
        headers: dict[str, str],
        target: str = "",
        task_id: str = "",
        *,
        status_code: int | None = None,
    ) -> list[FindingRecord]:
        """Check HTTP response headers for security issues."""
        findings: list[FindingRecord] = []
        if not isinstance(status_code, int) or not 100 <= status_code <= 599:
            return findings
        security_headers = {
            "x-frame-options": "缺少 X-Frame-Options 响应头",
            "x-content-type-options": "缺少 X-Content-Type-Options 响应头",
            "strict-transport-security": "缺少 HSTS 响应头",
            "content-security-policy": "缺少 Content-Security-Policy 响应头",
        }
        lower_headers = {k.lower(): v for k, v in headers.items()}
        for header, title in security_headers.items():
            if header not in lower_headers:
                findings.append(FindingRecord(
                    finding_id=str(uuid.uuid4())[:8],
                    title=title,
                    category="missing_control",
                    surface_type="web",
                    severity="low",
                    confidence="confirmed",
                    cvss_score=0.0,
                    cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:N",
                    cvss_rationale=(
                        "The missing response control is confirmed, but this baseline check did not "
                        "demonstrate exploitation or CIA impact; C/I/A remain None."
                    ),
                    cwe_ids=(
                        ["CWE-693", "CWE-1021"]
                        if header == "x-frame-options"
                        else ["CWE-693"]
                    ),
                    owasp_categories=["OWASP-A05:2021-Security-Misconfiguration"],
                    affected_target=target,
                    description=f"HTTP 响应中缺少安全响应头: {header}",
                    evidence_summary=(
                        f"HTTP {status_code} response from {target or '<target>'} omitted {header}."
                    ),
                    recommendation=f"在服务器配置中添加 {header} 响应头",
                    source_task_ids=[task_id] if task_id else [],
                    verification_level="confirmed",
                    reproduction_steps=[
                        f"Send an authorized GET request to {target or '<target>'}.",
                        f"Confirm HTTP {status_code} does not include the {header} response header.",
                    ],
                    # Trivially-verifiable hardening hint; do not let the
                    # severity evaluator promote this to medium just because
                    # missing_control + verified happens to compute > 4.0.
                    is_baseline_check=True,
                ))
        return findings

    def from_http_headers_result(self, parsed: dict[str, Any], task_id: str = "") -> list[FindingRecord]:
        return self.from_http_headers(
            parsed.get("headers") if isinstance(parsed.get("headers"), dict) else {},
            target=str(parsed.get("url") or ""),
            task_id=task_id,
            status_code=parsed.get("status_code") if isinstance(parsed.get("status_code"), int) else None,
        )

    def from_hydra(self, parsed: dict[str, Any], task_id: str = "") -> list[FindingRecord]:
        findings: list[FindingRecord] = []
        for cred in parsed.get("credentials_found", []):
            findings.append(FindingRecord(
                finding_id=str(uuid.uuid4())[:8],
                title=f"弱凭证 - {cred.get('service', '')} ({cred.get('host', '')}:{cred.get('port', '')})",
                category="weak_credential",
                surface_type="credential",
                severity="critical",
                confidence="confirmed",
                affected_target=f"{cred.get('host', '')}:{cred.get('port', '')}",
                affected_service=cred.get("service", ""),
                description=f"发现有效凭证: 用户名 {cred.get('username', '')}",
                evidence_summary=f"hydra 爆破成功: {cred.get('username', '')}@{cred.get('host', '')}",
                recommendation="立即修改弱密码，启用账户锁定策略，考虑使用多因素认证",
                source_task_ids=[task_id] if task_id else [],
                verified=True,
                verification_level="exploitable",
                reproduction_steps=[
                    f"Replay the authorized credential check for {cred.get('service', '')}.",
                    "Confirm access succeeds and immediately revoke or rotate the test credential.",
                ],
            ))
        return findings

    def normalize_batch(
        self, parser_key: str, parsed: dict[str, Any], task_id: str = ""
    ) -> list[FindingRecord]:
        """Dispatch to the appropriate normalizer based on parser key."""
        dispatch = {
            "nmap": self.from_nmap,
            "nuclei": self.from_nuclei,
            "sqlmap": self.from_sqlmap,
            "nikto": self.from_nikto,
            "hydra": self.from_hydra,
            "http_headers": self.from_http_headers_result,
        }
        fn = dispatch.get(parser_key)
        if fn is None:
            return []
        return fn(parsed, task_id=task_id)


__all__ = ["FindingNormalizer"]
