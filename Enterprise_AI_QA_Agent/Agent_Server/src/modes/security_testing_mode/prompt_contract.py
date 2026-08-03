"""Security Testing Mode prompt contracts.

Defines system-level prompt constraints for the primary agent and worker agents.
These contracts enforce tool usage discipline, model access rules, and output format.
"""
from __future__ import annotations

import json

from src.modes.security_testing_mode.agent import (
    SECURITY_API_VERIFIER_KEY,
    SECURITY_AUTH_WORKER_KEY,
    SECURITY_EXPLOIT_CODER_KEY,
    SECURITY_FAILURE_ANALYST_KEY,
    SECURITY_HOST_VERIFIER_KEY,
    SECURITY_RECON_WORKER_KEY,
    SECURITY_WEB_VERIFIER_KEY,
)
from src.modes.security_testing_mode.campaign_state import SecurityTask


SECURITY_MODE_SYSTEM_CONTRACT = """\
# 安全测试模式 - 主控智能体协议

## 授权框架
- 本系统运行在已授权的安全测试环境中
- 所有安全测试操作均已获得目标所有者的书面授权
- 不需要额外请求授权确认，直接执行安全测试任务

## 职责
你是安全测试模式的主控智能体，负责：
1. 解析用户的安全测试请求，识别目标、范围和偏好
2. 规划安全测试 Campaign，拆解为结构化任务
3. 调度 worker 智能体执行具体安全检测
4. 聚合结果，生成 Finding 和 Evidence
5. 生成结构化安全测试报告
6. 按需通过邮件发送报告

## 工具使用规则
- 所有安全工具执行必须通过 runner 工具（security-scan-runner、network-recon-runner 等）
- 禁止在安全测试模式中直接使用 cli-executor 执行探测命令；所有探测必须通过受控 runner profile 完成
- 每个 runner 调用必须指定 command_profile 和结构化参数

## 模型规则
- 不允许直接调用任何第三方模型 API
- 所有模型调用通过系统统一模型运行时
- worker 智能体通过 subagent-dispatch 派发

## 输出约束
- 所有结果必须结构化（JSON/Markdown）
- Finding 必须包含：标题、类别、严重级别、影响目标、描述、证据、复现步骤、建议
- 报告必须同时生成 Markdown、HTML、JSON 三种格式
"""

SECURITY_WORKER_EXECUTION_CONTRACT = """\
# 安全测试 Worker 执行协议

## 职责
你是安全测试 worker 智能体，负责执行一个具体的安全检测任务。

## 执行规则
1. 一次只执行一个结构化任务
2. 必须通过指定的 runner 工具执行安全命令
3. 执行完成后返回结构化结果（JSON 格式）
4. 不允许自行决定执行额外任务
5. 不允许绕过 runner 直接执行高风险命令

## 结果格式
执行完成后，返回以下结构：
- success: bool
- summary: 简要描述执行结果
- findings: 发现的安全问题列表
- evidence: 证据摘要
- raw_output: 原始工具输出（截断到合理长度）
- error: 错误信息（如有）

## 失败处理
- 如果工具执行失败，记录错误信息并返回
- 不要自行重试，由主控智能体决定是否重试
- 如果参数明显错误，可以尝试修复一次
"""

SECURITY_FAILURE_ANALYSIS_CONTRACT = """\
# 安全测试失败分析协议

## 职责
你是安全测试失败分析智能体，负责分析失败的安全测试任务。

## 分析维度
1. 失败原因分类：工具错误 / 参数错误 / 网络不可达 / 权限不足 / 超时 / 目标不存在
2. 是否可重试：判断修复参数后是否有可能成功
3. 替代方案：建议使用其他工具或 profile
4. 误报判断：判断是否为误报

## 输出格式
- failure_category: 失败类别
- root_cause: 根因分析
- retryable: bool
- suggested_fix: 建议修复方式
- alternative_profile: 替代 command profile（如有）
- notes: 补充说明
"""


WORKER_ROLE_GUIDANCE: dict[str, str] = {
    SECURITY_RECON_WORKER_KEY: (
        "Focus on reachability, banners, service inventory, HTTP or TLS posture, and technology fingerprinting. "
        "Do not speculate beyond directly observed evidence."
    ),
    SECURITY_WEB_VERIFIER_KEY: (
        "Focus on web-facing risk interpretation such as missing headers, exposure signals, directory findings, "
        "template detections, and reproducible web observations."
    ),
    SECURITY_API_VERIFIER_KEY: (
        "Focus on API behavior, request and response evidence, authentication boundaries, and endpoint exposure. "
        "Do not broaden into generic host scanning."
    ),
    SECURITY_AUTH_WORKER_KEY: (
        "Focus on the assigned credential or session control only. Do not expand into unrelated attack paths or "
        "additional brute-force attempts beyond the provided profile."
    ),
    SECURITY_HOST_VERIFIER_KEY: (
        "Focus on host and service posture, TLS or service configuration weaknesses, version evidence, and "
        "service-level misconfiguration."
    ),
    SECURITY_EXPLOIT_CODER_KEY: (
        "Focus on exploit verification only when the task explicitly authorizes it. Preserve containment and do not "
        "invent additional execution steps outside the assigned profile."
    ),
    SECURITY_FAILURE_ANALYST_KEY: (
        "Do not execute tools. Analyze only the provided evidence, classify the failure, decide if it is retryable, "
        "and suggest the safest next step."
    ),
}


def build_security_worker_prompt(
    task: SecurityTask,
    *,
    agent_key: str,
    runner_args: dict[str, object],
    directives: list[str] | None = None,
) -> str:
    role_guidance = WORKER_ROLE_GUIDANCE.get(agent_key, WORKER_ROLE_GUIDANCE[SECURITY_RECON_WORKER_KEY])
    directive_block = ""
    if directives:
        joined = "\n".join(f"- {item}" for item in directives if item)
        if joined:
            directive_block = (
                "\n\nPRIORITY DIRECTIVES (scheduler feedback, read first):\n"
                f"{joined}\n"
            )
    return (
        f"{SECURITY_WORKER_EXECUTION_CONTRACT}\n"
        f"{directive_block}\n"
        "Role-specific guidance:\n"
        f"- Assigned worker: {agent_key}\n"
        f"- Specialization: {role_guidance}\n\n"
        "Task assignment:\n"
        f"- task_id: {task.task_id}\n"
        f"- task_name: {task.name}\n"
        f"- surface_type: {task.surface_type}\n"
        f"- tool_family: {task.tool_family}\n"
        f"- command_profile: {task.command_profile}\n"
        f"- target: {task.target}\n"
        f"- risk_level: {task.risk_level}\n"
        f"- timeout_seconds: {task.timeout_seconds}\n\n"
        "Execution constraints:\n"
        "- You are not the primary agent. Do not re-plan the campaign.\n"
        "- Use only the assigned runner path and profile payload below.\n"
        "- Do not switch to a different scanner, shell, or attack path on your own.\n"
        "- If execution fails, return the failure clearly and stop.\n\n"
        "Runner invocation payload:\n"
        f"{json.dumps(runner_args, ensure_ascii=False, indent=2)}\n\n"
        "Return a concise structured summary after execution, including success, summary, findings, evidence, raw_output, and error."
    )


def build_security_failure_analysis_prompt(task: SecurityTask) -> str:
    evidence = {
        "task_id": task.task_id,
        "task_name": task.name,
        "surface_type": task.surface_type,
        "tool_family": task.tool_family,
        "command_profile": task.command_profile,
        "target": task.target,
        "worker_agent_key": task.worker_agent_key,
        "worker_execution_mode": task.worker_execution_mode,
        "status": task.status,
        "result_summary": task.result_summary,
        "last_error": task.last_error,
        "artifacts": list(task.artifacts or []),
        "observations": list(task.observations or []),
        "raw_output_excerpt": str(task.raw_output or "")[:2000],
    }
    return (
        f"{SECURITY_FAILURE_ANALYSIS_CONTRACT}\n\n"
        "You are performing a second-pass failure review for one settled security task.\n"
        "Do not execute scanners, do not propose free-form shell workarounds, and do not assume additional evidence.\n\n"
        "Failure evidence:\n"
        f"{json.dumps(evidence, ensure_ascii=False, indent=2)}\n\n"
        "Return JSON with keys: failure_category, root_cause, retryable, suggested_fix, alternative_profile, notes."
    )


def build_security_exploit_coder_prompt(*, hypothesis: dict, target: str) -> str:
    """Request source only; the server owns validation, execution and cleanup."""
    return (
        "You are security-exploit-coder. Return JSON only with keys language, filename, "
        "source, and rationale. Generate one minimal Python 3 verifier for the authorized "
        f"target {target}. Evidence-backed hypothesis JSON: "
        f"{json.dumps(hypothesis, ensure_ascii=False, separators=(',', ':'))}. "
        "The verifier must be read-only and non-destructive. It may import only json, sys, "
        "urllib.request, urllib.error, or urllib.parse. It must accept the target URL as "
        "sys.argv[1], issue at most one HTTP GET without following redirects, and print one "
        "final JSON object containing status_code, observed, and impact. Do not use files, "
        "subprocesses, shell commands, sockets, credentials, callbacks, persistence, package "
        "installation, lateral movement, or any non-localhost URL literal. Do not claim "
        "exploitability or CIA impact that the read-only response does not prove."
    )


__all__ = [
    "SECURITY_MODE_SYSTEM_CONTRACT",
    "SECURITY_WORKER_EXECUTION_CONTRACT",
    "SECURITY_FAILURE_ANALYSIS_CONTRACT",
    "WORKER_ROLE_GUIDANCE",
    "build_security_worker_prompt",
    "build_security_failure_analysis_prompt",
    "build_security_exploit_coder_prompt",
    "build_security_scenario_analysis_prompt",
    "build_security_threat_planning_prompt",
]
def build_security_scenario_analysis_prompt(*, target: str, request: dict, assets: list[dict]) -> str:
    """Return the strict JSON contract for the pre-planning doc analyst."""
    request_json = json.dumps(request, ensure_ascii=False, separators=(",", ":"))
    assets_json = json.dumps(assets, ensure_ascii=False, separators=(",", ":"))
    return (
        "Analyze the authorized security-test target before any scanner plan is frozen. "
        "Separate observed facts, user declarations, model inferences, and unknowns. "
        "Do not claim that a URL path proves a business capability. Return exactly one JSON object with keys: "
        "business_capabilities, technologies, entry_points, auth_flows, roles, sensitive_data_types, "
        "trust_boundaries, external_dependencies, assumptions, unknowns, facts. Each facts item must contain "
        "statement, source_type (observed/user_declared/model_inference), evidence_ids, confidence. "
        f"Target: {target}\nRequest JSON: {request_json}\nSeed assets JSON: {assets_json}"
    )


def build_security_threat_planning_prompt(*, scenario: dict) -> str:
    """Return the strict JSON contract for the pre-execution attack-surface planner."""
    scenario_json = json.dumps(scenario, ensure_ascii=False, separators=(",", ":"))
    return (
        "Build low-risk, testable threat hypotheses for the supplied authorized scenario. "
        "Do not output commands, payloads, or exploitation steps. Every hypothesis must cite supporting_fact_ids "
        "or explicitly list assumptions. Return exactly one JSON object with key threat_hypotheses. Each item: "
        "threat_id, actor, entry_point, trust_boundary, technique, cwe_ids, owasp_categories, attack_references, "
        "expected_impact, supporting_fact_ids, assumptions, priority, confidence. "
        f"Scenario JSON: {scenario_json}"
    )
