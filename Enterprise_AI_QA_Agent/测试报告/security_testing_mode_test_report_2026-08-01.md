# Security Testing Mode 底层升级完整测试报告

## 1. 报告信息

| 项目 | 内容 |
| --- | --- |
| 报告名称 | `security_testing_mode` 底层升级完整测试报告 |
| 测试日期 | 2026-08-01 |
| 测试对象 | `Agent_Server/src/modes/security_testing_mode` 及其安全执行、权限、模型、调度依赖 |
| 对照基线 | Git commit `32516b1b` |
| 设计依据 | `security_testing_mode_foundational_upgrade.md` |
| 对比依据 | `security_testing_mode_vs_pentagi_comparison.md` |
| Python | `E:\PyThon\Anaconda_PyThon\envs\Python3.11\python.exe` |
| 安全镜像 | `vxcontrol/kali-linux` |
| 测试模型 | `qwen3.6-plus`（测试窗口临时激活） |
| 恢复模型 | `agnes-2.0-flash` |
| 报告结论 | 通过；完整套件保留 2 个与本次安全升级无关的 Windows 长路径失败 |

## 2. 执行摘要

本次测试完成了 `security_testing_mode` 底层升级的自动化回归、真实后端会话 API、内部大模型、多 Worker 调度、Kali Docker 执行、跨会话记忆、审批恢复、中断传播和环境清理验证。

核心结论：

- 安全模式定向测试：`75 passed, 1 skipped`。
- 后端完整测试：`284 passed, 1 skipped, 2 failed`。
- 三个完整安全 Campaign：共执行 9 个 Worker 任务，9 个完成、0 个失败。
- 两个真实目标均生成结构化 Markdown 报告，各产生 4 个低风险发现。
- 同目标第二次运行成功从 PostgreSQL/pgvector 召回 3 个历史成功 profile。
- 高风险 profile 能创建参数绑定审批，批准后才在 Kali 中执行。
- 父会话中断后，已启动 Worker 被中断，其余 Worker 不再派发。
- 测试结束后活动模型、3000 监听状态和 Docker 容器均恢复。

综合判定：本次底层升级范围内的执行环境、调度闭环、记忆召回、输出压缩、安全硬门、审批和中断功能满足验收要求。

## 3. 测试范围

### 3.1 纳入范围

1. S1 执行环境：
   - Docker 同步执行。
   - Detached 后台执行和轮询。
   - 宿主机与容器双向文件传输。
   - 路径穿越保护。
   - localhost 到 `host.docker.internal` 重写。
   - 受控自由命令门控。

2. S2 调度闭环：
   - Refiner 动态追加、删除和降级任务。
   - Reflector 对无结构化结果的有界纠偏。
   - Mentor 在连续失败后要求更换路线。
   - 任务数量上限和资源冲突控制。

3. S3 记忆召回：
   - 成功 profile 写入。
   - 目标指纹匹配。
   - 跨会话召回。
   - Surface 和风险等级兼容过滤。

4. S4 输出压缩：
   - 超过阈值的工具输出压缩。
   - URL、CVE、端口、服务、状态和错误保留。

5. S5 工具能力：
   - `tcpdump_timed_capture`。
   - `searchsploit_exploit_lookup`。
   - `msf_module_info`。
   - `free_command`。
   - 固定工具/包映射 bootstrap。

6. S6 安全硬门：
   - 目标 allowlist 双层校验。
   - 服务端可信授权继承。
   - 参数级风险审批。
   - 审批 scope hash。
   - 只接受服务端审批标记。

7. 运行时能力：
   - Qwen 显式模型选择。
   - 父子会话状态传播。
   - Interrupt 和 Worker 取消。
   - 阶段、checkpoint、Worker、Runner、审批和记忆日志。

### 3.2 不在范围

- 持久 PTY 或 SSH 连接池。
- C2、反弹 shell、横向移动和完整后渗透。
- Graphiti 风格安全情景图谱。
- 任意软件安装的通用 Installer Agent。
- 自动化恢复并继续已中断的原 Campaign。

这些项目与升级规格的“范围与非目标”一致，不计入本次失败。

## 4. 测试环境

| 组件 | 状态 |
| --- | --- |
| FastAPI 后端 | `http://127.0.0.1:1032`，健康检查 `ok` |
| PostgreSQL | 正常，`postgres_ok=true` |
| 会话存储 | PostgreSQL |
| 记忆存储 | `postgres_pgvector` |
| 安全 Runner backend | Docker |
| Kali 镜像 | `vxcontrol/kali-linux` |
| 目标一 | `http://localhost:8089` |
| 目标二 | `http://localhost:3000/` |
| 3000 原始监听 | Windows `::1:3000` |
| 临时网络适配 | 测试期间启动 IPv4 到 IPv6 用户态代理，结束后停止 |
| 最终活动模型 | `agnes-2.0-flash` |
| 最终安全容器数 | 0 |

## 5. 自动化测试结果

### 5.1 安全模式定向套件

执行命令：

```powershell
& 'E:\PyThon\Anaconda_PyThon\envs\Python3.11\python.exe' -m pytest `
  tests/test_security_reflect_mentor.py `
  tests/test_intent_safety_routing.py `
  tests/test_security_execution_environment_upgrade.py `
  tests/test_security_output_compaction.py `
  tests/test_security_target_guard.py -q
```

结果：

```text
75 passed, 1 skipped in 6.01s
```

判定：通过。跳过项属于运行环境条件跳过，不影响本次能力验收。

### 5.2 后端完整套件

执行命令：

```powershell
& 'E:\PyThon\Anaconda_PyThon\envs\Python3.11\python.exe' -m pytest tests -q
```

结果：

```text
284 passed, 1 skipped, 2 failed in 9.78s
```

失败用例：

1. `test_reregistering_stale_runner_requeues_prior_assignment`
2. `test_heartbeat_from_stale_runner_requeues_prior_assignment`

共同错误：

```text
FileNotFoundError: [Errno 2] No such file or directory
```

共同调用位置：

```text
application/compatibility/runner_service.py::_store_uploaded_artifact
path.write_bytes(content)
```

分析：两个用例在 Windows 深目录下生成兼容性测试产物路径，最终路径超过当前文件系统/进程可接受长度。使用临时短盘符复测时，`Path.resolve()` 仍解析回原始 `G:` 深路径，因此失败位置和错误保持不变。

影响：与 `security_testing_mode`、Kali Runner、审批、记忆和调度逻辑无关，没有发现本次升级引入的完整套件回归。

### 5.3 静态与启动检查

| 检查 | 结果 |
| --- | --- |
| `python -m compileall -q src` | 通过 |
| `from src.main import app` | 通过，输出 `Enterprise AI QA Agent` |
| `git diff --check` | 通过，仅有 Git 的 CRLF 转换提示 |
| FastAPI `/api/v1/health` | `ok` |

## 6. 真实场景测试

### 6.1 场景 A：8089 低风险安全基线

| 项目 | 结果 |
| --- | --- |
| 父会话 ID | `03bf52df-e757-448f-a83a-d904291cc971` |
| Campaign ID | `f3cc4fec-88b8-4961-b450-46897ea638c1` |
| 模型 | `qwen3.6-plus` |
| 执行策略 | `subagent_session` |
| 状态 | `completed` |
| 快照 | `completed` |
| Worker | 3 |
| 任务 | 3/3 完成，0 失败 |
| 耗时 | 111.68 秒 |
| 发现 | 4 个低风险 |

实际执行 profile：

- `httpx_probe`
- `whatweb_fingerprint`
- `http_headers_probe`

关键证据：

- 根路径返回 HTTP 302。
- 跳转到 `/auth/login`。
- 页面被识别为 XXL-JOB 分布式任务调度平台。
- Kali 容器内真实执行 httpx、whatweb 和 header probe。

发现项：

1. 缺少 `X-Frame-Options`。
2. 缺少 `X-Content-Type-Options`。
3. 缺少 `Strict-Transport-Security`。
4. 缺少 `Content-Security-Policy`。

判定：通过。

### 6.2 场景 B：8089 同目标记忆召回

| 项目 | 结果 |
| --- | --- |
| 父会话 ID | `8192f435-2584-4e0f-a6e4-2d76309ed22c` |
| Campaign ID | `0cef9945-d634-44fe-9889-703065defd04` |
| 状态 | `completed` |
| Worker | 3 |
| 任务 | 3/3 完成，0 失败 |
| 耗时 | 117.57 秒 |
| 发现 | 4 个低风险 |

规划阶段日志：

```text
security_memory_recall_completed
target_fingerprint=target-d6bc14ce29278acc
recalled_profiles=['http_headers_probe', 'whatweb_fingerprint', 'httpx_probe']
```

验证点：

- 第二个会话成功读取第一个会话写入的成功 execution observation。
- 召回范围基于服务端生成的目标指纹。
- 召回结果只改变 profile 优先级。
- 系统仍重新执行真实工具，没有直接复用历史结论。
- 低风险请求没有因历史结果引入中高风险 profile。

判定：通过。

### 6.3 场景 C：3000 低风险安全基线

| 项目 | 结果 |
| --- | --- |
| 父会话 ID | `7f0ba1e2-26c7-45d0-87ef-147316ad6075` |
| Campaign ID | `381169d3-0298-4f9a-b263-eddd0f84a7ed` |
| 模型 | `qwen3.6-plus` |
| 状态 | `completed` |
| 快照 | `completed` |
| Worker | 3 |
| 任务 | 3/3 完成，0 失败 |
| 耗时 | 67.00 秒 |
| 发现 | 4 个低风险 |

关键证据：

- 目标返回 HTTP 200。
- 页面标题为 `blog-web`。
- 检测到 HTML5/module 脚本特征。
- Kali 容器内实际完成 3 个 profile。
- 生成完整结构化报告。

发现项：

1. 缺少 `X-Frame-Options`。
2. 缺少 `X-Content-Type-Options`。
3. 缺少 `Strict-Transport-Security`。
4. 缺少 `Content-Security-Policy`。

网络说明：目标最初仅监听 Windows `::1:3000`。测试期间使用临时 IPv4 到 IPv6 代理，并把 Host 保持为 `localhost:3000`，使 Docker 中的 `host.docker.internal:3000` 可以访问实际服务。测试后代理已停止，最终监听恢复为仅 `::1:3000`。

判定：通过。

### 6.4 场景 D：父会话中断传播

| 项目 | 结果 |
| --- | --- |
| 父会话 ID | `cd5ba722-2580-4108-9730-56aafce51922` |
| 父状态 | `interrupted` |
| 快照 | `interrupted` |
| 中断前 Worker 数 | 1 |
| 中断后 Worker 数 | 1 |
| 已启动子会话状态 | `interrupted` |
| 未派发任务 | 2 |

执行过程：

1. 从正式会话消息接口发起 8089 安全 Campaign。
2. 监测到第一个 Worker 创建后调用 `/interrupt`。
3. Coordinator 取消其持有的 Worker 协程。
4. 已启动子会话被写为 `interrupted`。
5. 任务池中 3 个未终结任务全部收敛为 skipped/interrupted。
6. 后两个 Worker 没有派发。
7. 父会话生成 interrupted 快照并保存已有证据。

关键日志：

```text
security_coordinator_interrupted
task_interrupted
security_phase_transition ... to_phase=interrupted
```

判定：通过。

### 6.5 场景 E：高风险 profile 审批与恢复

| 项目 | 结果 |
| --- | --- |
| 父会话 ID | `de695926-6f34-477c-9d52-97144b31c906` |
| Agent | `security-exploit-coder` |
| Tool | `exploit-workbench-runner` |
| Profile | `searchsploit_exploit_lookup` |
| 审批 ID | `3064f832-b8d1-462a-849d-d8a1d5689fc1` |
| 审批前状态 | `waiting_approval` |
| 审批后状态 | `completed` |
| 实际命令 | Kali 中执行 `searchsploit` |
| 退出码 | 0 |

审批记录包含：

- 完整工具参数。
- `approval_scope_hash`。
- `security_task_risk_approval_required` 原因码。
- Agent、模型、turn 和 tool job 关联信息。

批准后，`RuntimeService.resume_after_approval()` 注入仅服务端可产生的 `_server_approval_granted=True`，随后 Runner 才执行 profile。用户提供的 `approved`、`approval_granted` 或 `authorization_confirmed` 字段不会被信任。

Searchsploit 结果：执行成功，当前 Exploit-DB 数据库未找到 XXL-JOB 对应公开 exploit，返回 0 条利用和 0 条 shellcode。这是有效的空结果，不是执行失败。

判定：通过。

## 7. 需求与证据追踪

| 需求 | 状态 | 证据 |
| --- | --- | --- |
| 使用真实后端会话 API | 通过 | 5 个父会话均由 `/api/v1/sessions` 和消息接口触发 |
| 使用系统内部模型 | 通过 | 父会话和 Worker 使用 `qwen3.6-plus` |
| 使用 `vxcontrol/kali-linux` | 通过 | HTTP、WhatWeb、Header、Searchsploit 均在该镜像执行 |
| 多场景测试 | 通过 | 8089、8089 recall、3000、interrupt、approval |
| 详细节点日志 | 通过 | phase/checkpoint/refiner/memory/worker/runner/approval/interrupt 日志完整 |
| 测试后销毁容器 | 通过 | 最终 `qa-security-runner` 容器数为 0 |
| 恢复模型状态 | 通过 | 活动模型恢复 `agnes-2.0-flash` |
| 清理临时 3000 代理 | 通过 | 最终仅原始 `::1:3000` 监听 |
| 更新设计文档 | 通过 | foundational upgrade 和 PentAGI comparison 已更新 |

## 8. 测试过程中发现并修复的问题

### DEF-01 多审批恢复快照阶段错误

现象：存在多个审批项时，批准第一个审批后，系统无条件清空 `pending_approvals`，导致快照阶段被写为 `resumable` 而不是 `waiting_approval`。

根因：`resume_after_approval()` 没有保留尚未解决的审批对象。

修复：过滤并保留剩余审批，同时同步更新 pending turn 的 `pending_approval_ids` 和 `pending_approvals`。

回归：新增直接测试，验证审批标记注入和剩余审批快照阶段。

状态：已修复并通过测试。

### DEF-02 Exploit Runner 无法进入参数级审批

现象：`exploit-workbench-runner` 仍注册为 `restricted`，模型不可见，因此无法产生具体 profile 工具调用和后端审批记录。

根因：S5 已实现 profile 和参数级风险门，但注册表权限仍保留旧占位阶段的 restricted 设置。

修复：将 exploit runner 调整为 `ask`。工具可见不代表直接执行；具体 profile 仍由 `ExecutionSafetyPolicy` 和服务端审批标记控制。

回归：注册契约测试和真实 Searchsploit 审批恢复场景均通过。

状态：已修复并通过测试。

## 9. 已知问题与残余风险

### 9.1 已知测试环境问题

完整套件仍有两个兼容性 Runner 的 Windows 长路径失败。建议后续单独处理：

- 为测试产物使用系统临时短路径。
- 或在产物存储层加入 Windows 长路径前缀/路径缩短策略。
- 修复时不得改变兼容性 Runner 的生产产物目录契约。

### 9.2 安全模式残余能力差距

- 无 PTY/SSH 持久交互环境。
- 无自动 C2、横向移动和后渗透流程。
- Bootstrap 仅为固定映射，且默认关闭。
- 输出压缩为确定性信号保留，不是完整 LLM 语义摘要。
- 记忆使用 pgvector，没有独立安全情景图谱。
- Interrupted Campaign 当前终止并保存证据，不支持原 Campaign 续跑。

这些限制已经写入设计文档，不构成本轮验收失败。

## 10. 最终环境清理

测试完成后执行并核对：

| 清理项 | 最终状态 |
| --- | --- |
| `qa-security-runner` 容器 | 0 |
| 3000 临时 IPv4 代理 | 已停止 |
| 3000 监听 | 仅 `::1:3000` |
| 活动模型 | `agnes-2.0-flash` |
| 后端 | `http://127.0.0.1:1032` 健康运行 |
| PostgreSQL | 正常 |
| 临时短盘符 | 已移除 |

## 11. 最终结论

本次 `security_testing_mode` 底层升级测试通过。

通过依据：

- 本次改动相关的 75 项自动化测试全部通过。
- 两个真实 Web 目标均完成多 Worker、真实 Kali 工具执行和报告生成。
- 动态调度、跨会话记忆、参数审批和父子中断均有真实 API 证据。
- 未发现本次安全模式升级导致的后端完整套件回归。
- 所有安全 Runner 容器和临时网络适配均已清理。
- 模型和后端环境已恢复到交付状态。

验收状态：**通过，有已记录的非阻塞已知问题。**

## 12. 证据索引

- 底层升级规格与实施记录：`Agent_Server/docs/security_testing_mode_foundational_upgrade.md`
- PentAGI 对比与升级后实证：`Agent_Server/docs/security_testing_mode_vs_pentagi_comparison.md`
- 安全定向回归：`Agent_Server/tests/test_intent_safety_routing.py`
- Refiner/Reflector/Mentor：`Agent_Server/tests/test_security_reflect_mentor.py`
- Docker 执行环境：`Agent_Server/tests/test_security_execution_environment_upgrade.py`
- 输出压缩：`Agent_Server/tests/test_security_output_compaction.py`
- 目标硬门：`Agent_Server/tests/test_security_target_guard.py`
- 后端日志：系统临时目录 `enterprise-ai-qa-backend.stdout.log` / `enterprise-ai-qa-backend.stderr.log`
- 会话证据：第 6 节列出的父会话、Worker 会话、事件历史、快照、工具作业和产物记录

