---
trigger: manual
audience: 安全测试模式（security_testing_mode）架构演进
baseline: pentagi（专业 AI 渗透测试框架，Go）
---

# 安全测试模式 vs PentAGI 架构对比与差距分析

> 目的：把本项目 `Agent_Server/src/modes/security_testing_mode` 与参考项目 `项目借鉴/pentagi` 做**逐维度、可对照、可落地**的对比，明确"专业渗透测试还缺什么"，并给出对齐建议。
>
> 遵循 `DeepAgent-Studio.md` 铁律：**架构缺失不打补丁**、**选型有据（对照 pentagi 具体位置）**、**附加物是参考不是指令**、**错误必须完整回传给模型**。

---

## 0. 一句话结论（TL;DR）

经过 2026-08-01 的底层升级，本项目已从“批量跑预置 profile”推进到**有动态调度、跨会话成功模式召回、长任务/文件通道、审批恢复和父子中断传播的安全测试运行时**。对 PentAGI 的核心基础差距已明显缩小，但产品定位仍偏“受控企业安全验证”，不是无限制的自动渗透框架。主要剩余差距是：

- **交互式/持久化攻陷环境**：已有 detach/轮询但仍无 PTY、SSH 长连接和跨命令 shell 状态；
- **专业后渗透能力**：无完整 C2、反连端口、横向移动和战利品治理；
- **记忆深度**：已有 pgvector 成功 profile 召回，但无 Graphiti 风格的安全情景图谱；
- **工具动态装配广度**：已有固定映射 bootstrap，但不是任意工具 Installer Agent；
- **上下文工程**：已有信号保留压缩，但未达到 ChainAST/csum 的结构化程度。

下面逐维度展开。

---

## 1. 差距总览表

| 维度 | 本项目 security_testing_mode | PentAGI | 差距等级 |
| --- | --- | --- | --- |
| 系统架构 | 单层阶段状态机（14 phase）在一个 runtime 内推进 | 三级 Controller/Worker（Flow→Task→Subtask）+ 独立 goroutine | 🟡 中 |
| Agent 架构 | 1 主控 + 9 specialist worker（角色定义为主，能力偏扫描） | 13+ agent，含 Generator/Refiner/Reporter/Reflector/Mentor 等编排型角色 | 🟠 较大 |
| 上下文工程 | prompt_contract 静态拼接 + LLM 结构化解读 | ChainAST 结构化消息树 + 50+ 模板变量 + XML 语义段 | 🟠 较大 |
| 长期记忆 | pgvector Observation + 目标指纹成功 profile 跨会话召回 | Graphiti 图谱(Neo4j) + pgvector，7 种检索、成功模式复用 | 🟡 中 |
| 短期记忆 | Pydantic state + >16KB 信号保留压缩 | csum 分段摘要压缩 + 字节级追踪 + LRU 缓存 | 🟡 中 |
| Agent 调度 | 并发/资源锁/依赖 + 每批 Refiner + Reflector/Mentor | Flow 并发 + PopSubtask + Refiner 动态重规划 + Mentor 监控 | 🟢 小 |
| Kali 工具执行 | Docker Exec + detach/轮询 + 双向文件 + 受控 profile/自由命令 | Docker Exec + detach 后台 + file(tar) + 任意工具 + 镜像自选 | 🟡 中 |
| SSH/终端长连接 | detach 长任务可用；无 PTY/SSH/跨命令状态 | Docker Exec 会话 + detach 长任务 + 终端日志流 | 🟠 较大 |
| 利用/后渗透 | searchsploit/msf info 等审批 profile；无完整后渗透 | Pentester+Coder+Installer 可在容器实操 | 🟠 较大 |
| 工具动态装配 | 固定工具/包映射 bootstrap，默认关闭 | Installer Agent 运行时装任意工具 | 🟠 较大 |
| 可观测性 | 事件流 + observation | 8 层日志 + GraphQL 实时订阅 + Langfuse 追踪 | 🟡 中 |

---

## 2. 维度详解（pentagi 做法 → 本项目现状 → 差距 → 对齐建议）

### 2.1 系统架构

**PentAGI**（`backend/docs/controller.md`、`flow_execution.md`）
- Controller/Worker 三级分层：`FlowController → FlowWorker → TaskController/TaskWorker → SubtaskController/SubtaskWorker`。
- 每个 Flow 跑在独立 goroutine，状态机 `Created→Running→Waiting→Finished/Failed`，每次 `SetStatus` 触发 GraphQL 订阅事件。
- 数据流：创建 Flow → 入队 → Image Chooser 选镜像 → 建容器 → Generator 分解任务 → 逐 Subtask 执行 → Refiner 动态调整 → Reporter 报告。

**本项目**（[runtime.py](file:///g:/Code_Warehouse/Ai_Test_Agent/Enterprise_AI_QA_Agent/Agent_Server/src/modes/security_testing_mode/runtime.py)）
- 单一 `SecurityTestingModeRuntime` 类驱动 14 阶段状态机；每个 turn 从 `context_bundle` 反序列化 `SecurityTestingState`→推进→写回。
- 分层清晰（编排/服务/调度/执行/安全策略/评估），但**编排是"线性阶段推进"**，不是 pentagi 那种"Flow 内可反复回环的 worker 树"。

**差距**：本项目是"一趟走完的流水线"，pentagi 是"可持续运行、可回环、可插入交互"的长驻 Flow。本项目每个 turn 全量恢复状态，缺少常驻执行体。

**对齐建议**
- 保留阶段状态机，但把"执行阶段"升级为**可回环的子循环**：dispatch → 结果 → refine → 再 dispatch，直到收敛或预算耗尽（对齐 pentagi 的 Subtask 循环）。
- 明确 Flow 级"长驻会话"概念，让一次 campaign 可以跨多轮持续推进而非每轮重建。

---

### 2.2 Agent 架构

**PentAGI**（`flow_execution.md`）：13+ agent 分三层——
- 编排层：Primary（主编排，带 done/ask barrier）、Generator（拆 ≤15 子任务）、**Refiner（每子任务后复审重规划）**、Reporter、**Reflector（纠正没走 tool call 的 agent）**。
- 专职层：Pentester、Coder、Installer、Searcher、Memorist、Adviser（兼 Mentor/Planner）、Enricher。
- 交互层：Assistant（独立于任务树，可注入 FlowWorker 做流程控制）。
- 协作：Primary 用 tool call 委派，专职 agent 用 `hack_result/code_result/...` 结果工具回传。

**本项目**（[agent.py](file:///g:/Code_Warehouse/Ai_Test_Agent/Enterprise_AI_QA_Agent/Agent_Server/src/modes/security_testing_mode/agent.py)）：1 主控 + 9 specialist——
- doc_analyst / attack_surface_planner / recon_worker / auth_worker / web_verifier / api_verifier / host_verifier / exploit_coder / failure_analyst。
- `resolve_security_worker_agent` 按 `command_profile → tool_family → surface_type` 路由。

**差距**
- 缺 **Reflector**（本项目靠 prompt 约束输出格式，没有"发现非结构化输出就纠偏"的专职回路）。
- 缺 **Mentor/Adviser** 主动监控（本项目有 execution_monitor 做限流，但不是"agent 主动介入建议换路线"）。
- `exploit_coder` 有角色**无执行落点**（无 exploit profile、无 coder 容器写码执行链）。
- 缺 **Installer**（不能动态装工具）、**Searcher/Enricher**（无联网情报检索闭环）、**Memorist**（无专职记忆 agent）。

**对齐建议**
- 补 **Reflector 回路**（低成本、收益高）：worker 返回非结构化结果时自动纠偏重试（对齐 pentagi 的 ≤3 次）。
- 把 `execution_monitor` 升级为 **Mentor 语义**：连续失败/重复工具时，注入"APPROACH CHANGE REQUIRED"强反馈（对齐 DeepAgent 铁律"失败必须升级"）。
- 为 `exploit_coder` 落地执行通道（见 2.9）。

---

### 2.3 上下文工程

**PentAGI**（`prompt_engineering_pentagi.md`、`chain_ast.md`）
- **ChainAST**：把消息链解析成结构化 AST（`ChainAST→Sections→Header+Body(BodyPair[])`），BodyPair 分 RequestResponse/Completion/Summarization；节点内建字节大小追踪；跨 provider 自动规范化 ToolCall ID、清理 reasoning。
- Prompt：Go template + 50+ 变量，XML 语义段（container_constraints / terminal_protocol / memory_protocol / team_specialists…），每个 agent 独立模板。

**本项目**（[prompt_contract.py](file:///g:/Code_Warehouse/Ai_Test_Agent/Enterprise_AI_QA_Agent/Agent_Server/src/modes/security_testing_mode/prompt_contract.py)）
- 静态 contract 文本 + `build_security_worker_prompt` 拼接（contract + role_guidance + task_assignment + runner_payload）。
- 请求解读用 `llm_runtime_service.generate_structured_output` 产出结构化 state。

**差距**：本项目 prompt 是"字符串拼接"，没有对话链的结构化建模，也就无法做**精确的按字节裁剪/摘要/QA 保留**——这是 2.5 短期记忆问题的根因。

**对齐建议**
- 中期引入类 ChainAST 的**结构化消息模型**（至少区分 request/response/tool/summary，带 size），为压缩打基础。项目已有 `application/context/`（transcript_hygiene、context_compaction），应把安全模式的 worker 长输出接入统一压缩管线，而不是各自 1800 字符硬截断。

---

### 2.4 长期记忆（跨 campaign 知识沉淀）🔴 重点缺口

**PentAGI**（`backend/pkg/graphiti/`、`database.md`）
- **双记忆**：`pgvector` 存**可复用知识**（guide/answer/code），`Graphiti`(Neo4j) 存**执行历史/情景记忆**。
- 7 种检索：TemporalWindow / EntityRelationships / DiverseResults / EpisodeContext / **SuccessfulTools（成功攻击模式复用）** / RecentContext / EntityByLabel。
- 18 种工具执行后**自动入向量库**；Memory-first 策略（先查内部知识再联网）。

**本项目**（[memory_service.py](file:///g:/Code_Warehouse/Ai_Test_Agent/Enterprise_AI_QA_Agent/Agent_Server/src/modes/security_testing_mode/memory_service.py)）
- `SecurityMemoryService` 写 4 类 `ObservationRecord`（campaign_summary/finding_detail/failed_task/execution_record），并记录 `target_fingerprint/profile_key/surface_type/produced_finding`。
- `recall_successful_patterns()` 在 Campaign 规划前通过平台 pgvector 跨会话检索同目标指纹的成功 profile，过滤失败记录和不兼容 surface。
- `recon_planner` 把召回结果作为 advisory 优先级；低风险请求仍会过滤中高风险历史 profile。

**差距**：成功 profile 的读写闭环已经建立；与 PentAGI 的剩余差距主要是没有 Graphiti 情景图谱、关系检索和更丰富的时序/实体检索策略。

**对齐建议**
- 复用项目已有的 `postgres_vector_memory_store`(pgvector) 与 `memgraph`(已在技术栈内！) 搭建**成功攻击模式库**：finding + 触发它的 profile/命令 + 目标指纹 → 向量化入库。
- 新增一个 **SuccessfulTools 式检索**：规划阶段先按"目标指纹（技术栈/端口/服务）"召回历史成功 profile，喂给 planner。
- Memory-first：`recon_planner`/`vulnerability_planner` 生成计划前先查记忆库。

---

### 2.5 短期记忆（单 campaign 内上下文）

**PentAGI**（`chain_summary.md`）：csum 三阶段压缩——Section Summarization / Last Section Rotation(50KB) / QA Pair Summarization(64KB)；MaxBPBytes=16KB；最后一个 BodyPair 永不摘要；goroutine 并行摘要；LRU 缓存(1000/4h/SHA-256)；terminal/browser 结果 >16KB 自动摘要。

**本项目**：`SecurityTestingState` 仍全量 Pydantic 序列化进 `context_bundle`；worker 超阈值输出已进入确定性的结构感知压缩，优先保留 URL、CVE、端口、服务、状态和错误信号。

**差距**：已消除简单头部截断，但仍没有 csum 的分级摘要、最后 QA 对保护、LRU 缓存和 ChainAST 字节级状态管理。

**对齐建议**：把 worker 工具输出接入 `context_compaction_service` 做**语义摘要而非截断**；对 campaign_state 里的历史 execution_records 做"保留最近 N + 早期摘要"。

---

### 2.6 Agent 调度

**PentAGI**：Flow 独立 goroutine；`SubtaskController.PopSubtask` 逐个取；**每个 subtask 完成后 Refiner 重规划**；General agent ≤100 tool call、Limited ≤20；ExecutionMonitorDetector（同工具连 5 次/总 10 次触发 Mentor）；重复 3 次阻断；Reflector ≤3。

**本项目**（[subagent_coordinator.py](file:///g:/Code_Warehouse/Ai_Test_Agent/Enterprise_AI_QA_Agent/Agent_Server/src/modes/security_testing_mode/subagent_coordinator.py)）：`run_all` 循环批调度；`_select_batch` 按依赖+风险排序、尊重资源锁与并发≤3；每批 settle 后调用 Refiner 追加/删除/降级后续任务；无结构化结果触发有界 Reflector；execution_monitor 连续失败后由 Mentor 要求换 profile/路线；父 interrupt 会取消运行 Worker 并停止后续派发。

**差距**：核心闭环已对齐。PentAGI 仍在长期驻留 Flow、独立 Refiner/Mentor Agent、工具调用预算和更复杂任务树方面更完整。

**对齐建议**：在 `run_all` 每批 settle 后调用 `subtask_refiner`，允许**基于新发现动态追加/删改后续任务**（对齐 pentagi Refiner）。

---

### 2.7 Kali 镜像工具使用

**PentAGI**（`docs/docker.md`、`pkg/tools/terminal.go`）
- Image Chooser 自动选镜像（默认 vxcontrol/kali-linux，失败回退 debian）；每 Flow 分配 2 端口（28000+flowID*2）用于回连监听；NET_RAW+可选 NET_ADMIN；Bridge/Host 网络。
- `terminal` 封装 Docker Exec；支持 **detach 后台长任务**（500ms 探测即返回，`context.WithoutCancel`）；默认超时 1200s、硬顶 3h；`file` 工具用 tar API 读写容器文件；`browser` 用独立 scraper 容器。
- **容器内可跑任意 Kali 工具**，18 种工具结果自动入向量库。

**本项目**（[execution_environment_service.py](file:///g:/Code_Warehouse/Ai_Test_Agent/Enterprise_AI_QA_Agent/Agent_Server/src/application/security/execution_environment_service.py)、[command_profiles.py](file:///g:/Code_Warehouse/Ai_Test_Agent/Enterprise_AI_QA_Agent/Agent_Server/src/application/security/command_profiles.py)）
- `docker run -d ... tail -f /dev/null` 起容器，支持同步执行、detached 后台执行/轮询、`docker cp` 双向文件通道、输出产物收集和按运行清理。
- 预置 profile 除常规 recon/web/service/credential 外，已补 traffic/exploit 的 `tcpdump_timed_capture`、`searchsploit_exploit_lookup`、`msf_module_info`；每个带 parser、风险等级和审批要求。
- 受控自由命令默认关闭；开启后要求服务端审批标记、目标 allowlist、可执行文件白名单和破坏性模式拦截。Docker backend 可按固定映射 bootstrap 缺失工具。

**差距**
- 仍以注册 profile 和固定 bootstrap 为主，不能像 PentAGI Installer 一样任意扩展工具。
- 无镜像自选、回连端口分配、PTY 与多步交互式 exploit 会话。
- 合规审批更严格，这是产品边界差异，不应简单视为能力缺陷。

**对齐建议**（按合规诉求分档）
- 若定位"合规安全扫描"：保持 profile 白名单，但补 **detach 长任务** + **file 通道** + **结果入记忆库**。
- 若要"专业渗透"：在受控授权下开放**容器内自由命令通道**（带审批 + allowlist + 完整 stdout/stderr 回传），并补 exploit/后渗透 profile。

---

### 2.8 SSH / 终端长连接 🔴 重点缺口

**PentAGI**：**不用 SSH**，用 Docker Exec 达到等效效果——容器常驻（unless-stopped），detach 支持后台长命令，stdin/stdout 记入 TermLog 并实时推 GraphQL；缺点是工作目录不跨 exec 保持（需显式 cd）。

**本项目**：已有 detached 后台命令、轮询日志和容器复用，但每次仍是独立 `docker exec`；没有持久 PTY/SSH，也不保留 shell 工作态。

**差距**：长耗时非交互操作已可运行；需要**会话态/多步交互**的操作仍不支持。

**对齐建议**
- 短期：引入 **detach + 轮询/日志回读** 模式跑长任务（对齐 pentagi detach，不必上真 SSH）。
- 中期：如需交互式，封装**持久 PTY 会话**（`docker exec -it` + 附着流），或对远程 Kali 用 SSH 长连接池；无论哪种，务必遵守铁律——**子进程完整 stdout/stderr 必须回传给模型**。

---

### 2.9 专业渗透测试完整能力（侦察/扫描/利用/后渗透/横向/凭证/报告）

| 环节 | PentAGI | 本项目 | 结论 |
| --- | --- | --- | --- |
| 侦察 Recon | Searcher 7 引擎 + Sploitus + browser + memory-first | recon_planner + nmap/httpx + pgvector 成功 profile recall | 缺多源联网情报与图谱检索 |
| 扫描 Scanning | 容器内任意工具 + NET_ADMIN + 端口监听 | 16 只读 profile | 覆盖窄 |
| 利用 Exploitation | Pentester+Coder 容器实操、msf/sqlmap、hack_result | exploit runner + searchsploit/msf info 审批 profile；无完整利用链 | 🟠 受控部分能力 |
| 后渗透 Post-Exp | file/terminal 持久操作、Installer 装工具 | 双向文件/自由命令门控/固定 bootstrap；无持续 shell | 🔴 仍缺完整闭环 |
| 横向移动 | 可在容器编排多步 | ❌ 无编排 | 🔴 空缺 |
| 凭证管理 | 运行时获取凭证可复用 | auth_strategy 仅静态凭证 | 缺动态凭证复用 |
| 报告 Report | Reporter + 8 层日志 + 实时订阅 | report_builder(MD/JSON/HTML) + 事件流 | 🟢 基本对齐 |
| 可观测 | Langfuse 追踪 + GraphQL | 事件流 + observation | 缺 LLM 调用级追踪 |

**你可能没考虑到的部分（补充清单）**
1. **镜像/工具就绪性检查**：本项目已有固定映射 bootstrap，但仍缺 PentAGI 的 Image Chooser、通用 Installer 和换镜像兜底。
2. **回连与监听基础设施**：反弹 shell/监听端口需要端口分配与网络编排（本项目无）。
3. **授权与合规边界的机器化校验**：双层目标 allowlist、可信授权继承、参数级风险门和服务端审批标记已落地；后续应补授权撤销和审计保留策略。
4. **LLM 调用级可观测**：接入类 Langfuse 的 trace，便于复盘"模型为何选这个 profile"。
5. **成本/预算护栏**：pentagi 有 tool-call 上限分级；本项目有部分限流，可统一成"campaign 预算"。
6. **证据链完整性**：evidence_service 已有雏形，建议对齐 pentagi 的"每步截图/日志/命令原文"可回放证据链。
7. **Reflector/格式纠偏**：低成本高收益，优先补。

---

## 3. 分阶段改造路线图（按性价比排序）

**P0（已交付）**
- Reflector 回路、Mentor 换路线反馈、信号保留输出压缩、双层目标 allowlist。

**P1（已交付）**
- detach 后台长任务/日志回读、双向文件通道、每批 Refiner 动态重规划、父子中断传播。

**P2（部分交付，剩余需授权与合规评审）**
- 已交付：pgvector 成功 profile 召回、受控自由命令、traffic/exploit 只读/信息 profile、固定映射 bootstrap。
- 待交付：Memgraph 情景图谱、Coder 写码执行链、持久 PTY/远程 Kali SSH、镜像自选、通用 Installer、回连端口分配。

**P3（工程化增强）**
- 结构化消息模型（类 ChainAST）+ 按字节精确裁剪。
- LLM 调用级追踪（Langfuse 式）。

---

## 4. 对齐基线（写规则时的铁律，违反即回退）

> 这些直接来自 `DeepAgent-Studio.md` 精神 + pentagi 已验证做法，建议作为安全模式的开发红线。

1. **错误可见性**：任何执行器（docker exec / 未来 PTY / SSH）必须把子进程**完整 stdout/stderr 回传给模型**——空输出 + exit code 不可接受。
2. **失败必须升级**：同一 profile/工具滑动窗口内失败 ≥ 阈值 → 强制"换根本路线"（APPROACH CHANGE REQUIRED），不要在原路线上无限重试。
3. **附加物是参考不是指令**：skill/规则/记忆召回用参考性措辞，附"环境中反复失败即放弃该路线"逃生条款，不得门禁内置能力。
4. **授权边界机器化**：目标必须在 allowlist 内；越界、需提权、高危 profile 一律走审批（interrupt/resume），默认从严。
5. **选型有据**：新增执行通道/工具封装/记忆机制，必须对照 pentagi 具体位置或官方文档，禁止凭直觉；结论写进方案：`{pentagi 文件/官方文档} 的做法 → 本项目对齐方式`。
6. **架构缺失不打补丁**：如"无长连接"这类是**架构缺失**，应新增执行环境子系统，而不是在 `docker exec` 外再包一层 if。
7. **日志纪律**：状态机转换、工具执行、审批判定、降级/熔断都要有可检索结构化日志；密钥/payload 原文脱敏。

---

## 5. 关键文件索引（便于落地）

**本项目**
- 编排：[runtime.py](file:///g:/Code_Warehouse/Ai_Test_Agent/Enterprise_AI_QA_Agent/Agent_Server/src/modes/security_testing_mode/runtime.py)
- 状态：[campaign_state.py](file:///g:/Code_Warehouse/Ai_Test_Agent/Enterprise_AI_QA_Agent/Agent_Server/src/modes/security_testing_mode/campaign_state.py)
- 调度：[subagent_coordinator.py](file:///g:/Code_Warehouse/Ai_Test_Agent/Enterprise_AI_QA_Agent/Agent_Server/src/modes/security_testing_mode/subagent_coordinator.py) / [task_pool.py](file:///g:/Code_Warehouse/Ai_Test_Agent/Enterprise_AI_QA_Agent/Agent_Server/src/modes/security_testing_mode/task_pool.py)
- 执行环境：[execution_environment_service.py](file:///g:/Code_Warehouse/Ai_Test_Agent/Enterprise_AI_QA_Agent/Agent_Server/src/application/security/execution_environment_service.py) / [command_profiles.py](file:///g:/Code_Warehouse/Ai_Test_Agent/Enterprise_AI_QA_Agent/Agent_Server/src/application/security/command_profiles.py)
- 记忆：[memory_service.py](file:///g:/Code_Warehouse/Ai_Test_Agent/Enterprise_AI_QA_Agent/Agent_Server/src/modes/security_testing_mode/memory_service.py)
- 配置：`core/config.py` 的 `security_runner_*`

**PentAGI（参考位置）**
- 架构：`backend/docs/controller.md`、`backend/docs/flow_execution.md`
- 上下文：`backend/docs/chain_ast.md`、`backend/docs/chain_summary.md`、`backend/docs/prompt_engineering_pentagi.md`
- 记忆：`backend/pkg/graphiti/client.go`、`backend/docs/database.md`
- 执行：`backend/pkg/tools/terminal.go`、`backend/pkg/tools/tools.go`、`backend/docs/docker.md`

---

_本文基于对两套代码库的实读整理，用于指导 security_testing_mode 向专业渗透测试能力演进。落地任何一项前，请按第 4 节铁律先查证 pentagi 对应实现再动手。_

---

## 6. 2026-08-01 升级后实证

本轮升级以 commit `32516b1b` 为基线，并用指定 Python 3.11、真实 FastAPI 会话 API、内部 `qwen3.6-plus` 模型和 `vxcontrol/kali-linux` 验证，不以 mock 结果替代端到端证据。

| 能力 | 证据 | 结论 |
| --- | --- | --- |
| 动态调度闭环 | 自动化构造 nmap 发现 8443，Refiner 追加并执行 service detect；每批均有 Refiner 日志 | 对齐 PentAGI “边跑边改计划”的基础语义 |
| Memory-first | 会话 `8192f435-2584-4e0f-a6e4-2d76309ed22c` 召回同指纹的 `http_headers_probe/whatweb_fingerprint/httpx_probe` | 成功模式跨会话复用已成立，仍缺图谱层 |
| Docker 执行 | 8089/3000 多轮真实 Kali 执行；detached/file 有集成测试；每次 Runner 自动销毁 | 非交互式执行基础基本对齐 |
| 审批恢复 | 会话 `de695926-6f34-477c-9d52-97144b31c906` 生成参数绑定 approval，API 批准后 `searchsploit` exit code 0 | 高风险 profile 具备可审计的人机门控 |
| 父子中断 | 会话 `cd5ba722-2580-4108-9730-56aafce51922` 在首个 Worker 后 interrupt，子会话 interrupted，后两项未派发 | Coordinator 取消与收敛链路成立 |
| 目标 8089 | 会话 `03bf52df-e757-448f-a83a-d904291cc971`，3/3 完成，识别 XXL-JOB，4 个低风险发现 | 真实应用基线通过 |
| 目标 3000 | 会话 `7f0ba1e2-26c7-45d0-87ef-147316ad6075`，3/3 完成，识别 `blog-web`，4 个低风险发现 | 真实应用基线通过 |

自动化定向结果为 `75 passed, 1 skipped`；完整后端结果为 `284 passed, 1 skipped, 2 failed`，两个失败是 Windows 深路径下兼容性 Runner 测试产物写入的既有 `FileNotFoundError`。验证后活动模型恢复为 `agnes-2.0-flash`，3000 临时 IPv4 代理已停止，`qa-security-runner` 容器数量为 0。
