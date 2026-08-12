---
trigger: always_on
---

# DeepAgent-Studio 开发铁律：对齐成熟架构与官方文档，不缝补丁、不摸瞎

本项目是**为 DeepSeek 量身定制的 Agent 工作台**，后端为 **Rust**，目标是复刻 Claude Code 级执行内核。**任何架构、选型、技术点、代码生成，都必须有权威依据（成熟参考项目 / 官方文档）；严禁凭直觉自创，严禁只打局部补丁。自己想的永远不如官方技术文档权威。**

**重点是系统底层（后端 Rust 内核）；前端并非不管——凡后端改动涉及前后端交互（Tauri command 签名、事件、数据契约），必须同步更新前端并保持一致，避免前后端脱节。**

## 信源优先级（按此顺序查证，命中即停）

**A. 行为机制 / 架构**（工具循环、权限、Hook、Skill/CLAUDE.md 注入、压缩、子代理、取消、状态机、系统提示词）——本地 `G:\Code_Warehouse\DeepAgent-Studio\借鉴`：
1. **Claude Code**（`借鉴\claudecode`，restored-src / package）—— 行为机制第一信源。
2. **Codex**（`借鉴\codex\codex-rs`，Rust）—— 与本项目同语言，架构/状态机/取消/沙箱执行直接对照；**代码审查触发链（`/review` 命令、审查专用流程）以它为准**。
3. **Grok**（`借鉴\grok-build`，Rust）—— 模型交互、流式、工具协议。
4. **其它本地参考**：DeepSeek-Reasonix（Go 桌面 Agent，会话/恢复/心跳/沙箱）、Kun。
5. **能力增强参考**（为本系统增强而引入，接入时同样先读源码再动手）：
   - **open-code-review**（`借鉴\open-code-review`，Go）—— 代码审查能力：审查规则引擎、diff 审查、`delegate` 宿主代理委托模式、plugins/skills 接入形态。
   - **better-harness**（`借鉴\better-harness`）—— 让 AI 写好代码的 harness 工程：hooks、skills、agent 资产组织、case-studies 经验库。

**B. Rust 技术点 / 库选型 / 语言用法**：
- 优先看参考项目（codex-rs、grok-build）里同类技术用哪个 crate、怎么组织；
- 再查 **Rust 官方文档 / std / docs.rs / 该 crate 官方文档**；
- **禁止**凭记忆臆造 API、crate 名、feature、版本行为——以官方文档为准。

**C. 参考项目都没有的技术点**（如 Windows 沙箱用的是**微软官方 Sandboxie / Windows Sandbox**、Job Object、Win32 API 等）：
- **必须查对应官方文档**（Microsoft Learn / Sandboxie 官方文档 / Win32 API 手册）；
- 官方怎么规定就怎么做，不得用"应该是这样"的猜测实现系统底层能力。

**D. 模型侧**：以 **DeepSeek 官方手册**（联网）为准——模型能力、API 参数、Thinking/reasoning_effort、function calling、上下文窗口、限流等，不得沿用 Claude/OpenAI 的假设。

**E. 联网检索**：仅当上述本地信源与官方文档都无对应时才用，优先官方/一手来源。

> 查证结论必须写进方案：`{信源项目/官方文档 + 具体位置} 的做法 → 本项目的对齐方式`。冲突裁决：行为逻辑以 Claude Code 为准、Rust 工程实现以 Codex 为准、模型侧以 DeepSeek 官方为准、OS/沙箱以微软官方为准。

## 能力增强接入要求（open-code-review / better-harness）

- **代码审查触发方式**：先对照 **codex 的 `/review` 实现**（触发入口、前端命令、审查会话形态）再设计本系统方案。基线：**手动触发**走前端 `@`/斜杠命令（对齐 codex）；**AI 写代码任务的自动触发**（写任务完成后自动审查一轮）作为可选增强，需先在 codex/claudecode 中查证是否有对应机制，无对应则按"自创从宽"处理——审查结果只作反馈，不得变成误杀 run 的门卫。
- **审查执行通道**：优先用 open-code-review 的 `delegate` 模式（输出结构化审查规格，由 DeepSeek 模型执行审查），CLI 已作为 devDependency 存在（`pnpm review` / `npx ocr`）。
- **better-harness 的用法**：其 hooks/skills/资产组织作为"让 AI 写好代码"的参考蓝本，接入本系统时必须遵守"附加物是参考不是指令"基线，不得压制内置工具。

## 强制工作流

1. **先查证再动手**：任何行为机制、库选型、系统底层技术点，先按 A–E 找到权威依据并引用具体文件/文档位置，禁止无依据就写代码。
2. **要完整架构，不要补丁**：修复前先判断"这是补丁还是架构缺失"。同类问题反复出现（如 CompletionGate 连环误杀）即为架构错位——**必须对照信源重构该子系统，而非在旧结构上再加一层判断**。
3. **选型有据**：引入/更换任何 crate、系统 API、脚手架、算法时，必须说明依据来源（参考项目在用 / 官方文档推荐），不得只凭"常见""应该"。
4. **前后端同步**：改动 Tauri command、事件名、payload/DTO 结构时，必须同时更新前端调用与类型（`api.ts`/`types.ts` 等），并核对一致，禁止只改一侧造成脱节。
5. **无对应才自创**：所有信源与官方文档都无对应时才允许自设计，代码中标注 `// No upstream counterpart (checked: claudecode/codex/grok/official docs):` + 理由。
6. **自创机制默认从宽**：自创的"门卫/校验/强制"逻辑（如 CompletionGate）宁可漏过、不可误杀——误杀正确执行的 run 比没有门卫更糟。
7. **真实失败样本回归**：修行为缺陷时，回归测试必须用日志/会话抓到的真实失败 prompt 与数据，不允许只造理想化用例。

## 日志纪律（排查问题的生命线）

- **习惯性打日志**：新增/修改任何核心路径（状态机转换、工具执行、Hook 派发、权限判定、配置加载、压缩、恢复、取消、降级/熔断）时，**必须同步补结构化日志**——判定标准：该路径出问题时，仅凭日志能还原"发生了什么、为什么走到这一步"。
- **格式统一，走既有双路日志，不得另起炉灶**：
  - 诊断日志 → `runtime-logs.db`：统一经 `append_runtime_log` + `NewRuntimeLogEntry`，字段齐全（`level` / `category` / `event` / `message` / `data_json`，并尽量带 `run_id` / `session_id` / `source`）；
  - 产品事件 → `run_events`：可回放的状态机事实，经内核事件通道落库。
- **命名与结构**：`event` 用 snake_case 动词短语（如 `registry_ready`、`input_queued`）；上下文一律放 `data` 结构化 JSON 字段，**禁止把变量拼进 message 字符串**了事。
- **失败路径必留痕**：任何 `Err` 返回、静默降级、fallback、熔断触发点，都必须有一条可检索的日志（含原因与关键参数），禁止吞错。
- **脱敏红线**：日志不得记录 API key/密钥/prompt 原文（runtime-logs 只记长度；密钥经 redaction 清洗），新日志点必须遵守。

## 已验证的对齐基线（违反即回归）

- **错误可见性**：任何执行器（含沙箱）必须把子进程完整 stdout/stderr 回传给模型。自纠错完全依赖看得见报错——空输出 + exit code 不可接受。
- **附加物永远是参考，不是指令**：Skill/规则正文注入用参考性措辞，附"环境中反复失败即放弃该路线"逃生条款；附加物（skill/MCP/rules）不得门禁或压制内置工具。
- **失败必须升级**：同一工具滑动窗口内失败 ≥4 次 → 反馈升级为强制换根本路线（APPROACH CHANGE REQUIRED），优先内置能力与零依赖路线。
- **外部配置须校验**：兼容读取 `~/.claude/*` 等外部配置时，值必须验证对本 provider 有效（如 model 名必须存在于目录），无效则忽略而非透传。
- **完成校验以事实为准、从用户短指令推导**：CompletionPolicy 只能从用户原始短指令提取要求，绝不扫描附件/粘贴正文/文件内容；提取结果必须有数量上限与合法性过滤（中文全角标点、CJK 粘连已多次误伤）。
- **模型侧一律以 DeepSeek 官方为准**：Thinking/reasoning_effort、max_tokens、function calling 格式、上下文窗口、限流重试策略等，不得照搬 Claude/OpenAI 的取值。

## 已知踩坑速查（详见 memory）

- Sandboxie `Start.exe` 不中继沙箱内输出 → 已用工作区重定向回读修复，勿回退。
- 中文 prompt 全角标点（：，；）粘连进"必须路径" → 路径提取按路径合法字符切段，勿改回空格分词。
- skill 命令式全文重注入曾锁死模型策略 → 保持参考性措辞。
- 测试须隔离用户主目录：`DualConfigLoader` 会读真实 `~/.claude/settings.json`，测试用 `with_user_home(None)`/临时目录。
- 写工作区外文件（如本规则文件）受沙箱写限制 → 需提权执行。
