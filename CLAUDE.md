# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 仓库组成

**御策天检(智能自动化测试平台)**,内含两个独立子工程(各自后端+前端,共用一套 Docker 数据服务):

| 子工程 | 后端 | 前端 | 后端要点 |
|---|---|---|---|
| **项目A** AI Test Agent | `Agent_Server/` (FastAPI :8001) | `agent_web_server/` (Vite:5175) | 单体 LLM 适配器编排 + Browser-Use 执行 + Qdrant RAG |
| **项目B** Enterprise AI QA Agent | `Enterprise_AI_QA_Agent/Agent_Server/` (FastAPI+LangGraph :1032) | `Enterprise_AI_QA_Agent/agent_web/` (Vite+Electron :5176) | 多 Agent 编排 + 六大注册中心 + LangGraph |

## 导航(内容层在 docs/,按需加载)

- **运行/启停/测试命令**:见 [docs/RUN_COMMANDS.md](docs/RUN_COMMANDS.md)(start_all.py 用法、手动启后端/前端、依赖安装、pytest、端口总览)。
- **架构 big picture**(需读多文件才拼出的):见 [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)(入口链路、LLM 适配器、RAG 知识库、六注册中心、数据基础设施)。

## 硬性编码规范(战略层,不可违反)

- **后端启动 cwd 必须匹配 import 路径**:项目A 从**仓库根**启动(`Agent_Server.*`),项目B 从 `Enterprise_AI_QA_Agent/` 启动(`src.main:app`)。配错则 import 失败。
- **配置一律从 `.env` 读**(`python-dotenv`/`pydantic-settings`),严禁硬编码密钥;缺 HOST/PORT/CORS 时 Config 类直接 raise,故**改后端必先有 .env**。
- **启停只用 [start_all.py](start_all.py)** 或其记录的 PID/端口。禁止 `taskkill /IM node.exe` 按镜像名全杀(误伤用户其他进程)——脚本已封装精准 PID+端口 kill。
- **LLM 输出容错**:任一 Provider 的 JSON 解析走多层修复(剥推理标签→括号匹配→尾逗号→截断补全→json-repair),不要假设 LLM 返回干净 JSON。
- **扩展走工厂/适配器注册**:新增邮件服务商/项目管理平台/LLM Provider 一律走 `_PROVIDER_MAP` / 适配器注册,不改动现有调用方。
- **Windows 特例**:控制台默认 GBK,脚本需 `sys.stdout.reconfigure(utf-8)` / `PYTHONIOENCODING=utf-8`;asyncio 用 `WindowsProactorEventLoopPolicy`(入口已设)。vite 6 前端只绑 `::1`,端口探测要同试 IPv4+IPv6。
- **前端资源**:根路径 `/xxx.svg` 指 `public/`,新增静态资源放各前端的 `public/`。
- **项目B(Enterprise_AI_QA_Agent)开发强制遵循两份核心规范**(项目A 不受约束,为单体适配器架构):
  - **Harness Engineering 规范**:[Enterprise_AI_QA_Agent/docs/HARNESS_ENGINEERING_开发规范.md](Enterprise_AI_QA_Agent/docs/HARNESS_ENGINEERING_开发规范.md)。核心:任何 Agent 能力只有配套 8 层 Harness(上下文/任务/工具/执行/验证/评估/可观测/清理)才算完成;新增 Agent/Tool 必须先注册 + 给 schema + 接验证/评估/前端状态;执行 Agent 不得自判完成,需独立评估层;关键结论必须带证据引用。
  - **Claude Code UI Agent 全流程复刻规范**:[Enterprise_AI_QA_Agent/docs/Claude_Code_UI_Agent_全流程复刻规范.md](Enterprise_AI_QA_Agent/docs/Claude_Code_UI_Agent_全流程复刻规范.md)。核心:复刻 Claude Code 的完整运行骨架(8 层分层:启动/会话路由/REPL/输入预处理/递归执行/工具权限仲裁/状态持久化回放/远程会话协调者子代理)而非只做聊天页;用 FastAPI+LangGraph+Vue 按统一协议扩展;收敛到"可观察/可恢复/可扩展/可自动化测试"。
  - 两份规范与临时实现冲突时,**以规范为准**;接入新 Agent/Tool/页面前先说明归属哪层、schema、验证/评估与前端状态。
- **变更归档需经用户确认**(覆盖原"默认自动记录"规则):用 `write`/`edit` 改完代码/配置后,**不自动归档**,先问用户"要不要记录这次改动";用户明确说记才执行三步曲(decisions 文件 + CHANGELOG + 锚点区刷新最近 5 条)。未明确说要记则跳过。纯读、跑命令、装依赖不触发、也不问。本仓库(项目A、项目B)均生效。

## 最近变更索引

<!-- RECENT_INDEX_START -->
- 2026-07-30 修复 xlsx artifact 下载 500 + Content-Disposition/MIME type + tool 参数验证误拒空数组 -> 详见 [decisions/2026-07-30-xlsx-download-fix.md](docs/decisions/2026-07-30-xlsx-download-fix.md)
- 2026-07-29 编写一键启停脚本 start_all.py 并初始化架构导航三层结构 -> 详见 [decisions/2026-07-29-start_all-and-claudemd.md](docs/decisions/2026-07-29-start_all-and-claudemd.md)
<!-- RECENT_INDEX_END -->
