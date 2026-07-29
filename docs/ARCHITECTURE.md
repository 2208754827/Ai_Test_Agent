# 架构导航(读多文件才能拼出的 big picture)

> 本文是 CLAUDE.md 的「内容层」,记录两个子工程的核心架构索引。CLAUDE.md 仅保留指针。

## 项目A — Agent_Server(单体 FastAPI + LLM 适配器)

- 入口 [Agent_Server/app.py](../Agent_Server/app.py) → 路由集中注册在 [Agent_Server/Basic/routes.py](../Agent_Server/Basic/routes.py)(19 个 router) → config 在 [Agent_Server/Basic/config.py](../Agent_Server/Basic/config.py)(.env 驱动,缺 HOST/PORT/CORS 直接 raise) → lifespan 在 [Agent_Server/Basic/startup.py](../Agent_Server/Basic/startup.py)。
- **LLM 适配器(核心)**:`Agent_Server/llm/` 采用 Adapter Pattern,`factory.py` 按注册表创建 Provider,每个 Provider 自带 `parse_json_response()` + `json-repair` fallback;`wrapper.py`(`LLMWrapper`)统一拦截 `ainvoke` 做 JSON 清洗/action 别名映射;`auto_switch.py` 负责模型 429/失败自动切换(`FailoverChatModel`)。
- **一键测试**:`Agent_Server/OneClick_Test/` 持有三级任务树(task_tree L1 意图 / L2 功能规划 / L3 原子用例)、循环检测、模板+LLM 混合生成、Skills 便签注入、与页面知识库共享同一条 Browser-Use 探索链路。
- **页面知识库(RAG)**:`Agent_Server/Page_Knowledge/` 用 Qdrant 存页面结构 embedding,精确匹配优先 → 语义检索(阈值 0.82)兜底,`diff_engine` 做页面变更比对推荐回归范围;模块初始化时自动注入 `NO_PROXY` 防系统代理拦截本地 Qdrant。
- **渗透测试**:`Agent_Server/Pentest_Agent/`(PentAGI 复刻)Flow→Task→Subtask 三层 + Docker 沙箱(`vxcontrol/kali-linux`)+ Qdrant 项目隔离记忆。
- **邮件服务工厂**:`Agent_Server/Email_manage/sender.py` 用 `_PROVIDER_MAP` + `dispatch_send`,新增服务商只加一个 `_send_via_xxx` 并注册,不改动调用方。
- **多平台集成**:`Agent_Server/Project_manage/` 用 Factory Pattern 接入 11 个项目管理平台(禅道/Jira/PingCode/TAPD/ONES/云效/Worktile/8Manage/MS Project/Asana/ClickUp),每平台 Config/Cases/Bugs 三组件。
- **前端** [agent_web_server/](../agent_web_server/):Vue3 + Naive UI,API 经 Vite 代理转发到 :8001。

## 项目B — Enterprise Agent_Server(FastAPI + LangGraph 多 Agent 编排)

- 入口 [Enterprise_AI_QA_Agent/Agent_Server/src/main.py](../Enterprise_AI_QA_Agent/Agent_Server/src/main.py) → lifespan 装配各 application service → 14 组路由(前缀 `/api/v1`)。
- **六大注册中心** `src/registry/`:agents / tools / models / skills / mcp / modes,Agent/Tool/Runtime 扩展走统一协议。
- **测试模式** `src/modes/`:8 种编排实现(api_testing / code_review / compatibility / performance / security / smoke / ui_automation / default)。
- **核心文档**(开发前必读,定义运行骨架契约):
  - [Enterprise_AI_QA_Agent/docs/Claude_Code_UI_Agent_全流程复刻规范.md](../Enterprise_AI_QA_Agent/docs/Claude_Code_UI_Agent_全流程复刻规范.md)
  - [Enterprise_AI_QA_Agent/docs/HARNESS_ENGINEERING_开发规范.md](../Enterprise_AI_QA_Agent/docs/HARNESS_ENGINEERING_开发规范.md)
- **数据基础设施** `src/infrastructure/`:适配 Postgres(pgvector 记忆)/MySQL/Memgraph(知识图谱)/Redis/MinIO(产物)。`.env` 里 `MEMORY_BACKEND`/`SESSION_BACKEND`/`TOOL_JOB_BACKEND`/`ARTIFACT_STORAGE_BACKEND`/`UI_GRAPH_BACKEND` 等开关决定后端选型。
- **Docker 管理**:`src/api/routes/docker.py` 提供 Docker 容器生命周期管理(容器前缀 `qa-agent`,与 start_all.py 的数据服务容器名 `qa-redis/qa-minio/...` 区分开)。
- **MCP**:`src/application/mcp/` 连接管理 + 工具桥接,stdio 命令白名单(`MCP_STDIO_COMMAND_ALLOWLIST`)。
- **凭证加密**:渠道令牌(QQ/飞书/Lark/微信)用 `CHANNEL_CREDENTIAL_ENCRYPTION_KEY`(Fernet)加密后存库。
- **前端** [Enterprise_AI_QA_Agent/agent_web/](../Enterprise_AI_QA_Agent/agent_web/):Vue3+Vite+Naive UI,支持 Electron 打包(产物「御策天检.exe」);`npm run dev` 会并行起应用(:5176)与 VitePress 文档站。`src/scripts/dev-all.mjs` 编排多服务。
