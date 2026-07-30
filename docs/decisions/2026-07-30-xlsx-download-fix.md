# 2026-07-30 修复 xlsx artifact 下载失败 + tool 参数验证误拒

## 背景

项目B(Enterprise AI QA Agent)中，用户在浏览器(Vite 开发服务器 localhost:5176)点击前端生成的 xlsx 下载链接时，弹出"无法下载出现问题"提示。同时 `test-case-xlsx-exporter` 工具调用时因参数验证误拒空数组而报"arguments are invalid"。

## 问题与根因

### 问题 1：xlsx 下载链接返回 500 Internal Server Error

**现象**：浏览器点击 `/api/v1/sessions/{id}/artifacts/{id}/content` 下载链接，弹出"无法下载出现问题"。

**根因**：`get_artifact_content` 端点(sessions.py:249)调用了 `request.app.state.tool_job_service._store.get_artifact(artifact_id)`，但 `PostgresToolJobStore` **没有 `get_artifact` 方法**，只有 `list_artifacts`。这导致 `AttributeError`，返回 500。

**次要问题**（修复 500 后暴露）：即使 `get_artifact` 存在，原代码的 `Content-Disposition` 头也缺少 RFC 5987 `filename*` 参数，中文文件名在 Chromium 中无法正确解析；且所有文件一律返回 `application/octet-stream`，xlsx 没有正确的 MIME type。

### 问题 2：test-case-xlsx-exporter 工具参数验证误拒

**现象**：LLM 调用 `test-case-xlsx-exporter` 时传入 `cases: []`，被 `_validate_tool_input` 拦截返回"arguments are invalid"。

**根因**：`_validate_tool_input`(tool_executor.py)将空数组 `[]` 视为"缺失必填字段"（`val == []` 判定为 missing），但 LLM（特别是 GLM-5.1）经常在不确定具体用例时先传空数组。验证直接拦截后 LLM 无法自行修正。

## 修改内容

### 1. 新增 `get_artifact` 方法（核心修复）

**文件**：`Enterprise_AI_QA_Agent/Agent_Server/src/runtime/postgres_tool_job_store.py`

- 新增 `async get_artifact(artifact_id)` → 委托 `_get_artifact_sync`
- 新增 `_get_artifact_sync(artifact_id)`：按 `id` 查询 `postgres_tool_artifact_table`，返回 `ToolArtifactRecord | None`

**文件**：`Enterprise_AI_QA_Agent/Agent_Server/src/runtime/tool_job_store.py`

- `ToolJobStore` Protocol 新增 `async get_artifact(artifact_id) -> ToolArtifactRecord | None`
- `InMemoryToolJobStore` 新增 `async get_artifact(artifact_id)` → `self._artifacts.get(artifact_id)`

**文件**：`Enterprise_AI_QA_Agent/Agent_Server/src/application/runtime/tool_job_service.py`

- 新增 `async get_artifact(artifact_id)` → 委托 `self._store.get_artifact(artifact_id)`

**文件**：`Enterprise_AI_QA_Agent/Agent_Server/src/api/routes/sessions.py`

- 将 `tool_job_service._store.get_artifact()` 改为 `tool_job_service.get_artifact()`，不再绕过 service 直接访问私有 `_store`

### 2. 修复 Content-Disposition 和 MIME type（下载体验修复）

**文件**：`Enterprise_AI_QA_Agent/Agent_Server/src/api/routes/sessions.py`

新增辅助函数和映射表：

- `_EXTENSION_MIME_MAP`：扩展名 → MIME type 映射（xlsx/xls/docx/pdf/csv/json 等 20+ 种）
- `_guess_media_type(filename, fallback)`：根据扩展名返回正确 MIME type
- `_content_disposition_attachment(filename)`：生成 RFC 6266/5987 合规的 `Content-Disposition` 头，同时包含 `filename=`（ASCII 回退）和 `filename*=`（UTF-8 编码）

修改 `get_artifact_content` 端点三个 Case：
- **Case 1 (MinIO)**：用 `_guess_media_type` 替换 generic MIME，用 `_content_disposition_attachment` 替换简单头
- **Case 2 (本地文件)**：将 `FileResponse` 替换为 `Response` + `read_bytes()` + 正确 headers（RFC 5987 Content-Disposition + 正确 MIME type）
- **Case 3 (Inline text)**：用 `_content_disposition_attachment` 替换简单头

移除了不再使用的 `FileResponse` import。

### 3. 放宽 tool 参数验证（工具调用修复）

**文件**：`Enterprise_AI_QA_Agent/Agent_Server/src/graph/nodes/tool_executor.py`

`_validate_tool_input` 中，将空数组 `[]` 从"缺失必填字段"判定中移除：

```python
# 修改前
if key not in arguments or arguments.get(key) is None or arguments.get(key) == "" or arguments.get(key) == []:
    errors.append(f"Missing required field: {key}")

# 修改后
val = arguments.get(key)
if key not in arguments or val is None or val == "":
    errors.append(f"Missing required field: {key}")
```

空数组交给 tool handler 处理，handler 返回有意义的错误消息（如"No test cases provided"），LLM 可据此正确重试。

## 完整数据流（修复后）

1. LLM 调用 `test-case-xlsx-exporter` → `_validate_tool_input` 放行空数组 → handler 生成 xlsx
2. `_save_artifacts` 存储 artifact 记录（xlsx 为 `storage_mode="path_only"`，不存 inline text）
3. `tool_runtime_service` 为 artifact 生成 `/api/v1/sessions/{id}/artifacts/{id}/content` URL
4. `responder.py` 将裸 URL 转为 `[⬇ 点击下载](url)` markdown 链接
5. 前端 `markdown.ts` 为链接添加 `download` 属性
6. 用户点击 → Vite 代理 `/api` → 后端 `get_artifact_content`
7. `tool_job_service.get_artifact()` → `PostgresToolJobStore.get_artifact()` 查询数据库
8. Case 2 匹配本地文件 → `Response` + 正确 MIME type + RFC 5987 Content-Disposition
9. 浏览器正确解析中文文件名，成功下载 xlsx

## 验证

- `curl` 直接请求 artifact 端点：HTTP 200，`content-type: application/vnd.openxmlformats-officedocument.spreadsheetml.sheet`，`content-disposition` 含 `filename*=UTF-8''` 编码
- 下载的 xlsx 文件被 openpyxl 正确解析（13行10列，含测试用例数据）
- 后端日志无 `AttributeError`

## 影响范围

- 修改文件（4 个）：
  - `Enterprise_AI_QA_Agent/Agent_Server/src/runtime/postgres_tool_job_store.py`（新增 `get_artifact`）
  - `Enterprise_AI_QA_Agent/Agent_Server/src/runtime/tool_job_store.py`（Protocol + InMemory 新增 `get_artifact`）
  - `Enterprise_AI_QA_Agent/Agent_Server/src/application/runtime/tool_job_service.py`（新增 `get_artifact` 公开方法）
  - `Enterprise_AI_QA_Agent/Agent_Server/src/api/routes/sessions.py`（Content-Disposition/MIME type 修复 + 调用路径修正）
  - `Enterprise_AI_QA_Agent/Agent_Server/src/graph/nodes/tool_executor.py`（放宽空数组验证）
- 不影响项目A（AI Test Agent），不影响数据库 schema，不涉及前端代码变更

## 附录：test-case-xlsx-exporter 工具从注册到 LLM 调用的完整链路

### 1. 工具注册（ToolRegistry）

**文件**：`Enterprise_AI_QA_Agent/Agent_Server/src/registry/tools.py:696-761`

工具在 `ToolRegistry._BUILTIN_TOOLS` 字典中静态注册，key 为 `"test-case-xlsx-exporter"`：

```python
"test-case-xlsx-exporter": ToolModule(
    descriptor=ToolDescriptor(
        key="test-case-xlsx-exporter",
        name="Test Case XLSX Exporter",
        description="Export structured test cases to an xlsx (Excel) file for download. ...",
        category="qa",
        permission_level="safe",
        input_schema={
            "type": "object",
            "properties": {
                "cases": {
                    "type": "array",
                    "description": "Array of test case objects to export...",
                    "items": { ... }  # 每个 case 的子字段定义
                },
                "feature": {
                    "type": "string",
                    "description": "Feature name for the xlsx filename.",
                },
            },
            "required": ["cases"],
        },
        output_schema={ "ok", "summary", "artifact_path", "case_count", "download_urls", "artifacts", "metrics", "error" },
        tags=["qa", "export", "xlsx"],
    ),
    handler_key="test-case-xlsx-exporter",
),
```

关键要素：
- **`input_schema`**：定义了 LLM 需要传入的参数结构（`cases` 数组 + 可选 `feature` 字符串），LLM 据此构造 function call 参数
- **`description`**：告诉 LLM 何时该调用此工具（"after generating test cases with the test-case-generator tool"）
- **`handler_key`**：映射到 `ToolRuntimeService._HANDLER_MAP` 中的实际执行函数
- **`permission_level="safe"`**：无需用户审批即可执行

### 2. Handler 绑定（ToolRuntimeService）

**文件**：`Enterprise_AI_QA_Agent/Agent_Server/src/application/runtime/tool_runtime_service.py:204`

```python
self._HANDLER_MAP = {
    ...
    "test-case-xlsx-exporter": self._run_test_case_xlsx_exporter,
    ...
}
```

当 `tool_executor` 节点收到 LLM 的 tool_call 后，通过 `handler_key` 查找此映射，调用对应的 handler 函数。

### 3. Handler 实现

**文件**：`Enterprise_AI_QA_Agent/Agent_Server/src/application/runtime/tool_runtime_service.py:1535-1667`

`_run_test_case_xlsx_exporter` 执行流程：

1. **参数提取**：`cases = arguments.get("cases") or []`，`feature = arguments.get("feature") or "test_cases"`
2. **空 cases 校验**：若 `cases` 为空，返回 `{"status": "failed", "error": "missing_cases"}`（由 handler 自身处理，不依赖 `_validate_tool_input`）
3. **openpyxl 生成 xlsx**：创建 Workbook → 写表头（带样式）→ 遍历 cases 写数据行 → 自动调整列宽
4. **保存到 artifact 目录**：`_prepare_local_artifact_dir()` 生成路径 `data/artifacts/{session_id}/{tool_key}/`，文件名 `{safe_feature}_test_cases.xlsx`
5. **返回结果**：包含 `artifacts` 数组（type/label/path），由 `mark_completed` → `_save_artifacts` 注册到数据库

### 4. Skill 关联（SkillRegistry）

**文件**：`Enterprise_AI_QA_Agent/Agent_Server/src/registry/skills.py:30-37`

```python
"case-design": SkillDescriptor(
    key="case-design",
    name="Case Design",
    tool_keys=["test-case-generator", "test-case-xlsx-exporter", "report-writer"],
),
```

`case-design` skill 声明了它使用的工具列表，包含 `test-case-xlsx-exporter`。

**文件**：`Enterprise_AI_QA_Agent/Agent_Server/src/SKILLS/case-design/SKILL.md`

SKILL.md 是 LLM 可读的技能指令文件，定义了调用工作流：

```markdown
## Tool Workflow
1. **Generate test cases**: Call `test-case-generator` tool
2. **Export to xlsx**: Call `test-case-xlsx-exporter` tool, passing the `cases` array from step 1
3. **Provide download link**: Copy the `download_markdown` string verbatim into your response
```

这确保 LLM 知道：先用 `test-case-generator` 生成用例，再用 `test-case-xlsx-exporter` 导出 xlsx，最后把下载链接原样输出。

### 5. Agent 关联（AgentRegistry）

**文件**：`Enterprise_AI_QA_Agent/Agent_Server/src/registry/agents.py:55-71`

```python
"qa-planner": AgentModule(
    descriptor=AgentDescriptor(
        key="qa-planner",
        supported_tools=["attachment-reader", "session-history", ..., "test-case-generator", "test-case-xlsx-exporter", "report-writer"],
        supported_skills=["requirements-analysis", "case-design"],
    )
)
```

`qa-planner` agent 的 `supported_tools` 直接包含 `test-case-xlsx-exporter`，`supported_skills` 包含 `case-design`。

### 6. LLM 如何发现并调用工具（Router → ModelInvoker）

**文件**：`Enterprise_AI_QA_Agent/Agent_Server/src/graph/nodes/router.py`

Router 节点在每轮对话开始时组装可用工具列表：

```python
# 从 agent 的 supported_skills 中提取关联工具
agent_skill_tools = [
    tool_key
    for skill in skill_registry.get_many(agent.supported_skills)
    for tool_key in skill.tool_keys
]
# 合并：skill 工具 + 已加载的 skill 工具
initial_tool_keys = list(dict.fromkeys(["skill", *loaded_skill_tools, *agent_skill_tools]))
# 能力解析 + 暴露策略过滤
tools = capability_resolver.eligible_tools(
    tools=tool_registry.get_many(initial_tool_keys), ...
)
tools = tool_exposure_policy.filter_supported(tools=tools, agent=agent)
state["available_tool_keys"] = [tool.key for tool in tools]
```

**文件**：`Enterprise_AI_QA_Agent/Agent_Server/src/graph/nodes/model_invoker.py:68`

ModelInvoker 节点将工具列表转换为 LLM API 的 function calling 格式：

```python
request_payload = ModelInvocationRequest(
    tools=tool_registry.build_model_tools(model_visible_tool_keys),
    ...
)
```

**文件**：`Enterprise_AI_QA_Agent/Agent_Server/src/registry/tools.py:2240-2249`

`build_model_tools` 将 `ToolDescriptor` 转为 LLM 能理解的格式：

```python
def build_model_tools(self, keys: list[str]) -> list[dict]:
    tools = self.get_many(keys)
    return [
        {
            "name": tool.key,           # "test-case-xlsx-exporter"
            "description": tool.description,  # 告诉 LLM 何时调用
            "input_schema": tool.input_schema,  # cases 数组 + feature 字符串
        }
        for tool in tools
    ]
```

### 7. 完整调用链路图

```
用户消息 "帮我生成测试用例并导出xlsx"
  │
  ▼
Router 节点
  ├─ 解析 agent → qa-planner (supported_skills=["case-design"])
  ├─ 从 case-design skill 提取 tool_keys → ["test-case-generator", "test-case-xlsx-exporter", "report-writer"]
  ├─ 合并到 available_tool_keys
  └─ 写入 state["available_tool_keys"]
  │
  ▼
ModelInvoker 节点
  ├─ tool_registry.build_model_tools(available_tool_keys)
  ├─ 转为 LLM function calling 格式 [{name, description, input_schema}, ...]
  └─ 发送给 LLM API
  │
  ▼
LLM 返回 tool_calls: [{name: "test-case-generator", arguments: {...}}]
  │
  ▼
ToolExecutor 节点
  ├─ _validate_tool_input: 校验参数（空数组现在放行）
  ├─ 查找 handler: _HANDLER_MAP["test-case-generator"] → _run_test_case_generator
  └─ 执行 handler → 返回 cases 数组
  │
  ▼
LLM 第二轮：看到 generator 结果，决定调用 xlsx exporter
  ├─ tool_calls: [{name: "test-case-xlsx-exporter", arguments: {cases: [...], feature: "..."}}]
  │
  ▼
ToolExecutor 节点
  ├─ _validate_tool_input: 校验通过
  ├─ handler: _run_test_case_xlsx_exporter
  │   ├─ openpyxl 生成 xlsx → 保存到 data/artifacts/.../xxx_test_cases.xlsx
  │   └─ 返回 {artifacts: [{type, label, path}]}
  ├─ mark_completed → _save_artifacts → 写入 postgres_tool_artifact_table
  └─ tool_runtime_service 注入 download_urls + download_markdown
  │
  ▼
Responder 节点
  ├─ _linkify_artifact_urls: 裸 URL → [⬇ 点击下载](/api/v1/sessions/.../artifacts/.../content)
  └─ LLM 输出包含下载链接
  │
  ▼
前端渲染
  ├─ markdown.ts: 识别 artifact URL → 添加 download 属性
  └─ 用户点击 → Vite 代理 → 后端 get_artifact_content → 200 + xlsx 文件流
```
