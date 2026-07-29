# 2026-07-29 CLAUDE.md 瘦身:抽离内容层到 docs/

## 背景

此前 `CLAUDE.md` 7.8KB,超用户设定的 5KB 上限。根因:架构导航(两条子工程的 big picture)与运行命令清单(一键启停/手动启/依赖/测试)占了大头,这些是「可一次性摊开读懂」的内容,不属于战略层。

## 修改内容

### 1. 抽离「内容层」到独立 docs 文件
- 新建 **[docs/ARCHITECTURE.md](../ARCHITECTURE.md)**:两个子工程的架构导航(入口链路、LLM 适配器、RAG 知识库、渗透测试、六大注册中心、测试模式、数据基础设施、MCP、Electron 前端等)。
- 新建 **[docs/RUN_COMMANDS.md](../RUN_COMMANDS.md)**:start_all.py 一键启停、后端/前端手动启依赖、pytest、端口总览表。

### 2. CLAUDE.md 瘦身为战略层
精简后仅保留:
- 仓库组成表(两子工程一览)
- 导航(两个指针链接,按需加载 docs)
- 硬性编码规范(战略级、不可违反的 7 条)
- 最近变更索引锚点区(`<!-- RECENT_INDEX_START/END -->`)

删除:详细架构段落、完整命令清单及说明——这些移入 docs/。
保留:cwd 约束、.env 强制、精准 kill、LLM 容错、扩展模式、Windows 特例等「一违反就出错」的硬规则(精简到一句话级)。

### 3. 三层结构最终形态
- `CLAUDE.md`(~3.0KB,战略层)≤5KB
- `docs/CHANGELOG.md`(精简索引)
- `docs/decisions/<时间戳>-<功能>.md`(详细记录)
- `docs/ARCHITECTURE.md`、`docs/RUN_COMMANDS.md`(可摊开的内容层,按需读)

CLAUDE.md 不再承载可摊开内容,只通过指针指向;会话启动只读 CLAUDE.md,需要时再精确读单个 docs。

## 影响范围

- 新增:`docs/ARCHITECTURE.md`、`docs/RUN_COMMANDS.md`、`docs/decisions/2026-07-29-claudemd-split.md`。
- 改写:`CLAUDE.md`(瘦身)、`docs/CHANGELOG.md`(顶部加新记录)。
- 不改任何业务代码、`.env`、`start_all.py`。

## 验证

`wc -c CLAUDE.md` 瘦身后 <5KB;锚点区仅含最新索引,标记区外文字未动。
