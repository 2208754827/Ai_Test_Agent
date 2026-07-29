# 2026-07-29 编写一键启停脚本 start_all.py 并初始化 CLAUDE.md

## 背景

仓库含两个独立子工程(项目A: `Agent_Server`+`agent_web_server`;项目B: `Enterprise_AI_QA_Agent/Agent_Server`+`agent_web`),各自后端+前端,共用一套 Docker 数据服务。此前无统一启停入口:数据服务靠手动 `docker start`、后端靠手动 `python`、前端靠手动 `npm run dev`,且缺文档化的架构导航。

## 修改内容

### 1. 新增 `start_all.py`(仓库根,自包含一键启停)

职责:拉起数据服务 → 后端×2 → 前端×2,全部以后台 detached 子进程运行,自动打开两个前端页(不打开 API 文档页)。

关键设计点与踩坑修复:

1. **Docker Desktop 自动拉起**:若 `docker ps` 失败(engine 未就绪),检测 `C:\Program Files\Docker\Docker\Docker Desktop.exe` 并 `subprocess.Popen` 启动,最长等待 180s 每 3s 轮询 `docker ps` 就绪。

2. **后端启动**:
   - 项目A:`[CONDA_AGENT_PYTHON, "Agent_Server/app.py"]`,cwd=仓库根(因 `app.py` 用 `Agent_Server.*` 绝对 import)。
   - 项目B:`[CONDA_AGENT_PYTHON, "Agent_Server/src/main.py"]`,cwd=`Enterprise_AI_QA_Agent`(因 main.py 用 `src.*` import,要求 cwd 是 `Agent_Server` 的父目录)。
   - conda 环境路径硬编码 `E:\anaconda\envs\agent\python.exe`。

3. **前端启动绕开 npm.cmd**:不调 `npm run dev`(npm.cmd 是批处理 shim,detached+stdin=DEVNULL 下会异常退出并把 vite 子进程带走),改为直接 `[node, "node_modules/vite/bin/vite.js"]`。

4. **端口探测兼容 IPv6**:vite 6(项目B)默认只绑 `::1`(IPv6 localhost),不绑 `127.0.0.1`;vite 5(项目A)绑 `0.0.0.0`。`port_open()` 改为同时探测 `127.0.0.1` 与 `::1`(`socket.AF_INET`/`AF_INET6`)。

5. **乱码修复**:Windows 控制台默认 GBK,Python print UTF-8 中文乱码;脚本顶部 `sys.stdout.reconfigure(encoding="utf-8")`(旧 Python 回退 `io.TextIOWrapper`)。

6. **精准停止(绝不误伤)**:
   - 优先用记录的 PID `taskkill /F /T`(带进程树)。
   - PID 记录缺失时,按端口反查 `OwningProcess`(`Get-NetTCPConnection -State Listen`)兜底。
   - **严禁** `taskkill /IM node.exe` 按镜像名全杀——会误杀用户其他 node 进程。

7. **Docker 容器**:启动 qa-redis/qa-minio/qa-memgraph/qa-pgvector;MySQL(3306)复用宿主机实例(root 密码 test),脚本只探测不拉起。

### 2. 初始化 `CLAUDE.md`(战略导航层)
- 摘录两个子工程的入口、cwd 约束、依赖、Docker 服务、架构导航(LCM 适配器/六大注册中心/RAG 知识库等需读多文件才理解的 big picture)。
- 设锚点 `<!-- RECENT_INDEX_START/END -->`,只放变更索引(5 条倒序),不放 Diff。

### 3. 建立归档三层结构
- `CLAUDE.md`:战略层(<5KB),硬规则 + 架构索引 + 最近变更锚点。
- `docs/CHANGELOG.md`:精简索引(顶部追加)。
- `docs/decisions/<时间戳>-<功能>.md`:详细记录(本文即首条)。

### 4. 副带修复
- 项目B 前端缺 `public/logo.svg`(AppTopBar.vue 等 5 处引用 `/logo.svg`),从 `docs/public/logo.svg` 拷贝到 `Enterprise_AI_QA_Agent/agent_web/public/logo.svg`。

## 影响范围

- 新增文件:`start_all.py`、`CLAUDE.md`、`docs/CHANGELOG.md`、`docs/decisions/2026-07-29-start_all-and-claudemd.md`、`Enterprise_AI_QA_Agent/agent_web/public/logo.svg`。
- 新增目录:`logs/`(运行日志,已在 .gitignore 范畴)、`docs/decisions/`。
- 不改动任何既有业务代码与 `.env` 文件;两个后端导入路径、前端构建脚本均维持原样。

## 验证

- `python start_all.py stop`:9 个服务精准停止(乱码已消除,无残留)。
- `python start_all.py start`:9 个服务全部 UP(MySQL/Postgres/Redis/MinIO/Memgraph + 两个后端 + 两个前端)。
- 前端页 `/logo.svg` 返回 200,覆盖报错消失。
- `python start_all.py status`:表格化展示各端口状态。
