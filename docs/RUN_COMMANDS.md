# 运行环境与常用命令

> 本文是 CLAUDE.md 的「内容层」,记录启停/启依赖/测试的完整命令清单。CLAUDE.md 仅保留指针。

## 一键启停(推荐)

仓库根 [start_all.py](../start_all.py) 负责拉起全部 9 个服务(数据服务×5 + 后端×2 + 前端×2)+ 自动打开两个前端页:
```
python start_all.py            # 启动:Docker→后端×2→前端×2,并打开两个前端页
python start_all.py start --no-open  # 只启动,不开浏览器
python start_all.py stop       # 精准停止(按 pid/端口,绝不按镜像名全杀)
python start_all.py restart    # 先停后启
python start_all.py status     # 查看各端口监听状态
```
- Docker Desktop 未运行时,start_all.py 会**自动拉起并等待 engine 就绪**(~180s)再 `docker start` 容器。
- 日志写到 `logs/`(backend_a/b.log、frontend_a/b.log),pid 记录 `logs/pids.json`。
- 启停**只用本脚本**或脚本记录的 PID/端口操作;禁止 `taskkill /IM node.exe` 之类按镜像名全杀(会误伤用户其他进程)。

### Docker 数据服务容器名
qa-redis(6379) / qa-minio(9000) / qa-memgraph(7687) / qa-pgvector:5432(见 start_all.py)。MySQL(3306)复用宿主机已装实例(root 密码 test),脚本只探测不拉起。

## 后端手动启动

conda `agent` 环境,Python = `E:\anaconda\envs\agent\python.exe`:
- 项目A:**仓库根目录**执行 `python Agent_Server/app.py` → :8001
- 项目B:`Enterprise_AI_QA_Agent/` 目录执行 `python Agent_Server/src/main.py` → :1032

> **启动 cwd 必须与 import 路径匹配**:项目A 从仓库根启动(`Agent_Server.*`),项目B 从 `Enterprise_AI_QA_Agent/` 启动(`src.main:app`,main.py 会自行修 sys.path)。

各自依赖 `.env`(见 `Agent_Server/.env.example` 与 `Enterprise_AI_QA_Agent/Agent_Server/.env.example`)。**必须先有 `.env`**,Config 类会在缺 HOST/PORT/CORS 时直接 raise。

## 前端手动启动

- 项目A:`cd agent_web_server && npm install && npm run dev`
- 项目B:`cd Enterprise_AI_QA_Agent/agent_web && npm install && npm run dev:app`(只起应用;`npm run dev` 会同时起 VitePress 文档)
- vite 6(项目B)默认只绑 **::1(IPv6)**,探测端口要同时试 `127.0.0.1` 和 `::1`(start_all.py 的 `port_open` 已处理)。

## 依赖安装

- 项目A:`cd Agent_Server && pip install -r requirements.txt && playwright install chromium`
- 项目B:`cd Enterprise_AI_QA_Agent/Agent_Server && pip install -e .[dev]`(pyproject.toml)
- 前端:各自 `npm install`。

## 测试

- 项目B 后端:`cd Enterprise_AI_QA_Agent/Agent_Server && python -m pytest tests/`(单测:`pytest tests/test_xxx.py::test_name`)
- 项目A 测试零散,跑指定文件即可:`pytest <path>`
- 全流程脚本:**Enterprise_AI_QA_Agent/scripts/run_today_fullflow_tests.py**

## 端口总览

| 服务 | 端口 |
|---|---|
| MySQL(宿主机) | 3306 |
| Postgres(qa-pgvector) | 5432 |
| Redis(qa-redis) | 6379 |
| MinIO(qa-minio) | 9000 |
| Memgraph(qa-memgraph) | 7687 |
| 后端A Agent_Server | 8001 |
| 后端B Enterprise | 1032 |
| 前端A agent_web | 5175 |
| 前端B Enterprise agent_web | 5176 |
