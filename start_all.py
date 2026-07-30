#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AI Test Agent 一键启动 / 停止脚本
================================

用法:
    python start_all.py              # 启动全部服务,并自动打开浏览器
    python start_all.py start        # 同上
    python start_all.py start --no-open   # 启动但不自动打开浏览器
    python start_all.py stop         # 停止全部本进程拉起的服务
    python start_all.py status       # 查看各端口监听状态
    python start_all.py restart      # 先停后启(重启后也会自动打开浏览器)

说明:
    - 数据服务(MySQL/Postgres/Redis/MinIO/Memgraph):
      MySQL 复用宿主机已安装的 mysqld(root 密码 test, 端口 3306),脚本只探测;
      Postgres/Redis/MinIO/Memgraph 走 docker 容器 qa-pgvector/qa-redis/qa-minio/qa-memgraph。
      若 Docker Desktop 未运行,脚本会自动拉起并等待 engine 就绪(最长 ~180s),
      再 `docker start` 四个容器。
    - 后端用 conda 的 `agent` 环境 (E:\\anaconda\\envs\\agent)。
    - 前端用 node 直跑 vite 入口(绕开 npm.cmd 批处理 shim)。
    - 全部以后台 detached 子进程方式启动,日志写入 ./logs/。
    - 启动成功后用默认浏览器打开两个项目的前端页面;
      加 --no-open 可跳过自动开页。
    - 关闭本脚本不影响已启动的进程;电脑重启后需重新运行本脚本。
"""

import io
import os
import sys
import time
import socket
import signal
import subprocess
import argparse
import shutil
import webbrowser
from pathlib import Path

# 强制 stdout/stderr 用 UTF-8,避免 Windows 控制台中文乱码
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
        os.environ.setdefault("PYTHONIOENCODING", "utf-8")
    except Exception:
        # 极旧 Python 无 reconfigure,回退到包装
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", line_buffering=True)
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", line_buffering=True)

# ============================================================
# 配置区
# ============================================================

# 仓库根目录 = 本脚本所在目录
REPO_ROOT = Path(__file__).resolve().parent

# conda agent 环境 python
CONDA_AGENT_PYTHON = r"E:\anaconda\envs\agent\python.exe"

# node 走 PATH;前端直接用 node 跑 vite 入口,绕开 npm.cmd 批处理 shim
NODE = shutil.which("node") or "node"

# docker 容器(数据服务)
DOCKER_DATA_CONTAINERS = ["qa-redis", "qa-minio", "qa-memgraph", "qa-pgvector"]

# Docker Desktop 可执行文件(已存在则自动拉起;拉起后等待 docker engine 就绪)
DOCKER_DESKTOP_EXE = r"C:\Program Files\Docker\Docker\Docker Desktop.exe"
DOCKER_START_TIMEOUT = 180  # docker engine 就绪最长等待秒数

# 端口定义
PORTS = {
    "mysql_host":  3306,   # 宿主机 MySQL (root/test)
    "postgres":    5432,   # qa-pgvector
    "redis":       6379,   # qa-redis
    "minio":       9000,   # qa-minio
    "memgraph":    7687,   # qa-memgraph
    "backend_a":   8001,   # Agent_Server
    "backend_b":   1032,   # Enterprise AI QA Agent
    "frontend_a":  5175,   # agent_web_server
    "frontend_b":  5176,   # Enterprise agent_web
}

# 各服务启动定义
# cmd: 命令行; cwd: 工作目录; http: 是否通过端口探测(非 HTTP 用 None)
SERVICES = {
    "backend_a": {
        "label": "后端A Agent_Server (8001)",
        "cmd":   [CONDA_AGENT_PYTHON, "Agent_Server/app.py"],
        "cwd":   str(REPO_ROOT),
        "log":   "backend_a.log",
    },
    "backend_b": {
        "label": "后端B Enterprise (1032)",
        "cmd":   [CONDA_AGENT_PYTHON, "Agent_Server/src/main.py"],
        "cwd":   str(REPO_ROOT / "Enterprise_AI_QA_Agent"),
        "log":   "backend_b.log",
    },
    "frontend_a": {
        "label": "前端A agent_web_server (5175)",
        "cmd":   [NODE, "node_modules/vite/bin/vite.js"],
        "cwd":   str(REPO_ROOT / "agent_web_server"),
        "log":   "frontend_a.log",
    },
    "frontend_b": {
        "label": "前端B Enterprise agent_web (5176)",
        "cmd":   [NODE, "node_modules/vite/bin/vite.js"],
        "cwd":   str(REPO_ROOT / "Enterprise_AI_QA_Agent" / "agent_web"),
        "log":   "frontend_b.log",
    },
}

# 启动顺序:先数据服务 → 再后端 → 再前端
START_ORDER = ["backend_a", "backend_b", "frontend_a", "frontend_b"]

# PID 记录文件
PID_FILE = REPO_ROOT / "logs" / "pids.json"

# ============================================================
# 工具函数
# ============================================================

LOG_DIR = REPO_ROOT / "logs"
LOG_DIR.mkdir(exist_ok=True)

# Windows 下,subprocess 默认会弹黑框;用 CREATE_NO_WINDOW 隐藏
CREATE_FLAGS = 0
DETACHED_FLAGS = 0
DETACHED_PROCESS = 0x00000008
CREATE_NEW_PROCESS_GROUP = 0x00000200
CREATE_NO_WINDOW = 0x08000000


def info(msg):
    print(f"[*] {msg}")


def ok(msg):
    print(f"[+] {msg}")


def warn(msg):
    print(f"[!] {msg}")

def err(msg):
    print(f"[x] {msg}")


def port_open(port, host="127.0.0.1", timeout=0.5):
    """检测 TCP 端口是否监听。同时探测 IPv4 与 IPv6 ——
    vite 6 默认只绑定 ::1(IPv6 localhost),vite 5 绑 0.0.0.0,
    逐个探测以兼容二者。"""
    # 探测地址优先级:IPv4 回环 :: IPv6 回环 :: 通配
    candidates = ["127.0.0.1", "::1"] if host in ("127.0.0.1", "localhost") else [host]
    for h in candidates:
        try:
            fam = socket.AF_INET6 if ":" in h else socket.AF_INET
            with socket.socket(fam, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect((h, port))
                return True
        except OSError:
            continue
    return False


def wait_port(port, name, timeout=45):
    """等待端口上线"""
    info(f"等待 {name} 端口 {port} 就绪 ...")
    deadline = time.time() + timeout
    while time.time() < deadline:
        if port_open(port):
            ok(f"{name} 端口 {port} 已就绪")
            return True
        time.sleep(1)
    warn(f"{name} 端口 {port} 在 {timeout}s 内未就绪")
    return False


def run(cmd, cwd=None, check=False, capture=False):
    """统一 subprocess 调用(隐藏窗口)"""
    kwargs = dict(
        cwd=cwd,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.STDOUT if capture else None,
        text=True,
        creationflags=CREATE_NO_WINDOW if sys.platform == "win32" else 0,
        shell=False,
    )
    res = subprocess.run(cmd, **kwargs)
    if check and res.returncode != 0:
        raise RuntimeError(f"命令失败: {' '.join(cmd)} (code={res.returncode})")
    return res


# ============================================================
# 数据服务 (Docker)
# ============================================================

def docker_available():
    res = run(["docker", "version", "--format", "{{.Client.Version}}"], capture=True)
    return res.returncode == 0 and bool(res.stdout.strip())


def docker_engine_ready():
    """检测 docker daemon(服务端)是否就绪——`docker version` 仅校验客户端;
    引擎未起时 `docker ps` 会失败。此函数用于判断能否跑容器命令。"""
    res = run(["docker", "ps", "--format", "{{.ID}}"], capture=True)
    return res.returncode == 0


def ensure_docker_engine():
    """确保 docker engine 就绪。若未就绪则自动启动 Docker Desktop 并等待。
    返回 True 表示引擎可用;False 表示最终仍不可用。"""
    if docker_engine_ready():
        ok("Docker engine 已就绪")
        return True

    info("Docker engine 未就绪,尝试自动启动 Docker Desktop ...")
    exe = DOCKER_DESKTOP_EXE
    if not Path(exe).exists():
        # 兜底:从 PATH 找 docker,反推父目录
        dpath = shutil.which("docker")
        if dpath:
            cand = Path(dpath).resolve().parent.parent / "Docker Desktop.exe"
            if cand.exists():
                exe = str(cand)
    if not Path(exe).exists():
        err(f"未找到 Docker Desktop 可执行文件: {DOCKER_DESKTOP_EXE}")
        return False

    try:
        subprocess.Popen(
            [exe],
            cwd=str(Path(exe).parent),
            close_fds=True,
            creationflags=CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP
            if sys.platform == "win32" else 0,
        )
        ok(f"已发起启动 Docker Desktop: {exe}")
    except Exception as e:
        err(f"启动 Docker Desktop 失败: {e}")
        return False

    info(f"等待 Docker engine 就绪(最长 {DOCKER_START_TIMEOUT}s)...")
    deadline = time.time() + DOCKER_START_TIMEOUT
    dots = 0
    while time.time() < deadline:
        if docker_engine_ready():
            ok("Docker engine 已就绪")
            return True
        time.sleep(3)
        dots += 1
        if dots % 5 == 0:
            info(f"  仍在等待 Docker Desktop 启动 ... ({int(time.time() - (deadline - DOCKER_START_TIMEOUT))}s)")
    err("Docker engine 在限定时间内未就绪 — 请检查 Docker Desktop 是否正常启动")
    return False


def start_data_services():
    """启动数据服务:MySQL 探测宿主机实例;Postgres/Redis/MinIO/Memgraph 走 docker。
    若 Docker Desktop 未运行,自动拉起并等待 engine 就绪。"""
    info("=== 数据服务 ===")

    # 宿主机 MySQL:只探测,不主动拉起
    if port_open(PORTS["mysql_host"]):
        ok(f"宿主机 MySQL 端口 {PORTS['mysql_host']} 已在监听")
    else:
        warn(f"宿主机 MySQL 端口 {PORTS['mysql_host']} 未监听 — 请先手动启动宿主机 MySQL(root 密码 test)")

    if not ensure_docker_engine():
        err("Docker 不可用,跳过容器数据服务(Postgres/Redis/MinIO/Memgraph)")
        return False

    for name in DOCKER_DATA_CONTAINERS:
        info(f"启动 docker 容器 {name}")
        res = run(["docker", "start", name], capture=True)
        if res.returncode != 0:
            warn(f"{name} 启动失败: {res.stdout.strip()}")

    # 等待各 docker 端口
    wait_port(PORTS["redis"],    "Redis(qa-redis)",      timeout=30)
    wait_port(PORTS["minio"],    "MinIO(qa-minio)",      timeout=30)
    wait_port(PORTS["memgraph"], "Memgraph(qa-memgraph)", timeout=40)
    wait_port(PORTS["postgres"], "Postgres(qa-pgvector)", timeout=40)
    return True


def stop_data_services():
    info("=== 停止数据服务 ===")
    for name in DOCKER_DATA_CONTAINERS:
        run(["docker", "stop", name], capture=True)
        ok(f"已停止 docker 容器 {name}")
    info("宿主机 MySQL 不由本脚本管理,跳过")


# ============================================================
# 后端 / 前端 (子进程)
# ============================================================

def load_pids():
    if not PID_FILE.exists():
        return {}
    try:
        import json
        return json.loads(PID_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}


def save_pids(pids):
    import json
    PID_FILE.write_text(json.dumps(pids, indent=2), encoding="utf-8")


def proc_alive(pid):
    if not pid:
        return False
    try:
        if sys.platform == "win32":
            res = run(["powershell", "-NoProfile", "-Command",
                       f"Get-Process -Id {pid} -ErrorAction SilentlyContinue | Measure-Object | Select -ExpandProperty Count"],
                      capture=True)
            return res.returncode == 0 and res.stdout.strip() == "1"
        else:
            os.kill(pid, 0)
            return True
    except Exception:
        return False


def kill_pid(pid):
    if not pid:
        return
    try:
        if sys.platform == "win32":
            # taskkill 整个进程树
            run(["taskkill", "/F", "/T", "/PID", str(pid)], capture=True)
        else:
            os.killpg(os.getpgid(pid), signal.SIGTERM)
    except Exception:
        pass


def find_pid_on_port(port):
    """通过 TCP 监听端口反查进程 PID(Windows 用 powershell)"""
    if sys.platform != "win32":
        return None
    try:
        res = run(
            ["powershell", "-NoProfile", "-Command",
             f"(Get-NetTCPConnection -LocalPort {port} -State Listen -ErrorAction SilentlyContinue "
             f"| Select-Object -First 1).OwningProcess"],
            capture=True,
        )
        out = res.stdout.strip()
        if out and out.isdigit():
            return int(out)
    except Exception:
        return None
    return None


def kill_port(port):
    """kill 占用某端口的监听进程(及其进程树)"""
    pid = find_pid_on_port(port)
    if pid:
        kill_pid(pid)
        return pid
    return None


def start_service(key):
    svc = SERVICES[key]
    port = PORTS[key]
    if port_open(port):
        warn(f"{svc['label']} 端口 {port} 已被占用,跳过(可能已在运行)")
        return None

    log_path = LOG_DIR / svc["log"]
    info(f"启动 {svc['label']} -> {' '.join(svc['cmd'])}")
    info(f"  日志: {log_path}")

    flags = CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP if sys.platform == "win32" else 0
    with open(log_path, "ab") as f:
        proc = subprocess.Popen(
            svc["cmd"],
            cwd=svc["cwd"],
            stdout=f,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            creationflags=flags,
            close_fds=True,
        )
    return proc.pid


def start_app_services():
    info("=== 应用服务 (后端 + 前端) ===")
    pids = load_pids()
    for key in START_ORDER:
        pid = start_service(key)
        if pid:
            pids[key] = pid
            # 给一点缓冲再等端口
            wait_port(PORTS[key], SERVICES[key]["label"], timeout=50)
        else:
            # 已在运行,复用旧 pid(若存活)
            pids.setdefault(key, None)
    save_pids(pids)
    ok(f"PID 记录: {PID_FILE}")


def stop_app_services():
    info("=== 停止应用服务 ===")
    pids = load_pids()
    changed = False
    for key in START_ORDER:
        pid = pids.get(key)
        killed = False
        if pid and proc_alive(pid):
            kill_pid(pid)
            ok(f"已停止 {SERVICES[key]['label']} (pid={pid})")
            killed = True
        # 若无有效 pid 记录,则按端口反查进程并 kill
        # (兜底:处理上一次未由本脚本拉起、或 pid 记录丢失的游离进程)
        if not killed:
            pidx = kill_port(PORTS[key])
            if pidx:
                ok(f"已停止 {SERVICES[key]['label']} (按端口 {PORTS[key]} 查得 pid={pidx})")
                killed = True
        if not killed:
            warn(f"{SERVICES[key]['label']} 无运行进程,跳过")
        pids[key] = None
        changed = True
    if changed:
        save_pids(pids)


# ============================================================
# 状态
# ============================================================

def show_status():
    info("=== 服务状态 ===")
    rows = [
        ("MySQL(宿主机)",       PORTS["mysql_host"]),
        ("Postgres(qa-pgvector)", PORTS["postgres"]),
        ("Redis(qa-redis)",      PORTS["redis"]),
        ("MinIO(qa-minio)",      PORTS["minio"]),
        ("Memgraph(qa-memgraph)",PORTS["memgraph"]),
        ("后端A Agent_Server",   PORTS["backend_a"]),
        ("后端B Enterprise",     PORTS["backend_b"]),
        ("前端A agent_web",      PORTS["frontend_a"]),
        ("前端B Enterprise_web", PORTS["frontend_b"]),
    ]
    print(f"  {'服务':<26} {'端口':<7} {'状态':<6}")
    print(f"  {'-'*26} {'-'*7} {'-'*6}")
    for name, port in rows:
        st = "UP" if port_open(port) else "DOWN"
        print(f"  {name:<26} {port:<7} {st}")
    print()
    print("访问地址:")
    print(f"  项目A  前端 http://localhost:{PORTS['frontend_a']}/   文档 http://localhost:{PORTS['backend_a']}/docs")
    print(f"  项目B  前端 http://localhost:{PORTS['frontend_b']}/   文档 http://localhost:{PORTS['backend_b']}/docs")


# ============================================================
# main
# ============================================================

def open_pages():
    """启动成功后用默认浏览器打开两个项目的前端页面"""
    urls = [
        f"http://localhost:{PORTS['frontend_a']}/",
        f"http://localhost:{PORTS['frontend_b']}/",
    ]
    info("=== 自动打开浏览器 ===")
    for url in urls:
        try:
            webbrowser.open(url, new=2)  # new=2 尽量新标签页
            ok(f"已打开 {url}")
        except Exception as e:
            warn(f"打开失败 {url}: {e}")
    # 给浏览器一点时间逐个起
    time.sleep(0.5)


def do_start(open_browser=True):
    start_data_services()
    start_app_services()
    print()
    show_status()
    if open_browser:
        print()
        open_pages()


def do_stop():
    stop_app_services()
    stop_data_services()
    print()
    show_status()


def main():
    parser = argparse.ArgumentParser(description="AI Test Agent 一键启动/停止")
    parser.add_argument("action", nargs="?", default="start",
                        choices=["start", "stop", "status", "restart"])
    parser.add_argument("--no-open", dest="no_open", action="store_true",
                        help="启动后不自动打开浏览器")
    args = parser.parse_args()

    if args.action == "start":
        do_start(open_browser=not args.no_open)
    elif args.action == "stop":
        do_stop()
    elif args.action == "restart":
        do_stop()
        print()
        do_start(open_browser=not args.no_open)
    elif args.action == "status":
        show_status()


if __name__ == "__main__":
    main()
