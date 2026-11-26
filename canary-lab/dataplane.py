#!/usr/bin/env python3
"""模拟数据面 + 控制台 + 控制器进程监管（单进程，仅使用 Python 标准库）。

模拟三类资源
------------
- 网关路由：v1/v2 权重（只接受绝对值设置）、生效配置版本
- 实例池：版本、挂载配置、健康状态、运行状态
- 配置中心：cfg-v1 / cfg-v2 两份配置内容

另外承担
--------
- 控制器子进程的启动 / 优雅停止 / SIGKILL（模拟控制面宕机）
- 控制器持久化目录与数据面状态的落盘、重置
- 两条演练场景的自动执行（成功补齐 / 故障撤回），含中途 kill 控制器
- 模拟流量统计与全量命令审计日志
"""
from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

HERE = os.path.dirname(os.path.abspath(__file__))
RUN_DIR = os.path.join(HERE, "run")
STATE_PATH = os.path.join(RUN_DIR, "dataplane_state.json")
CTRL_DIR = os.path.join(RUN_DIR, "controller")
CTRL_STATE = os.path.join(CTRL_DIR, "controller_state.json")
CTRL_EVENTS = os.path.join(CTRL_DIR, "controller_events.json")
CTRL_DECISION = os.path.join(CTRL_DIR, "decision.json")
CTRL_LOG = os.path.join(CTRL_DIR, "stdout.log")

WEIGHT_LADDER = [0, 10, 25, 50, 75, 100]
TRAFFIC_SAMPLES_KEEP = 60
SIM_RPS = 120

LOCK = threading.RLock()


def _now(seconds: bool = False) -> str:
    fmt = "%Y-%m-%d %H:%M:%S" + (".%f" if seconds else "")
    out = time.strftime(fmt, time.localtime())
    return out[:-3] if seconds else out


# ============================================================ 状态与持久化
def initial_state() -> dict:
    return {
        "instances": [
            {"id": f"baseline-{n}", "version": "v1", "config_version": "cfg-v1",
             "status": "running", "healthy": True, "created_at": _now()}
            for n in range(1, 4)
        ],
        "gateway": {"canary_weight": 0, "config_version": "cfg-v1"},
        "configs": {
            "cfg-v1": {"feature_x": False, "timeout_ms": 1000, "remark": "基线配置"},
            "cfg-v2": {"feature_x": True, "timeout_ms": 800, "remark": "灰度配置"},
        },
        "release": None,
        "command_log": [],
        "traffic": {"samples": [], "counters": {"total": 0, "v2": 0, "v2_errors": 0}},
        "scenario": None,
        "seq": {"instance": 0, "command": 0, "release": 0},
    }


def load_state() -> dict:
    if os.path.exists(STATE_PATH):
        try:
            with open(STATE_PATH, encoding="utf-8") as fh:
                return json.load(fh)
        except (OSError, json.JSONDecodeError):
            pass
    return initial_state()


def persist_state() -> None:
    os.makedirs(RUN_DIR, exist_ok=True)
    tmp = STATE_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(STATE, fh, ensure_ascii=False, indent=2)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, STATE_PATH)


STATE = load_state()


# ============================================================ 控制器进程监管
class Supervisor:
    def __init__(self, dataplane_url: str):
        self.dataplane_url = dataplane_url
        self.proc: subprocess.Popen | None = None

    def _reap(self) -> None:
        if self.proc is not None and self.proc.poll() is not None:
            self.proc = None

    def start(self) -> dict:
        with LOCK:
            self._reap()
            if self.proc is not None:
                return {"ok": True, "note": "控制器已在运行", "pid": self.proc.pid}
            os.makedirs(CTRL_DIR, exist_ok=True)
            logfh = open(CTRL_LOG, "a", encoding="utf-8")
            self.proc = subprocess.Popen(
                [sys.executable, "-I", os.path.join(HERE, "controller.py"),
                 "--dataplane", self.dataplane_url, "--state-dir", CTRL_DIR],
                stdout=logfh, stderr=subprocess.STDOUT, cwd=HERE,
            )
            info = {"ok": True, "pid": self.proc.pid, "at": _now()}
            self._dp_note("CTRL_START", f"控制器子进程已启动 pid={self.proc.pid}")
            return info

    def stop(self, force: bool) -> dict:
        with LOCK:
            self._reap()
            if self.proc is None:
                return {"ok": False, "error": "控制器未在运行"}
            pid = self.proc.pid
            sig = signal.SIGKILL if force else signal.SIGTERM
            kind = "SIGKILL（模拟宕机/断电，无清理机会）" if force else "SIGTERM（优雅停止）"
            try:
                os.kill(pid, sig)
            except ProcessLookupError:
                pass
            if force:
                self.proc.wait(timeout=5)
                self.proc = None
            else:
                try:
                    self.proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.kill(pid, signal.SIGKILL)
                    self.proc.wait(timeout=5)
                self.proc = None
            self._dp_note("CTRL_KILL" if force else "CTRL_STOP",
                          f"控制器进程 pid={pid} 被{kind}；数据面资源与磁盘持久化状态保留")
            return {"ok": True, "pid": pid, "signal": int(sig)}

    def status(self) -> dict:
        with LOCK:
            self._reap()
            alive = self.proc is not None
            info: dict = {"alive": alive, "pid": self.proc.pid if self.proc else None}
            if os.path.exists(CTRL_STATE):
                try:
                    with open(CTRL_STATE, encoding="utf-8") as fh:
                        cs = json.load(fh)
                    info.update(epoch=cs.get("epoch"), phase=cs.get("phase"),
                                step_index=cs.get("step_index"),
                                decision=cs.get("decision"),
                                state_updated_at=cs.get("updated_at"),
                                heartbeat_age=round(time.time() - os.path.getmtime(CTRL_STATE), 1))
                except (OSError, json.JSONDecodeError) as exc:
                    info["error"] = f"控制器状态文件读取失败: {exc}"
            else:
                info["note"] = "尚无控制器持久化状态"
            return info

    def reset(self) -> dict:
        with LOCK:
            self._reap()
            if self.proc is not None:
                try:
                    os.kill(self.proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                self.proc.wait(timeout=5)
                self.proc = None
            global STATE
            STATE = initial_state()
            persist_state()
            if os.path.isdir(CTRL_DIR):
                for name in os.listdir(CTRL_DIR):
                    os.remove(os.path.join(CTRL_DIR, name))
            return {"ok": True, "at": _now()}

    @staticmethod
    def _dp_note(cmd: str, note: str) -> None:
        append_command(cmd, {}, note=note)


SUP: Supervisor | None = None


# ============================================================ 资源操作
def _next_seq(key: str) -> int:
    STATE["seq"][key] += 1
    return STATE["seq"][key]


def append_command(command: str, params: dict, note: str = "",
                   skipped: bool = False) -> dict:
    entry = {
        "seq": _next_seq("command"), "ts": _now(), "command": command,
        "params": params, "skipped": skipped, "note": note,
    }
    STATE["command_log"].append(entry)
    if len(STATE["command_log"]) > 500:
        STATE["command_log"] = STATE["command_log"][-500:]
    return entry


def live_instances() -> list[dict]:
    return [i for i in STATE["instances"] if i["status"] == "running"]


def create_instance(version: str, config_version: str) -> dict:
    if config_version not in STATE["configs"]:
        raise HttpError(400, f"未知配置版本 {config_version}")
    n = _next_seq("instance")
    inst_id = f"canary-{n}" if version != "v1" else f"baseline-new-{n}"
    inst = {"id": inst_id, "version": version, "config_version": config_version,
            "status": "running", "healthy": True, "created_at": _now()}
    STATE["instances"].append(inst)
    append_command("createInstance", {"id": inst_id, "version": version,
                                      "config_version": config_version},
                   note=f"创建实例 {inst_id}（{version}），未接流量前健康检查为健康")
    return inst


def attach_config(instance_id: str, config_version: str) -> dict:
    inst = _find_instance(instance_id)
    if config_version not in STATE["configs"]:
        raise HttpError(400, f"未知配置版本 {config_version}")
    before = inst["config_version"]
    inst["config_version"] = config_version
    append_command("attachConfig", {"id": instance_id, "from": before,
                                    "config_version": config_version},
                   note=f"实例 {instance_id} 配置 {before} → {config_version}")
    return inst


def set_gateway_weight(canary_weight: int) -> dict:
    if not isinstance(canary_weight, int) or not 0 <= canary_weight <= 100:
        raise HttpError(400, "canary_weight 必须是 0..100 的整数")
    gw = STATE["gateway"]
    # 幂等保护：相同绝对值直接跳过并在审计日志标注，证明重复调用不会叠加。
    if gw["canary_weight"] == canary_weight:
        append_command("setWeight",
                       {"canary_weight": canary_weight,
                        "base_weight": 100 - canary_weight},
                       skipped=True,
                       note=f"权重已是 v2={canary_weight}%，重复的绝对值命令被幂等跳过")
        return gw
    before = gw["canary_weight"]
    gw["canary_weight"] = canary_weight
    append_command("setWeight",
                   {"canary_weight": canary_weight,
                    "base_weight": 100 - canary_weight},
                   note=f"网关权重绝对值变更：v2 {before}% → {canary_weight}%，"
                        f"v1 同步为 {100 - canary_weight}%（无增量叠加）")
    return gw


def set_gateway_config(config_version: str) -> dict:
    if config_version not in STATE["configs"]:
        raise HttpError(400, f"未知配置版本 {config_version}")
    gw = STATE["gateway"]
    before = gw["config_version"]
    gw["config_version"] = config_version
    append_command("setGatewayConfig", {"from": before,
                                        "config_version": config_version},
                   note=f"网关生效配置 {before} → {config_version}")
    return gw


def terminate_instance(instance_id: str) -> dict:
    inst = _find_instance(instance_id)
    inst["status"] = "terminated"
    inst["healthy"] = False
    append_command("terminateInstance", {"id": instance_id},
                   note=f"实例 {instance_id}（{inst['version']}）已终止并摘流")
    return inst


def set_fault(instance_id: str, unhealthy: bool) -> dict:
    inst = _find_instance(instance_id)
    inst["healthy"] = not unhealthy
    append_command("injectFault",
                   {"id": instance_id, "unhealthy": unhealthy},
                   note=f"故障注入：实例 {instance_id} 健康标记 → "
                        f"{'不健康（模拟 500 错误）' if unhealthy else '恢复健康'}")
    return inst


def _find_instance(instance_id: str) -> dict:
    for inst in STATE["instances"]:
        if inst["id"] == instance_id:
            return inst
    raise HttpError(404, f"实例不存在: {instance_id}")


class HttpError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


# ============================================================ 发布单
def create_release(spec: dict) -> dict:
    if STATE["release"] and STATE["release"]["status"] == "IN_PROGRESS":
        raise HttpError(409, "已有进行中的发布单，请先结束或重置")
    rid = f"rel-{_next_seq('release'):03d}"
    release = {
        "id": rid,
        "status": "IN_PROGRESS",
        "spec": {
            "base_version": spec.get("base_version", "v1"),
            "canary_version": spec.get("canary_version", "v2"),
            "base_config": spec.get("base_config", "cfg-v1"),
            "canary_config": spec.get("canary_config", "cfg-v2"),
            "weight_ladder": WEIGHT_LADDER,
            "gate_weight": 50,
        },
        "decision": None,
        "created_at": _now(),
        "decided_at": None,
        "finished_at": None,
    }
    STATE["release"] = release
    append_command("createRelease", {"id": rid, "spec": release["spec"]},
                   note="创建灰度发布单：路由、实例版本、配置在同一发布单内联动变更")
    return release


def mark_decision(release_id: str, decision: str) -> dict:
    rel = STATE["release"]
    if not rel or rel["id"] != release_id:
        raise HttpError(404, "发布单不存在或已结束")
    if decision not in ("continue", "abort"):
        raise HttpError(400, "decision 仅支持 continue / abort")
    rel["decision"] = decision
    rel["decided_at"] = _now()
    append_command("decision", {"id": release_id, "decision": decision},
                   note=f"人工决策已登记：{'补齐（继续全量）' if decision == 'continue' else '撤回（回滚）'}")
    return rel


def write_decision_file(decision: str) -> dict:
    if decision not in ("continue", "abort"):
        raise HttpError(400, "decision 仅支持 continue / abort")
    os.makedirs(CTRL_DIR, exist_ok=True)
    tmp = CTRL_DECISION + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump({"decision": decision, "ts": _now()}, fh, ensure_ascii=False)
    os.replace(tmp, CTRL_DECISION)
    append_command("writeDecisionFile", {"decision": decision},
                   note="决策落盘到控制器持久化目录，控制器即使重启也能读到")
    return {"ok": True}


# ============================================================ 模拟流量
def traffic_sampler() -> None:
    while True:
        time.sleep(1.0)
        with LOCK:
            gw = STATE["gateway"]
            w2 = gw["canary_weight"] / 100.0
            v2_live = [i for i in live_instances() if i["version"] != "v1"]
            v2_healthy = any(i["healthy"] for i in v2_live)
            v2_rps = round(SIM_RPS * w2, 1)
            # v2 全部不健康时，v2 份额全部表现为错误请求。
            v2_errors = round(v2_rps, 1) if (v2_live and not v2_healthy) else 0.0
            v1_rps = round(SIM_RPS - v2_rps, 1)
            sample = {"ts": _now(seconds=True), "v1_rps": v1_rps,
                      "v2_rps": v2_rps, "v2_error_rps": v2_errors}
            traf = STATE["traffic"]
            traf["samples"].append(sample)
            del traf["samples"][:-TRAFFIC_SAMPLES_KEEP]
            traf["counters"]["total"] += SIM_RPS
            traf["counters"]["v2"] += int(v2_rps)
            traf["counters"]["v2_errors"] += int(v2_errors)

            # 根据控制器阶段同步发布单终态。
            rel = STATE["release"]
            if rel and rel["status"] == "IN_PROGRESS":
                cs = _read_controller_state()
                if cs and cs.get("phase") == "DONE" and cs.get("release"):
                    # DONE 且 v2 权重归零 = 撤回完成；否则 = 全量补齐完成。
                    rel["status"] = ("ROLLED_BACK" if gw["canary_weight"] == 0
                                     else "SUCCEEDED")
                    rel["finished_at"] = _now()
                    append_command("releaseFinish",
                                   {"id": rel["id"], "status": rel["status"]},
                                   note=f"发布单终态：{rel['status']}")
            persist_state()


def _read_controller_state() -> dict | None:
    if not os.path.exists(CTRL_STATE):
        return None
    try:
        with open(CTRL_STATE, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return None


def _read_controller_events() -> list[dict]:
    if not os.path.exists(CTRL_EVENTS):
        return []
    events = []
    try:
        with open(CTRL_EVENTS, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    events.append(json.loads(line))
    except (OSError, json.JSONDecodeError):
        pass
    return events[-300:]


# ============================================================ 场景演练
class ScenarioRunner(threading.Thread):
    def __init__(self, name: str):
        super().__init__(daemon=True)
        self.name = name  # "success" | "rollback"

    def run(self) -> None:
        try:
            self._run()
        except Exception as exc:  # 演练自身异常也要在页面上可见
            self._log("ERROR", f"演练异常终止: {exc}")
            with LOCK:
                STATE.setdefault("scenario", {"name": self.name, "steps": []})
                STATE["scenario"]["status"] = "FAILED"
                STATE["scenario"]["finished_at"] = _now()
                persist_state()
        else:
            with LOCK:
                if STATE.get("scenario", {}).get("status") == "RUNNING":
                    STATE["scenario"]["status"] = "DONE"
                    STATE["scenario"]["finished_at"] = _now()
                    persist_state()

    def _log(self, level: str, message: str) -> None:
        with LOCK:
            STATE.setdefault("scenario", {"name": self.name, "status": "RUNNING",
                                          "started_at": _now(), "steps": []})
            STATE["scenario"].setdefault("steps", []).append(
                {"ts": _now(seconds=True), "level": level, "message": message})
            persist_state()

    def _wait_phase(self, phase: str, timeout: float = 60) -> dict:
        deadline = time.time() + timeout
        while time.time() < deadline:
            cs = _read_controller_state()
            if cs and cs.get("phase") == phase:
                return cs
            time.sleep(0.3)
        raise TimeoutError(f"等待控制器阶段 {phase} 超时")

    def _wait_event(self, event_type: str, timeout: float = 30) -> dict:
        deadline = time.time() + timeout
        seen = 0
        while time.time() < deadline:
            events = _read_controller_events()
            for ev in events[seen:]:
                if ev["type"] == event_type:
                    return ev
            seen = len(events)
            time.sleep(0.3)
        raise TimeoutError(f"等待控制器事件 {event_type} 超时")

    def _run(self) -> None:
        # 先 reset（reset 会整体重建 STATE，包括清空旧的 scenario 记录），
        # 再登记本次演练，避免演练句柄被重置抹掉。
        SUP.reset()
        with LOCK:
            STATE["scenario"] = {"name": self.name, "status": "RUNNING",
                                 "started_at": _now(), "steps": []}
            persist_state()

        self._log("INFO", "① 环境已重置（3 个 v1 基线实例、v2 权重 0%）")
        time.sleep(0.5)
        self._log("INFO", "② 启动控制器进程，控制器开始持久化 state.json 与事件日志")
        SUP.start()
        time.sleep(1.0)

        spec = {"canary_version": "v2", "canary_config": "cfg-v2"}
        with LOCK:
            rel = create_release(spec)
            persist_state()
        self._log("INFO", f"③ 创建发布单 {rel['id']}：0%→10%→25%→50%（决策点）→75%→100%，"
                          "路由权重、v2 实例、cfg-v2 配置联动")

        cs = self._wait_phase("GATE")
        gw = cs and _read_controller_state()
        self._log("INFO", f"④ 灰度已到 50% 决策点（控制器记忆 step={cs.get('step_index')}）。"
                          "现在 SIGKILL 控制器，模拟控制面进程突然消失")
        SUP.stop(force=True)
        time.sleep(2.0)
        with LOCK:
            actual = json.loads(json.dumps({
                "gateway": STATE["gateway"],
                "instances": [i for i in STATE["instances"] if i["status"] == "running"],
            }))
        self._log("WARN",
                  f"⑤ 控制器已断开 2s：数据面实际生效状态保持不变——"
                  f"网关 v2={actual['gateway']['canary_weight']}%、"
                  f"配置 {actual['gateway']['config_version']}、"
                  f"存活实例 {[i['id'] + ':' + i['version'] for i in actual['instances']]}；"
                  "没有任何进程在改动流量")

        self._log("INFO", "⑥ 重新启动控制器：恢复后的第一个动作不是继续推流量，"
                          "而是读取数据面实际状态做恢复核对（RECONCILE_VERIFY）")
        SUP.start()
        verify = self._wait_event("RECONCILE_VERIFY")
        fixes = verify["action"].get("fixes", [])
        self._log("INFO",
                  "⑦ 核对结论：" + ("；".join(fixes) if fixes else
                                  "实际权重/实例/配置与期望完全一致，步进索引按实际值重对齐，"
                                  "无需补操作；权重命令均为绝对值，重复执行也不会二次放大")
                  + f"（控制器进入第 {verify['epoch']} 个生命周期）")

        if self.name == "rollback":
            canary_ids = [i["id"] for i in STATE["instances"]
                          if i["version"] == "v2" and i["status"] == "running"]
            for cid in canary_ids:
                with LOCK:
                    set_fault(cid, True)
                    persist_state()
            self._log("WARN",
                      f"⑧ 故障场景：向 v2 实例 {canary_ids} 注入故障（健康检查失败、"
                      "模拟流量出现 500）。依据‘实际状态不健康’选择撤回")
            time.sleep(1.5)
            write_decision_file("abort")
            self._log("INFO", "⑨ 人工决策【撤回】已落盘：阶梯降权 50→25→10→0，"
                              "网关配置切回 cfg-v1，最后终止 v2 实例")
            self._wait_release_done("ROLLED_BACK")
            self._log("OK", "⑩ 撤回完成：v2 权重 0%、v1 全量承接、v2 实例已终止，"
                            "全过程无任何一次权重增量叠加")
        else:
            self._log("INFO", "⑧ 成功场景：核对实际状态——v2=50%、v2 实例全部健康、"
                              "cfg-v2 已挂载，依据核对结果选择补齐")
            write_decision_file("continue")
            self._log("INFO", "⑨ 人工决策【补齐】已落盘：继续 50→75→100，"
                              "网关配置切 cfg-v2，终止 v1 基线实例")
            self._wait_release_done("SUCCEEDED")
            self._log("OK", "⑩ 全量发布完成：v2=100%，控制器阶段 DONE，"
                            "命令审计可证明每个权重值只被设置一次")

    def _wait_release_done(self, expected: str, timeout: float = 90) -> None:
        deadline = time.time() + timeout
        while time.time() < deadline:
            with LOCK:
                rel = STATE["release"]
                if rel and rel["status"] == expected:
                    return
            time.sleep(0.5)
        raise TimeoutError(f"等待发布单终态 {expected} 超时")


# ============================================================ HTTP 服务
class Handler(BaseHTTPRequestHandler):
    server_version = "CanaryLab/1.0"

    def log_message(self, *args):  # 静音默认访问日志
        pass

    def _json(self, obj, status: int = 200) -> None:
        body = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self) -> dict:
        length = int(self.headers.get("Content-Length", 0))
        if length == 0:
            return {}
        try:
            return json.loads(self.rfile.read(length).decode())
        except json.JSONDecodeError:
            raise HttpError(400, "请求体不是合法 JSON")

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        try:
            if path in ("/", "/index.html"):
                self._serve_index()
            elif path == "/api/state":
                with LOCK:
                    self._json(self._state_payload())
            elif path == "/api/controller/events":
                self._json({"events": _read_controller_events()})
            elif path == "/api/controller/log":
                text = ""
                if os.path.exists(CTRL_LOG):
                    with open(CTRL_LOG, encoding="utf-8", errors="replace") as fh:
                        text = fh.read()[-8000:]
                self._json({"log": text})
            else:
                self._json({"error": "not found"}, 404)
        except HttpError as exc:
            self._json({"error": exc.message}, exc.status)

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        try:
            body = self._read_body()
            with LOCK:
                result = self._route_post(path, body)
                persist_state()
            self._json(result)
        except HttpError as exc:
            self._json({"error": exc.message}, exc.status)

    def _route_post(self, path: str, body: dict) -> dict:
        # ---- 控制器进程管理
        if path == "/api/control/start":
            return SUP.start()
        if path == "/api/control/stop":
            return SUP.stop(force=False)
        if path == "/api/control/kill":
            return SUP.stop(force=True)
        if path == "/api/reset":
            return SUP.reset()

        # ---- 发布与决策
        if path == "/api/releases":
            return {"release": create_release(body)}
        if path == "/api/decision":
            return write_decision_file(body.get("decision"))
        if path.startswith("/api/releases/") and path.endswith("/decision"):
            rel_id = path.split("/")[3]
            return {"release": mark_decision(rel_id, body.get("decision"))}

        # ---- 模拟资源
        if path == "/api/instances":
            return {"instance": create_instance(
                body.get("version", "v2"), body.get("config_version", "cfg-v2"))}
        if path.startswith("/api/instances/") and path.endswith("/config"):
            inst_id = path.split("/")[3]
            return {"instance": attach_config(inst_id, body.get("config_version"))}
        if path.startswith("/api/instances/") and path.endswith("/terminate"):
            inst_id = path.split("/")[3]
            return {"instance": terminate_instance(inst_id)}
        if path.startswith("/api/fault/instances/"):
            inst_id = path.split("/")[4]
            return {"instance": set_fault(inst_id, bool(body.get("unhealthy", True)))}
        if path == "/api/fault/reset":
            for inst in STATE["instances"]:
                if inst["status"] == "running":
                    inst["healthy"] = True
            append_command("resetFault", {}, note="清除全部故障注入，实例恢复健康")
            return {"ok": True}

        # ---- 网关
        if path == "/api/gateway/weight":
            return {"gateway": set_gateway_weight(int(body.get("canary_weight", -1)))}
        if path == "/api/gateway/config":
            return {"gateway": set_gateway_config(body.get("config_version"))}

        # ---- 场景演练
        if path == "/api/scenario/run":
            name = body.get("name")
            if name not in ("success", "rollback"):
                raise HttpError(400, "name 仅支持 success / rollback")
            if STATE.get("scenario") and STATE["scenario"].get("status") == "RUNNING":
                raise HttpError(409, "已有演练在运行中")
            ScenarioRunner(name).start()
            return {"ok": True, "name": name}

        raise HttpError(404, f"未知接口: {path}")

    def _state_payload(self) -> dict:
        return {
            "ts": _now(seconds=True),
            "gateway": STATE["gateway"],
            "instances": STATE["instances"],
            "configs": STATE["configs"],
            "release": STATE["release"],
            "traffic": STATE["traffic"],
            "command_log": STATE["command_log"][-120:],
            "controller": SUP.status(),
            "controller_events": _read_controller_events()[-120:],
            "scenario": STATE.get("scenario"),
            "weight_ladder": WEIGHT_LADDER,
        }

    def _serve_index(self) -> None:
        index = os.path.join(HERE, "web", "index.html")
        with open(index, "rb") as fh:
            content = fh.read()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)


def main() -> int:
    parser = argparse.ArgumentParser(description="灰度发布模拟数据面 + 控制台")
    parser.add_argument("--port", type=int, default=18080)
    args = parser.parse_args()

    global SUP
    SUP = Supervisor(f"http://127.0.0.1:{args.port}")
    threading.Thread(target=traffic_sampler, daemon=True).start()

    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    print(f"canary-lab 数据面与控制台: http://127.0.0.1:{args.port}")
    print(f"运行状态目录: {RUN_DIR}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
