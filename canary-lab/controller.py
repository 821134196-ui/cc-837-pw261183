#!/usr/bin/env python3
"""灰度发布控制器（控制面）。

设计要点
========
1. 声明式调谐：控制器只持有“期望状态”（release spec），每 500ms 调谐一次，
   每次 tick 最多对数据面执行一个变更动作。
2. 状态持久化：每次状态/事件变化后原子写盘（state.json + events.jsonl）。
   进程被 SIGKILL 后重启，磁盘上的状态仍然完整。
3. 恢复核对（reconcile verify）：重启后的第一件事是读取数据面**实际**状态，
   与期望状态逐项核对，并以实际网关权重为基准重对齐步进索引——
   权重接口只接受绝对值（setWeight），不做任何增量叠加，
   因此即使 kill 恰好发生在“写入数据面之后、写盘之前”，恢复后也绝不会把流量再放大一次。
4. 50% 决策点：灰度走到一半时自动暂停，等待人工“补齐（继续）”或“撤回（回滚）”。
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request

STATE_FILE = "controller_state.json"
EVENTS_FILE = "controller_events.json"
DECISION_FILE = "decision.json"

# 灰度权重阶梯（v2 百分比）。50 是人工决策点。
WEIGHT_LADDER = [0, 10, 25, 50, 75, 100]
GATE_WEIGHT = 50
TICK_SECONDS = 0.5
HEALTH_HOLD_TICKS = 4  # 每个新权重位至少观察 2 个 tick 的健康结果


class DataPlaneError(RuntimeError):
    pass


class DataPlane:
    """数据面 HTTP API 的薄封装。所有调用都是幂等的绝对操作。"""

    def __init__(self, base: str):
        self.base = base.rstrip("/")

    def _call(self, method: str, path: str, body: dict | None = None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(
            self.base + path, data=data, method=method,
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return json.loads(resp.read().decode())
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode(errors="replace")
            raise DataPlaneError(f"HTTP {exc.code} {path}: {detail}") from None
        except urllib.error.URLError as exc:
            raise DataPlaneError(f"数据面不可达 {path}: {exc.reason}") from None

    def snapshot(self) -> dict:
        return self._call("GET", "/api/state")

    def create_instance(self, version: str, config_version: str) -> dict:
        return self._call("POST", "/api/instances",
                          {"version": version, "config_version": config_version})

    def attach_config(self, instance_id: str, config_version: str) -> dict:
        return self._call("POST", f"/api/instances/{instance_id}/config",
                          {"config_version": config_version})

    def set_weight(self, canary_weight: int) -> dict:
        # 绝对值设置：服务端按 100-w 设置 v1，任何重复调用结果完全相同。
        return self._call("POST", "/api/gateway/weight",
                          {"canary_weight": canary_weight})

    def set_gateway_config(self, config_version: str) -> dict:
        return self._call("POST", "/api/gateway/config",
                          {"config_version": config_version})

    def terminate_instance(self, instance_id: str) -> dict:
        return self._call("POST", f"/api/instances/{instance_id}/terminate")

    def mark_decision(self, release_id: str, decision: str) -> dict:
        return self._call("POST", f"/api/releases/{release_id}/decision",
                          {"decision": decision})


class Controller:
    def __init__(self, dataplane: DataPlane, state_dir: str):
        self.dp = dataplane
        self.state_dir = state_dir
        self.state_path = os.path.join(state_dir, STATE_FILE)
        self.events_path = os.path.join(state_dir, EVENTS_FILE)
        self.decision_path = os.path.join(state_dir, DECISION_FILE)
        # _resumed=True 表示磁盘上存在上一个进程留下的发布状态，
        # 本生命周期必须先做恢复核对；全新启动（IDLE）不需要核对。
        self._resumed = os.path.exists(self.state_path)
        self.state = self._load_state()
        if not self._resumed and self.state["phase"] != "IDLE":
            self._resumed = True
        self._hold_remaining = self.state.get("hold_remaining", 0)
        self._last_hold_event = 0.0
        self._verify_done = False

    # ------------------------------------------------------------------ 持久化
    def _load_state(self) -> dict:
        if os.path.exists(self.state_path):
            with open(self.state_path, encoding="utf-8") as fh:
                return json.load(fh)
        return {
            "epoch": 0,
            "pid": os.getpid(),
            "started_at": _now(),
            "release": None,          # 当前期望的发布单
            "phase": "IDLE",
            "step_index": 0,
            "decision": None,
            "hold_remaining": 0,
            "updated_at": None,
        }

    def _persist(self) -> None:
        self.state["hold_remaining"] = self._hold_remaining
        self.state["updated_at"] = _now()
        tmp = self.state_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(self.state, fh, ensure_ascii=False, indent=2)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, self.state_path)

    def log(self, event_type: str, basis: str, observed: dict | None = None,
            action: dict | None = None) -> None:
        """记录一条事件：依据（basis）+ 当时实际状态快照（observed）+ 实际动作（action）。"""
        event = {
            "ts": _now(),
            "epoch": self.state["epoch"],
            "type": event_type,
            "phase": self.state["phase"],
            "step_index": self.state["step_index"],
            "basis": basis,
            "observed": observed or {},
            "action": action or {},
        }
        with open(self.events_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(event, ensure_ascii=False) + "\n")
            fh.flush()
            os.fsync(fh.fileno())

    # ------------------------------------------------------------------ 主循环
    def run(self) -> None:
        self.state["pid"] = os.getpid()
        self.state["epoch"] += 1
        self._persist()
        self.log("CONTROLLER_START",
                 f"控制器进程启动（第 {self.state['epoch']} 个生命周期），"
                 "等待发布单并准备恢复核对")
        while True:
            try:
                self.tick()
            except DataPlaneError as exc:
                # 数据面暂时不可达：不推进任何状态，下一拍重试。
                self.log("DP_UNAVAILABLE", f"调谐被跳过：{exc}")
            time.sleep(TICK_SECONDS)

    def tick(self) -> None:
        snap = self.dp.snapshot()
        release = snap.get("release")

        # 没有发布单：若控制器残留旧状态，回到 IDLE。
        if not release or release["status"] in ("SUCCEEDED", "ROLLED_BACK"):
            if self.state["phase"] != "IDLE":
                self.state.update(phase="IDLE", release=None, step_index=0,
                                  decision=None, hold_remaining=0)
                self._hold_remaining = 0
                self._persist()
                self.log("RELEASE_GONE", "数据面无进行中的发布单，控制器回到 IDLE")
            return

        spec = release["spec"]
        if self.state["release"] is None or self.state["release"]["id"] != release["id"]:
            # 新发布单：初始化期望状态。这是本进程内的全新工作，不是恢复。
            self.state.update(
                release={"id": release["id"], "spec": spec},
                phase="ENSURE_V2", step_index=0, decision=None,
            )
            self._hold_remaining = 0
            self._resumed = False
            self._verify_done = False
            self._persist()
            self.log("RELEASE_ACCEPTED",
                     f"接收发布单 {release['id']}：目标版本 {spec['canary_version']}，"
                     f"目标配置 {spec['canary_config']}，"
                     f"权重阶梯 {WEIGHT_LADDER}（{GATE_WEIGHT}% 为人工决策点）")

        # 只有“带旧状态重启”才做恢复核对；全新接单直接进入正常调谐。
        if self._resumed and not self._verify_done:
            self.reconcile_verify(snap)
            self._verify_done = True
            self._persist()
            return

        self.dispatch(snap)

    # ------------------------------------------------- 恢复核对：实际状态 vs 期望状态
    def reconcile_verify(self, snap: dict) -> None:
        """进程恢复后核对数据面已生效的真实状态，并就地修正控制器记忆。"""
        spec = self.state["release"]["spec"]
        gw = snap["gateway"]
        instances = snap["instances"]
        phase = self.state["phase"]
        observed = {
            "gateway": {"canary_weight": gw["canary_weight"],
                        "config_version": gw["config_version"]},
            "instances": [{"id": i["id"], "version": i["version"],
                           "config_version": i["config_version"],
                           "status": i["status"], "healthy": i["healthy"]}
                          for i in instances],
            "controller_phase": phase,
            "remembered_step_index": self.state["step_index"],
        }
        fixes: list[str] = []

        # 1) 以实际网关权重为唯一基准，重对齐阶梯索引。权重是绝对值设置，
        #    因此重对齐后下一拍最多“重发同一个绝对值”（服务端幂等跳过），
        #    不可能产生第二次增量放大。
        actual_w = gw["canary_weight"]
        real_index = self._nearest_ladder_index(actual_w)
        if actual_w not in WEIGHT_LADDER:
            fixes.append(f"实际权重 {actual_w}% 不在阶梯上，就近对齐到 "
                         f"{WEIGHT_LADDER[real_index]}%")
        if real_index != self.state["step_index"]:
            fixes.append(
                f"步进索引按实际权重纠正：记忆中 step={self.state['step_index']}"
                f"（{WEIGHT_LADDER[self.state['step_index']]}%）→ "
                f"实际 step={real_index}（{WEIGHT_LADDER[real_index]}%），"
                "后续只发绝对值，不叠加流量")
            self.state["step_index"] = real_index

        # 2) 核对 v2 实例与配置挂载。
        v2_live = [i for i in instances
                   if i["version"] == spec["canary_version"] and i["status"] == "running"]
        if phase in ("ENSURE_V2", "ATTACH_CONFIG", "SHIFT", "GATE",
                     "ROLLBACK_SHIFT", "FORWARD_CLEANUP") and not v2_live:
            created = self.dp.create_instance(spec["canary_version"],
                                              spec["canary_config"])
            fixes.append(f"v2 实例缺失，依据实际状态补建 {created['instance']['id']}")
            v2_live = [created["instance"]]

        if phase in ("ATTACH_CONFIG", "SHIFT", "GATE", "FORWARD_CLEANUP"):
            for inst in v2_live:
                if inst["config_version"] != spec["canary_config"]:
                    self.dp.attach_config(inst["id"], spec["canary_config"])
                    fixes.append(f"实例 {inst['id']} 配置未生效，补挂 "
                                 f"{spec['canary_config']}")

        # 3) 撤回途中若网关仍引用新配置，切回基线配置。
        if phase == "ROLLBACK_SHIFT" and gw["config_version"] != spec["base_config"]:
            self.dp.set_gateway_config(spec["base_config"])
            fixes.append(f"撤回途中网关配置仍为 {gw['config_version']}，"
                         f"切回基线 {spec['base_config']}")

        unhealthy = [i["id"] for i in v2_live if not i["healthy"]]
        self.log(
            "RECONCILE_VERIFY",
            "恢复核对完成：" + ("；".join(fixes) if fixes else
                           "数据面实际状态与控制器期望一致，无需修正，"
                           "所有权重操作均为绝对值幂等设置，不存在重复放大"),
            observed={**observed, "unhealthy_v2": unhealthy},
            action={"fixes": fixes},
        )

    # ------------------------------------------------------------------ 阶段调度
    def dispatch(self, snap: dict) -> None:
        phase = self.state["phase"]
        spec = self.state["release"]["spec"]
        instances = snap["instances"]
        v2_live = [i for i in instances
                   if i["version"] == spec["canary_version"] and i["status"] == "running"]

        if phase == "ENSURE_V2":
            if not v2_live:
                created = self.dp.create_instance(spec["canary_version"],
                                                  spec["canary_config"])
                self._persist()
                self.log(
                    "ENSURE_V2",
                    f"发布第 1 步：灰度实例尚不存在，创建 {spec['canary_version']} "
                    f"实例（初始挂载 {spec['canary_config']}，此时不接流量）",
                    observed=self._obs(snap),
                    action={"create_instance": created["instance"]["id"]},
                )
                return
            self._enter("ATTACH_CONFIG",
                        f"v2 实例已就绪：{', '.join(i['id'] for i in v2_live)}，进入配置核对")
            return

        if phase == "ATTACH_CONFIG":
            for inst in v2_live:
                if inst["config_version"] != spec["canary_config"]:
                    self.dp.attach_config(inst["id"], spec["canary_config"])
                    self._persist()
                    self.log(
                        "ATTACH_CONFIG",
                        f"实例 {inst['id']} 实际挂载 {inst['config_version']}，"
                        f"与期望 {spec['canary_config']} 不符，补挂配置（先配置后流量）",
                        observed=self._obs(snap),
                        action={"attach_config": inst["id"],
                                "config_version": spec["canary_config"]},
                    )
                    return
            self._enter("SHIFT",
                        f"全部 v2 实例配置已生效（{spec['canary_config']}），"
                        "开始按阶梯调整网关权重")
            return

        if phase == "SHIFT":
            self._shift_forward(snap, v2_live)
            return

        if phase == "GATE":
            self._at_gate(snap, v2_live)
            return

        if phase == "ROLLBACK_SHIFT":
            self._shift_backward(snap)
            return

        if phase == "FORWARD_CLEANUP":
            self._cleanup_forward(snap)
            return

        if phase == "CLEANUP":
            self._cleanup_rollback(snap, v2_live)
            return

    # ---------------------------------------------------------- 正向：阶梯加权
    def _shift_forward(self, snap: dict, v2_live: list[dict]) -> None:
        spec = self.state["release"]["spec"]
        gw = snap["gateway"]
        idx = self.state["step_index"]
        target = WEIGHT_LADDER[idx]

        # 健康闸门：v2 任一实例不健康则保持当前权重，连续异常由人工在决策页处理。
        unhealthy = [i["id"] for i in v2_live if not i["healthy"]]
        if unhealthy:
            if time.time() - self._last_hold_event > 2:
                self.log("HEALTH_HOLD",
                         f"健康检查未通过（{', '.join(unhealthy)}），"
                         f"网关权重保持 v2={gw['canary_weight']}% 不放大，"
                         "可注入故障后在控制台撤回",
                         observed=self._obs(snap))
                self._last_hold_event = time.time()
            return

        if gw["canary_weight"] < target:
            # 绝对值设置；服务端命令日志对重复值幂等跳过。
            self.dp.set_weight(target)
            self._hold_remaining = HEALTH_HOLD_TICKS
            self._persist()
            self.log(
                "WEIGHT_SET",
                f"将网关 canary 权重绝对值设置为 {target}%（v1 自动为 {100 - target}%）；"
                "setWeight 是幂等绝对值操作，重复执行不会叠加流量",
                observed=self._obs(snap),
                action={"set_canary_weight": target, "set_base_weight": 100 - target},
            )
            return

        # 实际权重已到目标位：先观察若干拍，再推进下一阶梯。
        if self._hold_remaining > 0:
            self._hold_remaining -= 1
            self._persist()
            if self._hold_remaining == 0:
                self.log("HEALTH_OBSERVED",
                         f"v2={target}% 档位观察期结束，v2 实例健康，允许进入下一步",
                         observed=self._obs(snap))
            return

        if target == GATE_WEIGHT:
            self._enter("GATE",
                        f"已到 {GATE_WEIGHT}% 灰度决策点，暂停等待人工判定：补齐或撤回")
            return

        if idx == len(WEIGHT_LADDER) - 1:
            # 100% 完成：网关配置切到新版本，进入旧版本清理。
            if gw["config_version"] != spec["canary_config"]:
                self.dp.set_gateway_config(spec["canary_config"])
                self._persist()
                self.log("GATEWAY_CONFIG_SWITCH",
                         f"流量已 100% 指向 {spec['canary_version']}，"
                         f"网关配置切换为 {spec['canary_config']}",
                         observed=self._obs(snap),
                         action={"gateway_config": spec["canary_config"]})
                return
            self._enter("FORWARD_CLEANUP", "全量发布完成，开始清理 v1 基线实例")
            return

        self.state["step_index"] = idx + 1
        self._persist()
        self.log("STEP_ADVANCE",
                 f"依据健康观察结果，灰度步进推进到 step={idx + 1}"
                 f"（目标 v2={WEIGHT_LADDER[idx + 1]}%）",
                 observed=self._obs(snap))

    def _at_gate(self, snap: dict, v2_live: list[dict]) -> None:
        spec = self.state["release"]["spec"]
        unhealthy = [i["id"] for i in v2_live if not i["healthy"]]
        # 决策文件由数据面监管进程在人工点击时写入（控制器可能随时被 kill，
        # 决策本身也必须落盘而不是只存在内存里）。
        decision = None
        if os.path.exists(self.decision_path):
            try:
                with open(self.decision_path, encoding="utf-8") as fh:
                    decision = json.load(fh).get("decision")
            except (OSError, json.JSONDecodeError):
                decision = None

        if decision == "continue":
            os.remove(self.decision_path)
            self.state["decision"] = "continue"
            # 崩溃窗口里实际权重若偏离决策点，以实际值重对齐，并从“实际档位的下一阶”
            # 继续，避免把已达成的决策点再次当作目标而弹回 GATE。
            actual_idx = self._nearest_ladder_index(snap["gateway"]["canary_weight"])
            self.state["step_index"] = min(actual_idx + 1, len(WEIGHT_LADDER) - 1)
            self.dp.mark_decision(self.state["release"]["id"], "continue")
            self._enter("SHIFT",
                        f"人工决策【补齐】：核对实际状态 v2={snap['gateway']['canary_weight']}%、"
                        f"v2 健康实例 {len(v2_live) - len(unhealthy)}/{len(v2_live)}，"
                        f"下一目标 v2={WEIGHT_LADDER[self.state['step_index']]}%，"
                        "继续按阶梯向上推进")
            return
        if decision == "abort":
            os.remove(self.decision_path)
            self.state["decision"] = "abort"
            self.dp.mark_decision(self.state["release"]["id"], "abort")
            if snap["gateway"]["config_version"] != spec["base_config"]:
                self.dp.set_gateway_config(spec["base_config"])
            # 崩溃窗口里实际权重可能已低于记忆档位：以实际权重为准回退索引，
            # 避免撤回第一步发出与当前值相同的空操作。
            actual_idx = self._nearest_ladder_index(snap["gateway"]["canary_weight"])
            if actual_idx < self.state["step_index"]:
                self.state["step_index"] = actual_idx
            self._enter("ROLLBACK_SHIFT",
                        f"人工决策【撤回】：先把网关配置切回基线 {spec['base_config']}，"
                        f"再按阶梯把 v2 权重从实际值 "
                        f"{snap['gateway']['canary_weight']}% 降到 0（每档仍是绝对值设置）")
            return

        if time.time() - self._last_hold_event > 2:
            self.log(
                "GATE_WAITING",
                f"灰度暂停在 {GATE_WEIGHT}% 决策点：实际 v2 权重 "
                f"{snap['gateway']['canary_weight']}%，"
                f"v2 不健康实例 {unhealthy or '无'}，等待人工补齐/撤回；"
                "等待期间不执行任何流量变更",
                observed=self._obs(snap),
            )
            self._last_hold_event = time.time()

    # ---------------------------------------------------------- 反向：阶梯降权
    def _shift_backward(self, snap: dict) -> None:
        gw = snap["gateway"]
        idx = self.state["step_index"]
        target = WEIGHT_LADDER[idx]

        if gw["canary_weight"] > target:
            self.dp.set_weight(target)
            self._hold_remaining = HEALTH_HOLD_TICKS
            self._persist()
            self.log(
                "WEIGHT_ROLLBACK",
                f"撤回：网关 canary 权重绝对值降为 {target}%（v1 恢复到 {100 - target}%），"
                "降权同样是绝对值操作，不会与历史命令叠加",
                observed=self._obs(snap),
                action={"set_canary_weight": target, "set_base_weight": 100 - target},
            )
            return

        if self._hold_remaining > 0:
            self._hold_remaining -= 1
            self._persist()
            return

        if idx == 0:
            self._enter("CLEANUP", "v2 流量已归零，开始清理灰度实例与配置")
            return

        self.state["step_index"] = idx - 1
        self._persist()
        self.log("ROLLBACK_STEP",
                 f"撤回步进后退到 step={idx - 1}（目标 v2={WEIGHT_LADDER[idx - 1]}%）",
                 observed=self._obs(snap))

    # ------------------------------------------------------------------ 清理
    def _cleanup_forward(self, snap: dict) -> None:
        """补齐收尾：v2 已 100%，逐台终止 v1 基线实例，保留并转正 canary。"""
        spec = self.state["release"]["spec"]
        v1_live = [i for i in snap["instances"]
                   if i["version"] == spec["base_version"] and i["status"] == "running"]
        if v1_live:
            inst = v1_live[0]
            self.dp.terminate_instance(inst["id"])
            self._persist()
            self.log(
                "TERMINATE_BASELINE",
                f"补齐收尾：v2 已承接 100% 流量，终止基线实例 {inst['id']}"
                f"（{inst['version']}），canary 实例保留并转正",
                observed=self._obs(snap),
                action={"terminate": inst["id"]},
            )
            return
        gw = snap["gateway"]
        self._enter("DONE",
                    f"全量发布完成，最终状态：v2=100%（网关记录 canary_weight={gw['canary_weight']}%），"
                    f"网关配置 {gw['config_version']}，存活实例 "
                    f"{[i['id'] for i in snap['instances'] if i['status'] == 'running']}")

    def _cleanup_rollback(self, snap: dict, v2_live: list[dict]) -> None:
        """撤回收尾：v2 流量已归零，终止 canary 实例并把网关权重恢复为 0。"""
        spec = self.state["release"]["spec"]
        if v2_live:
            inst = v2_live[0]
            self.dp.terminate_instance(inst["id"])
            self._persist()
            self.log(
                "TERMINATE_CANARY",
                f"撤回收尾：终止灰度实例 {inst['id']}（{inst['version']}），"
                "流量已完全不经过它，基线版本继续全量服务",
                observed=self._obs(snap),
                action={"terminate": inst["id"]},
            )
            return
        gw = snap["gateway"]
        if gw["canary_weight"] != 0:
            self.dp.set_weight(0)
            self._persist()
            self.log("WEIGHT_RESET", "收尾：网关 canary 权重归零",
                     observed=self._obs(snap), action={"set_canary_weight": 0})
            return
        if gw["config_version"] != spec["base_config"]:
            self.dp.set_gateway_config(spec["base_config"])
            self._persist()
            self.log("GATEWAY_CONFIG_RESTORE",
                     f"收尾：网关配置恢复基线 {spec['base_config']}",
                     observed=self._obs(snap),
                     action={"gateway_config": spec["base_config"]})
            return
        self._enter("DONE",
                    f"撤回完成，最终状态：v2={gw['canary_weight']}%，"
                    f"网关配置 {gw['config_version']}，存活实例 "
                    f"{[i['id'] for i in snap['instances'] if i['status'] == 'running']}")

    # ------------------------------------------------------------------ 辅助
    @staticmethod
    def _nearest_ladder_index(weight: int) -> int:
        """实际权重到阶梯档位的就近映射（权重恰在档位上时精确命中）。"""
        if weight in WEIGHT_LADDER:
            return WEIGHT_LADDER.index(weight)
        return min(range(len(WEIGHT_LADDER)),
                   key=lambda k: abs(WEIGHT_LADDER[k] - weight))

    def _enter(self, phase: str, basis: str) -> None:
        old = self.state["phase"]
        self.state["phase"] = phase
        self._persist()
        self.log("PHASE_CHANGE", f"阶段切换 {old} → {phase}：{basis}")

    @staticmethod
    def _obs(snap: dict) -> dict:
        return {
            "gateway": {"canary_weight": snap["gateway"]["canary_weight"],
                        "config_version": snap["gateway"]["config_version"]},
            "instances": [{"id": i["id"], "version": i["version"],
                           "config_version": i["config_version"],
                           "status": i["status"], "healthy": i["healthy"]}
                          for i in snap["instances"]],
        }


def _now() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())


def main() -> int:
    parser = argparse.ArgumentParser(description="灰度发布控制器")
    parser.add_argument("--dataplane", default="http://127.0.0.1:18080")
    parser.add_argument("--state-dir", required=True,
                        help="控制器持久化目录（state.json / events.jsonl / decision.json）")
    args = parser.parse_args()

    os.makedirs(args.state_dir, exist_ok=True)
    dp = DataPlane(args.dataplane)
    Controller(dp, args.state_dir).run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
