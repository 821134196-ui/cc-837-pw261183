#!/usr/bin/env python3
"""端到端自测（不依赖浏览器，全部走数据面 HTTP API）。

覆盖：
1. 场景 A（补齐）：走到 50% 时 SIGKILL 控制器 → 重启恢复核对 → 人工补齐 → 全量成功；
2. 场景 B（撤回）：同样中断 → 恢复后注入故障 → 人工撤回 → 回滚完成；
3. 关键安全断言：权重命令序列单调、每个权重值只生效一次（幂等跳过不算放大），
   恢复核对期间不存在任何超过 50% 的权重设置；
4. 控制器在 50% 被 kill 期间，数据面实际状态不漂移。
"""
from __future__ import annotations

import os
import json
import subprocess
import sys
import time
import urllib.error
import urllib.request

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 18099
BASE = f"http://127.0.0.1:{PORT}"
HERE = os.path.dirname(os.path.abspath(__file__))
RUN = os.path.join(HERE, "run")


def call(method: str, path: str, body: dict | None = None, timeout: int = 10):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data=data, method=method,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        raise AssertionError(f"HTTP {exc.code} {path}: {exc.read().decode()}") from None


def wait_until(desc, predicate, timeout=120, interval=0.5):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        try:
            last = call("GET", "/api/state")
        except urllib.error.URLError:
            time.sleep(interval)
            continue
        if predicate(last):
            return last
        time.sleep(interval)
    raise AssertionError(f"等待超时: {desc}; 最后状态: {json.dumps(last, ensure_ascii=False)[:600]}")


def weight_commands(state: dict) -> list[dict]:
    return [c for c in state["command_log"] if c["command"] == "setWeight"]


def effective_weight_trace(state: dict) -> list[int]:
    """真正生效（非幂等跳过）的权重序列。"""
    return [c["params"]["canary_weight"] for c in weight_commands(state) if not c["skipped"]]


def assert_common_safety(state: dict, label: str) -> None:
    trace = effective_weight_trace(state)
    print(f"  [{label}] 生效权重轨迹: {trace}")
    decision = state["release"]["decision"]
    gate = state["release"]["spec"]["gate_weight"]

    if decision == "abort":
        # 撤回：以决策点为界，前半段单调非降，后半段单调非升；
        # 同一档位在升、降两个方向各出现一次是合法回退，不是“重复放大”。
        peak = max(trace)
        assert peak == gate, f"{label}: 撤回路径权重曾超过决策点: {peak}%"
        peak_pos = trace.index(peak)
        upward = trace[:peak_pos + 1]
        downward = trace[peak_pos:]
        assert all(b >= a for a, b in zip(upward, upward[1:])), \
            f"{label}: 决策点前出现降权: {upward}"
        assert all(b <= a for a, b in zip(downward, downward[1:])), \
            f"{label}: 撤回决策后出现反向放大: {downward}"
        print(f"  [{label}] 撤回轨迹分段单调：升段 {upward} / 降段 {downward}，无二次放大")
    else:
        # 补齐：整条轨迹严格单调上升，每个权重值最多生效一次。
        assert all(b > a for a, b in zip(trace, trace[1:])), \
            f"{label}: 补齐轨迹非严格上升: {trace}"
        duplicates = {w for w in trace if trace.count(w) > 1}
        assert not duplicates, f"{label}: 权重值被重复生效 {duplicates}"

    # 恢复核对（重启）发生在 50% 阶段：核对之后、人工决策登记之前，
    # 不允许任何权重变更（控制器只能核对、等待，不能自行放大或缩小）。
    events = state["controller_events"]
    verify_idx = [i for i, e in enumerate(events) if e["type"] == "RECONCILE_VERIFY"]
    assert verify_idx, f"{label}: 未找到恢复核对事件"
    for vi in verify_idx:
        later = events[vi + 1:]
        decision_pos = next(
            (k for k, e in enumerate(later)
             if e["type"] == "PHASE_CHANGE" and
             ("人工决策【补齐】" in e["basis"] or "人工决策【撤回】" in e["basis"])),
            len(later),
        )
        before_decision = later[:decision_pos]
        leaked = [e for e in before_decision
                  if e["type"] in ("WEIGHT_SET", "WEIGHT_ROLLBACK")]
        assert not leaked, f"{label}: 恢复核对后、人工决策前出现了权重变更 {leaked}"
        # 决策后的首个权重方向必须与决策一致：
        # 补齐 → 只能高于 50；撤回 → 只能低于 50。
        after = later[decision_pos:]
        first_change = next(
            (e for e in after if e["type"] in ("WEIGHT_SET", "WEIGHT_ROLLBACK")), None)
        if first_change:
            w = first_change["action"]["set_canary_weight"]
            if decision == "continue":
                assert w > gate, f"{label}: 补齐后首个权重 {w}% 未高于决策点 {gate}%"
            elif decision == "abort":
                assert w < gate, f"{label}: 撤回后首个权重 {w}% 未低于决策点 {gate}%"
    # 任何 setWeight 都必须是绝对值且 v1+v2=100。
    for c in weight_commands(state):
        p = c["params"]
        assert p["canary_weight"] + p["base_weight"] == 100, f"{label}: 权重之和不为 100: {p}"
    skipped = [c for c in weight_commands(state) if c["skipped"]]
    print(f"  [{label}] 幂等跳过的重复权重命令数: {len(skipped)}（重复绝对值命令不产生二次放大）")


def run_scenario(name: str, expect_status: str, expect_final_weight: int) -> None:
    print(f"\n=== 演练场景: {name} ===")
    call("POST", "/api/reset")
    call("POST", "/api/scenario/run", {"name": name})

    # 等待场景结束。
    final = wait_until(
        f"scenario {name} finished",
        lambda s: (s.get("scenario") or {}).get("status") in ("DONE", "FAILED"),
        timeout=150,
    )
    sc = final["scenario"]
    assert sc["status"] == "DONE", f"场景失败: {json.dumps(sc, ensure_ascii=False)}"
    assert final["release"]["status"] == expect_status, \
        f"发布单终态错误: {final['release']['status']} != {expect_status}"
    assert final["gateway"]["canary_weight"] == expect_final_weight
    print(f"  发布单终态: {final['release']['status']}，v2 最终权重: {expect_final_weight}%")

    # 控制器事件必须包含恢复核对，且事件全部带依据与实际状态快照。
    types = [e["type"] for e in final["controller_events"]]
    for required in ("CONTROLLER_START", "RECONCILE_VERIFY", "PHASE_CHANGE"):
        assert types.count(required) >= (2 if required == "CONTROLLER_START" else 1), \
            f"缺少事件 {required}，实际: {types}"
    for ev in final["controller_events"]:
        assert ev.get("basis"), f"事件缺少依据: {ev}"
        assert "observed" in ev and "action" in ev, f"事件缺少实际状态/动作: {ev}"
    verify_events = [e for e in final["controller_events"]
                     if e["type"] == "RECONCILE_VERIFY"]
    print(f"  恢复核对事件: {len(verify_events)} 条；"
          f"首个核对依据: {verify_events[0]['basis'][:80]}…")
    assert_common_safety(final, name)

    # kill 期间数据面不漂移：场景日志里应保留断开时的实际状态记录。
    steps = sc["steps"]
    drift_log = [s for s in steps if "控制器已断开" in s["message"]]
    assert drift_log, "缺少断控期间的数据面状态记录"
    print(f"  断控记录: {drift_log[0]['message'][:100]}…")

    # 控制器最终存活；发布单已走到终态（控制器随后自动回到 IDLE 等待下一单）。
    assert final["controller"]["alive"], "控制器最终未存活"
    assert final["release"]["finished_at"], "发布单未记录完成时间"


def main() -> int:
    proc = subprocess.Popen(
        [sys.executable, "-I", os.path.join(HERE, "dataplane.py"), "--port", str(PORT)],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    try:
        # 等待端口就绪。
        for _ in range(40):
            try:
                call("GET", "/api/state")
                break
            except urllib.error.URLError:
                time.sleep(0.25)
        else:
            out = proc.stdout.read() if proc.stdout else ""
            raise AssertionError(f"数据面未启动: {out}")

        run_scenario("success", "SUCCEEDED", 100)
        run_scenario("rollback", "ROLLED_BACK", 0)

        # 额外手工场景：不跑演练脚本，手动验证“kill 后实际状态不漂移 + 重启幂等”。
        print("\n=== 手工断控幂等测试 ===")
        call("POST", "/api/reset")
        call("POST", "/api/control/start")
        call("POST", "/api/releases", {"canary_version": "v2", "canary_config": "cfg-v2"})
        state = wait_until("gate reached",
                           lambda s: (s.get("controller") or {}).get("phase") == "GATE")
        weight_at_kill = state["gateway"]["canary_weight"]
        assert weight_at_kill == 50, f"决策点权重错误: {weight_at_kill}"
        call("POST", "/api/control/kill")
        time.sleep(3)
        mid = call("GET", "/api/state")
        assert mid["gateway"]["canary_weight"] == 50, "控制器停止期间网关权重漂移！"
        assert not mid["controller"]["alive"]
        print("  控制器 SIGKILL 后 3s，数据面权重稳定在 50%，无进程触碰流量")
        call("POST", "/api/control/start")
        state2 = wait_until(
            "gate again after restart",
            lambda s: (s.get("controller") or {}).get("phase") == "GATE"
            and s["controller"]["alive"] is True
            and (s.get("controller") or {}).get("epoch", 0) >= 2)
        assert state2["gateway"]["canary_weight"] == 50
        # 重启到决策点之间，不允许有任何生效的权重变更（只能幂等跳过）。
        trace = effective_weight_trace(state2)
        assert trace == [10, 25, 50], f"重启后出现额外权重变更: {trace}"
        print(f"  重启核对后生效权重轨迹仍为 {trace}，无重复放大")

        print("\n全部断言通过 ✔")
        return 0
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


if __name__ == "__main__":
    sys.exit(main())
