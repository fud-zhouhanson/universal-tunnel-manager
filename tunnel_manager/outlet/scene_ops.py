# -*- coding: utf-8 -*-
"""tunnel_manager.outlet/scene_ops — 情景切换与残留清理

由 P2 从 outlet/scene.py 的第 176–400 行**原样拆出**，正文逐字未改（与 P1 一样，只搬不改）。

【切片规则 —— 这不是漏写 import】
本项目按设计保持**单一扁平命名空间**：
  · 开发期入口 `python -m tunnel_manager.main` → 把所有切片拼进一个命名空间再执行；
  · 构建期 `bundle.py` → 同样顺序拼接成单文件 `dist/tunnel-manager.py`（纯源码，不含 exec）。
所以本文件里可以直接引用其它切片定义的函数与常量，无需 import。跨切片调用是既有事实。
本模块对外提供：active_ifaces、atrust_up、clean_residual_routes、do_scene、scene_steps
本模块依赖其它切片：_base、consts、detect/iface、outlet/manager、outlet/scene、util、win/identify、win/outlets、win/switch
"""
>>>SLICE_BODY<<<
def active_ifaces():
    """本机当前存在的网络接口名集合（跨平台）。"""
    if IS_WIN:
        return {i["name"] for i in scan_interfaces_win() if i.get("name")}
    return set(_sh("ifconfig -l").split())


def atrust_up():
    """aTrust 是否还在承载隧道（接口存在，或路由表里还有指向 utun7 的条目）。"""
    ifs = active_ifaces()
    if "utun7" in ifs:
        return True
    nets = _sh("netstat -rn -f inet | awk '{print $4}' | sort -u")
    return "utun7" in nets.split()


def scene_steps(target):
    """从任意当前态切到 target 的步骤清单（mode: auto 工具做 / manual 用户做）。"""
    if target == "game":
        return [
            {"key": "stop_atrust", "desc": "完全退出 aTrust", "mode": "auto",
             "detail": "按 WatchDog → Tunnel → Daemon 顺序 bootout 三个守护作业"},
            {"key": "clean_routes", "desc": "清理残留路由", "mode": "auto",
             "detail": "删掉指向已消失接口的条目，避免流量被黑洞"},
            {"key": "start_leigod", "desc": "在雷神加速器里点「开始加速」", "mode": "manual",
             "detail": "加速开关只在它的 GUI 里（本地控制口协议尚未还原）"},
            {"key": "verify", "desc": "校验出口是否已切到加速器", "mode": "verify",
             "detail": "切完后重新扫描，看情景是否变成「游戏模式」"},
        ]
    if target == "campus":
        return [
            {"key": "stop_leigod", "desc": "在雷神加速器里点「停止加速」", "mode": "manual",
             "detail": "同上，需要在其 GUI 操作"},
            {"key": "clean_routes", "desc": "清理残留路由", "mode": "auto",
             "detail": "删掉指向已消失接口的条目"},
            {"key": "start_atrust", "desc": "拉起 aTrust", "mode": "auto",
             "detail": "bootstrap 回三个守护作业并打开 App"},
            {"key": "login_atrust", "desc": "在 aTrust 里完成登录", "mode": "manual",
             "detail": "重新拉起后通常需要重新登录，约 10~30 秒"},
            {"key": "verify", "desc": "校验出口是否已切到 aTrust", "mode": "verify",
             "detail": "切完后重新扫描，看情景是否变成「校内模式」"},
        ]
    return []


def _del_route_cmd(dest):
    if "/" in dest:
        net, _slash, bits = dest.partition("/")
        if bits == "32":
            return f"route -n delete -host {net}"
        return f"route -n delete -net {dest}"
    return f"route -n delete -host {dest}"


def _win_clean_residual_routes():
    """Windows：删掉「所在接口已经不存在」的 IPv4 路由。

    与 macOS 同口径 —— 只动「指向不存在接口」的条目，**绝不碰默认路由**，
    也不碰任何还活着的接口上的路由。
    """
    valid = active_ifaces()
    stale = []
    for dest, alias in _routes_snapshot():
        if dest == "default":
            continue                       # 默认路由永远不动
        if alias and alias not in valid:
            stale.append(dest)
    stale = sorted(set(stale), key=lambda d: -len(d))
    if not stale:
        return 0, "无残留路由"

    lines = ["$ok=$true"]
    for d in stale:
        s = str(d).replace("'", "''")
        lines.append("try { Remove-NetRoute -DestinationPrefix '%s' "
                     "-Confirm:$false -ErrorAction Stop } catch { $ok=$false; "
                     "Write-Output ('ERR %s: ' + $_.Exception.Message) }" % (s, s))
    lines.append("if ($ok) { Write-Output '__TM_OK__' } "
                 "else { Write-Output '__TM_FAIL__' }")
    ok, text, cancelled = _win_elevated(lines, _cmd_remove_routes(stale))
    if cancelled:
        return 0, "NEED_ADMIN"
    if not ok:
        return 0, "清理未完全成功：%s" % (text[:160] or "未知原因")
    return len(stale), "已清理 %d 条（%s）" % (len(stale), ", ".join(stale[:6]))


def clean_residual_routes(pw=None):
    """删掉指向「已不存在的接口」的路由。返回 (条数, 说明)。"""
    if IS_WIN:
        return _win_clean_residual_routes()
    if not IS_MAC:
        return 0, "仅 macOS 支持"
    valid = active_ifaces()
    stale = []
    for line in _sh("netstat -rn -f inet").splitlines():
        p = line.split()
        if len(p) < 4:
            continue
        dest, netif = p[0], p[3]
        if netif.startswith(("utun", "feth", "tun", "tap", "ppp")) and netif not in valid:
            stale.append(dest)
    stale = sorted(set(stale), key=lambda d: -len(d))
    if not stale:
        return 0, "无残留路由"
    cmd = " ; ".join(_del_route_cmd(d) for d in stale)
    rc, _out, _err = run_root(cmd, pw)
    if rc == 403:
        return 0, "NEED_SUDO"
    return len(stale), f"已清理 {len(stale)} 条（{', '.join(stale[:6])}）"


def _atrust_entry():
    for k in TUNNEL_KNOWLEDGE:
        if k.get("name", "").lower().startswith("atrust"):
            return k
    return None


def _win_do_scene(target, pw=None):
    """Windows 上的情景切换 —— 复用「出口切换」那条路径，不另起一套。

    情景在这边其实就是「选一个出口」：
      campus → 切到 aTrust（它的 Windows 服务由出口层负责启停）
      game   → 切到「物理直连」（顺带停掉所有在用的隧道），
               再让用户在加速器界面点「开始加速」
               —— Windows 版加速器和 macOS 一样，开关只在 GUI 里
    """
    if target not in ("game", "campus"):
        return {"ok": False, "target": target, "done": [], "manual": [],
                "message": f"未知情景：{target}"}

    if target == "campus":
        key = next((o["key"] for o in discover_outlets()
                    if o["key"] != DIRECT_OUTLET
                    and o["key"].lower().startswith("atrust")), None)
        if not key:
            return {"ok": False, "target": target, "done": [], "manual": [],
                    "message": "没有发现 aTrust 这个出口（本机可能没装）"}
        r = switch_outlet(key, pw)
        r["target"] = target
        return r

    r = switch_outlet(DIRECT_OUTLET, pw)
    r["target"] = target
    r["manual"] = (["在加速器里点「开始加速」—— Windows 版的加速开关同样只在它自己的界面里"]
                   + (r.get("manual") or []))
    return r


def do_scene(target, pw=None):
    """执行情景切换里「可自动」的部分。
    返回 {ok, target, done, manual, message}；不需要的步骤不会出现。
    """
    if IS_WIN:
        return _win_do_scene(target, pw)
    if not IS_MAC:
        return {"ok": False, "target": target, "done": [], "manual": [],
                "message": f"情景切换当前仅支持 Windows / macOS"}
    if target not in ("game", "campus"):
        return {"ok": False, "target": target, "done": [], "manual": [],
                "message": f"未知情景：{target}"}

    # ---- 前置探测：没权限就**一步都不做** ----
    # 为什么必须放在最前面：情景切换天生是**多步**的（先停对家、再清残留路由），
    # 每一步都要 root。以前是做完第一步才发现没权限 —— 用户被留在
    # 「aTrust 已经摘掉、残留路由还挂着」的半残状态，比什么都不做更糟。
    can, _code, text = priv_capability(pw)
    if not can:
        return {"ok": False, "target": target, "read_only": True, "done": [],
                "manual": [{"key": s["key"], "desc": s["desc"],
                            "detail": s["detail"], "mode": s["mode"]}
                           for s in scene_steps(target)
                           if s["mode"] in ("manual", "verify")],
                "message": f"{text} —— 未做任何改动；可先按下面的步骤手动操作"}

    done, manual, need_sudo = [], [], False

    if target == "game":
        if atrust_up():
            # 走 stop_launchd_jobs 而不是自己拼命令：那里带**失败自动回滚**
            # （卸了一半会把已卸的 bootstrap 回来），
            # 情景切换停的正是同一个 WatchDog → Tunnel → Daemon 组合。
            ok, msg = stop_launchd_jobs(ATRUST_JOBS, ATRUST_PLISTS, pw, "aTrust")
            if msg == "NEED_SUDO":
                need_sudo = True
                done.append({"key": "stop_atrust", "ok": False,
                             "detail": "需要管理员密码才能停 aTrust"})
            else:
                done.append({"key": "stop_atrust", "ok": ok, "detail": msg})
        else:
            done.append({"key": "stop_atrust", "ok": True,
                         "detail": "aTrust 本来就没在跑"})
    else:
        targets = []
        for p in ATRUST_PLISTS:
            t = _safe_launchd_tokens(f"system {p}".split())
            if t:
                targets.append(" ".join(t))
        cmds = " ; ".join(f"launchctl bootstrap {t} 2>/dev/null || true"
                          for t in targets)
        rc, _o, _e = run_root(cmds, pw)
        if rc == 403:
            need_sudo = True
            done.append({"key": "start_atrust", "ok": False,
                         "detail": "需要管理员密码才能拉起 aTrust"})
        else:
            _sh('open -a "aTrust"')
            done.append({"key": "start_atrust", "ok": True,
                         "detail": "已恢复守护作业并打开 App"})

    if not need_sudo:
        _n, msg = clean_residual_routes(pw)
        if msg == "NEED_SUDO":
            need_sudo = True
            done.append({"key": "clean_routes", "ok": False, "detail": "需要管理员密码"})
        else:
            done.append({"key": "clean_routes", "ok": True, "detail": msg})

    for s in scene_steps(target):
        if s["mode"] in ("manual", "verify"):
            manual.append({"key": s["key"], "desc": s["desc"],
                           "detail": s["detail"], "mode": s["mode"]})

    if need_sudo:
        msg = "需要管理员密码才能完成自动步骤"
    elif manual:
        msg = "自动步骤已完成，请继续完成下面的手动步骤"
    else:
        msg = "切换完成"
    return {"ok": not need_sudo, "target": target, "done": done,
            "manual": manual, "message": msg}


