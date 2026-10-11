# -*- coding: utf-8 -*-
"""tunnel_manager.outlet/scene — 情景判定与切换（游戏模式 / 校内模式）

由 P1 从 server.py 的第 1236–1635 行**整块搬迁**而来，正文逐字未改。

【切片规则 —— 这不是漏写 import】
本项目按设计保持**单一扁平命名空间**：
  · 开发期入口 `python -m tunnel_manager.main` → 把所有切片拼进一个命名空间再执行；
  · 构建期 `bundle.py` → 同样顺序拼接成单文件 `dist/tunnel-manager.py`（纯源码，不含 exec）。
所以本文件里可以直接引用其它切片定义的函数与常量，无需 import。跨切片调用是既有事实。
本模块对外提供：ATRUST_JOBS、ATRUST_PLISTS、KNOWN_OWNER_NAMES、OUTLET_CATS、SCENES、active_ifaces 等 11 个
本模块依赖其它切片：_base、consts、detect/iface、outlet/manager、util、win/native
"""
>>>SLICE_BODY<<<
# ======================================================================
# 八·五、情景判定（游戏模式 / 校内模式 / 直连）
# ======================================================================

SCENES = {
    "game":    {"name": "游戏模式", "desc": "加速器独占出口（Steam 等游戏走专线）"},
    "campus":  {"name": "校内模式", "desc": "aTrust 独占出口（校园资源、文献、数据库）"},
    "direct":  {"name": "直连模式", "desc": "无隧道接管，全部走物理宽带"},
    "tunnel":  {"name": "隧道接管", "desc": "有隧道接口在承载公网（归属未识别）"},
    "mixed":   {"name": "多出口冲突", "desc": "多个隧道客户端同时接管公网，可能互相踩死"},
    "unknown": {"name": "未知", "desc": ""},
}

# 能当「出口」用的类别（覆盖网络、虚拟网卡不是出口，只做识别不参与切换）
OUTLET_CATS = ("企业VPN", "开源VPN", "系统VPN", "代理", "加速器")

KNOWN_OWNER_NAMES = {k["name"] for k in TUNNEL_KNOWLEDGE}


def _owner_scene(owner):
    """把隧道归属映射到情景。不认识的一律 'other'（不参与情景判定）。"""
    o = owner or ""
    low = o.lower()
    if "atrust" in low or "深信服" in o or "sangfor" in low:
        return "campus"
    if "雷神" in o or "leigod" in low:
        return "game"
    if "网易uu" in o or "uubooster" in low or "uu加速" in o:
        return "game"
    return "other"


def _iface_owners(res):
    """算出每个隧道接口的归属：{iface: {"owner": str, "guessed": bool}}。

    为什么需要「猜」：实测在 macOS 上**拿不到 TUN 接口的厂商信息**——
    `lsof | grep utun` 看不到、`ifconfig` 没有 description、
    `system_profiler SPNetworkDataType` 也不列 utun。
    而 Clash / sing-box / 雷神这类客户端建的接口**全都叫 utunN**，名字毫无特征。
    所以只能退而求其次：用「谁在跑」反推，并且**只在证据唯一时才认领**，
    认不出来就如实标成未识别 —— 宁可显示「未识别」也不要瞎指一个。
    """
    ifaces = res.get("interfaces") or []
    software = [s["name"] for s in (res.get("running_software") or [])]

    owners, claimed, ghosts = {}, set(), []

    # ① 最高优先级：已确认过的指纹。
    #    **按「路由特征」匹配，而不是按接口名** —— 这点很关键：
    #    接口名 utunN 每次重连/重启都可能换号（雷神这次是 utun6，下次可能就是 utun8），
    #    但客户端加的那组路由（雷神固定是 1/2/4/8/16/32/64/128 那八条拆分，
    #    aTrust 是 198.18.0.0/24 + 198.18.255.0/24 + 128.0/3…）才是它的"签名"。
    #    按签名认，换多少次接口号都认得出来。
    fps = load_fingerprints()
    cur_routes = _routes_snapshot()
    for key, fp in fps.items():
        want = set(fp.get("routes") or [])
        if want:
            hit_ifaces = {i for (d, i) in cur_routes if d in want}
            if len(hit_ifaces) == 1:
                owners[hit_ifaces.pop()] = {"owner": key, "guessed": False,
                                            "from": "fingerprint-route"}
                claimed.add(key)
                continue
        for name in fp.get("ifaces") or []:
            if name not in owners:
                owners[name] = {"owner": key, "guessed": False,
                                "from": "fingerprint-iface"}
                claimed.add(key)

    for i in ifaces:
        if i.get("kind") != "隧道":
            continue
        name = i["name"]
        if name in owners:
            continue                       # 指纹已经认领
        own = i.get("owner") or ""
        if own in KNOWN_OWNER_NAMES:
            owners[name] = {"owner": own, "guessed": False}
            claimed.add(own)
        elif i.get("ipv4"):
            ghosts.append(name)          # 有 IPv4 但认不出厂商的隧道接口

    outlet_names = {k["name"] for k in TUNNEL_KNOWLEDGE if k.get("cat") in OUTLET_CATS}
    loose = [s for s in software if s in outlet_names and s not in claimed]

    if len(ghosts) == 1 and len(loose) == 1:
        owners[ghosts[0]] = {"owner": loose[0], "guessed": True}
    else:
        for g in ghosts:
            owners[g] = {"owner": "", "guessed": True}
    return owners


def detect_scene(res):
    """判定当前出口情景。

    「谁在承载公网」= 多点抽查（egress_counts）里命中公网探测点的**隧道**接口。
    只有隧道接口才算——物理网卡命中是正常现象；系统隧道 / ZeroTier 之类不承载公网，
    用 _owner_scene 归为 other 后排除。

    返回 {key, name, desc, directors, egress, main_egress}
    """
    if not isinstance(res, dict) or res.get("error"):
        return {"key": "unknown", "name": SCENES["unknown"]["name"],
                "desc": "", "directors": [], "egress": {}, "main_egress": ""}

    egress = res.get("egress_counts") or {}
    owners = _iface_owners(res)

    carriers = {}   # iface -> (scene, hits, owner)
    for name, hits in egress.items():
        try:
            hits = int(hits)
        except (TypeError, ValueError):
            continue
        if hits <= 0:
            continue
        info = owners.get(name)
        if info is None:
            continue                       # 物理网卡 / 回环 / 系统隧道
        own = info["owner"]
        sc = _owner_scene(own) if own else "tunnel"
        if sc == "other":
            continue                       # 系统隧道等，不参与
        carriers[name] = (sc, hits, own)

    if not carriers:
        key, directors = "direct", []
    else:
        scenes = {v[0] for v in carriers.values()}
        if len(scenes) == 1:
            key = scenes.pop()
        elif scenes - {"tunnel"}:
            key = "mixed"
        else:
            key = "tunnel"
        directors = sorted(
            ({"iface": k, "owner": v[2] or "（归属未识别）", "hits": v[1],
              "scene": v[0], "guessed": (owners.get(k) or {}).get("guessed", False)}
             for k, v in carriers.items()),
            key=lambda x: -x["hits"])

    info = SCENES.get(key, SCENES["unknown"])
    return {
        "key": key, "name": info["name"], "desc": info["desc"],
        "directors": directors, "egress": egress,
        "main_egress": res.get("main_egress") or "",
    }


# ======================================================================
# 八·六、情景切换（游戏模式 ⇄ 校内模式）
# ======================================================================
#
# 为什么是「半自动」：实测雷神与 aTrust 都是「拆分整段公网」的全量接管，
# 同时开必然在同一张路由表里争夺最长前缀 → 只能二选一（PLAN 路线 E）。
# 但两件事脚本做不到：
#   1) 雷神的「开始/停止加速」只在它自己的 GUI 里（helper 的 127.0.0.1:10908
#      WebSocket 控制口协议尚未还原）；
#   2) aTrust 重新拉起后需要用户登录。
# 所以工具负责「可自动的那半」：停对家、清残留、校验；GUI 那半交给用户。

ATRUST_JOBS = [
    "system/com.sangfor.aTrustTunnelWatchDog",   # 必须先停守卫：KeepAlive 会把隧道拉回来
    "system/com.sangfor.aTrustTunnel",
    "system/com.sangfor.aTrustDaemon",
]
ATRUST_PLISTS = [
    "/Library/LaunchDaemons/com.sangfor.aTrustDaemon.plist",
    "/Library/LaunchDaemons/com.sangfor.aTrustTunnel.plist",
    "/Library/LaunchDaemons/com.sangfor.aTrustTunnelWatchDog.plist",
]


def _sh(cmd, timeout=20):
    """跑一条只读命令，返回 stdout。"""
    try:
        p = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True,
                           errors="replace", timeout=timeout)
        return p.stdout
    except (OSError, subprocess.SubprocessError):
        return ""


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

    done, manual, need_sudo = [], [], False

    if target == "game":
        if atrust_up():
            cmds = " ; ".join(f"launchctl bootout {j}" for j in ATRUST_JOBS)
            rc, _o, _e = run_root(cmds, pw)
            if rc == 403:
                need_sudo = True
                done.append({"key": "stop_atrust", "ok": False,
                             "detail": "需要管理员密码才能停 aTrust"})
            else:
                done.append({"key": "stop_atrust", "ok": True,
                             "detail": "已 bootout 3 个守护作业"})
        else:
            done.append({"key": "stop_atrust", "ok": True,
                         "detail": "aTrust 本来就没在跑"})
    else:
        cmds = " ; ".join(
            f"launchctl bootstrap system {p} 2>/dev/null || true" for p in ATRUST_PLISTS)
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


