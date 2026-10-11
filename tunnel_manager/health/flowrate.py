# -*- coding: utf-8 -*-
"""tunnel_manager.health/flowrate — 真实流速（接口级累计字节差分）

由 P1 从 server.py 的第 5242–5800 行**整块搬迁**而来，正文逐字未改。

【切片规则 —— 这不是漏写 import】
本项目按设计保持**单一扁平命名空间**：
  · 开发期入口 `python -m tunnel_manager.main` → 把所有切片拼进一个命名空间再执行；
  · 构建期 `bundle.py` → 同样顺序拼接成单文件 `dist/tunnel-manager.py`（纯源码，不含 exec）。
所以本文件里可以直接引用其它切片定义的函数与常量，无需 import。跨切片调用是既有事实。
本模块对外提供：do_steam_diagnose、do_steam_overview、do_steam_probe、flow_get、steam_diagnose、steam_summary
本模块依赖其它切片：_base、detect/iface、health/flow、steam/diagnose、util、win/native
"""
>>>SLICE_BODY<<<
# ======================================================================
# 真实流速（L1：接口级累计字节差分）
# ======================================================================
# 为什么是这条路，而不是复用上面的 nettop 引擎：
#
#   · `netstat -ib` 一次调用约 12 毫秒、**免 root**、跨 *nix，直接给出每个接口开机
#     以来的累计收发字节；相邻两次采样做差分 = 该接口的**真实速率**（不是估算，
#     也不花任何额外流量）。上面那套 nettop 引擎回答的是「哪个程序在跑流量」，
#     但它单次调用有约 5 秒固定开销，且是进程级 —— 根本回答不了
#     「流量现在走物理网卡还是隧道、隧道占了多少」。
#   · 隧道客户端（aTrust / Clash 等）在内核里转发，**进程级 socket 计数 ≠ 过隧道的
#     字节**。所以判断「隧道跑多快」只能靠接口级计数 —— 也就是这里。
#
# 语义上要留意：隧道流量会「双层计数」。明文过 utunN，加密后从 en0 出去，
# 所以 en0 的字节数 ≈ 隧道字节数 + 加密开销 + 真正的直连流量。
# 因此「走隧道占比」= 隧道接口速率 / 物理接口速率（略小于真实占比，加密开销所致），
# 上限截到 100%，界面上如实说明这是近似值。
#
# Windows 侧：`netstat -e` 只给整机总量、**不分接口**；分接口要用
#   Get-NetAdapterStatistics（实测在 PowerShell 5.1 上免管理员可读）。
#   ⚠️ 本机没有 Windows 环境，**该分支未经真机验证**；失败时前端应降级提示。

_FLOW_LOCK = threading.Lock()
_FLOW_MAX = 60                 # 环形缓冲：保留最近 60 个采样点
_FLOW_INTERVAL = {"Darwin": 1.0, "Windows": 2.0}   # PowerShell 起进程贵，Windows 放慢一倍
_FLOW_IDLE = 180.0             # 超过 3 分钟没人来取数 → 采样线程自行退出，不白烧 CPU
_FLOW = {
    "hist": [],        # [{"t": 采样时刻, "if": {接口名: [下行 B/s, 上行 B/s]}}]
    "running": False,
    "last_req": 0.0,
    "started_at": 0.0,
    "error": "",
}


def _nat_flow_counters():
    """没有 PowerShell 时的兜底：`netstat -e` 只给**整机**累计字节（不分接口）。

    分接口要 Get-NetAdapterStatistics，那是 cmdlet；整机总量 netstat 就够了。
    所以退化成一个叫「整机」的接口 —— 数字是真的，只是粒度粗一档。
    """
    rc, out, _ = run(["netstat", "-e"], timeout=15)
    if rc != 0 or not out:
        return None
    for line in out.splitlines():
        nums = re.findall(r"\d+", line)
        if len(nums) == 2:          # 「字节 / Bytes」那一行正好两个大数，且在最前面
            try:
                return {"整机": (int(nums[0]), int(nums[1]))}
            except ValueError:
                continue
    return None


def _flow_read_counters():
    """读各接口的累计字节 → {接口名: (Ibytes, Obytes)}；读不到返回 None。"""
    if IS_MAC:
        rc, out, _ = run(["netstat", "-ib"], timeout=8)
        if rc != 0 or not out:
            return None
        got = {}
        for ln in out.splitlines()[1:]:          # 跳过表头
            tk = ln.split()
            # 列数会变：<Link#N> 行有的带 MAC、有的不带（lo0 就没有地址列），
            # 所以一律**从右往左**取，最后 7 列固定是
            # Ipkts Ierrs Ibytes Opkts Oerrs Obytes Coll
            if len(tk) < 8:
                continue
            name = tk[0].rstrip("*")             # 名字带 * 表示该接口当前是 down
            if not name or name in got:
                continue        # 同一接口会按地址族重复出现（<Link#N>/IPv4/IPv6），
                                # 各行计数完全相同 —— 只留第一行即可
            try:
                got[name] = (int(tk[-5]), int(tk[-2]))
            except ValueError:
                continue
        return got or None
    if IS_WIN:
        if not ps_available()[0]:
            return _nat_flow_counters()
        rc, out, _ = run_ps(
            "[Console]::OutputEncoding=[Text.Encoding]::UTF8;"
            "Get-NetAdapterStatistics | Select-Object "
            "@{n='name';e={$_.Name}},"
            "@{n='in';e={[int64]$_.ReceivedBytes}},"
            "@{n='out';e={[int64]$_.SentBytes}} | ConvertTo-Json -Depth 3",
            timeout=15)
        if rc != 0 or not out:
            return _nat_flow_counters()
        try:
            data = json.loads(out)
        except json.JSONDecodeError:
            return None
        if isinstance(data, dict):
            data = [data]
        got = {}
        for a in data:
            nm = (a or {}).get("name")
            if nm:
                got[nm] = (int(a.get("in") or 0), int(a.get("out") or 0))
        return got or None
    return None


def _flow_kind(name):
    """按接口名粗分类型。只用于界面分组；判定口径与主扫描保持一致。"""
    if re.match(r"^lo\d*$", name):
        return "回环"
    if is_tunnel_iface(name):
        return "隧道"
    if is_phys_iface(name):
        return "物理"
    if is_system_iface(name):
        return "系统虚拟"
    return "其他"


def _flow_loop():
    """采样循环。以「上次被取数的时刻」为准做闲置退出，避免没人看时白烧 CPU。"""
    interval = _FLOW_INTERVAL.get(PLATFORM, 1.0)
    prev = {}
    while True:
        with _FLOW_LOCK:
            if time.time() - _FLOW["last_req"] > _FLOW_IDLE:
                _FLOW["running"] = False
                return
        try:
            got = _flow_read_counters()
            now = time.time()
            if got is None:
                with _FLOW_LOCK:
                    _FLOW["error"] = "读不到接口流量计数"
                time.sleep(interval)
                continue
            rates = {}
            if prev:
                for nm, (ci, co) in got.items():
                    p = prev.get(nm)
                    if not p:
                        continue                # 这一轮才出现的接口，没有基值
                    dt = max(0.05, now - p[2])
                    di, do = ci - p[0], co - p[1]
                    if di < 0:                  # 接口重开 / 计数器回绕
                        di = ci
                    if do < 0:
                        do = co
                    rates[nm] = [di / dt, do / dt]
            prev = {nm: (ci, co, now) for nm, (ci, co) in got.items()}
            if rates:
                with _FLOW_LOCK:
                    _FLOW["hist"].append({"t": round(now, 2), "if": rates})
                    if len(_FLOW["hist"]) > _FLOW_MAX:
                        _FLOW["hist"] = _FLOW["hist"][-_FLOW_MAX:]
                    _FLOW["error"] = ""
            time.sleep(interval)
        except Exception as e:      # noqa: BLE001 —— 采样线程绝不能把服务带崩
            with _FLOW_LOCK:
                _FLOW["error"] = str(e)
            time.sleep(interval)


def _flow_assemble(hist, err):
    supported = PLATFORM in _FLOW_INTERVAL
    out = {"ok": True, "supported": supported, "platform": PLATFORM,
           "interval": _FLOW_INTERVAL.get(PLATFORM, 0),
           "window": _FLOW_MAX, "samples": len(hist),
           "age": (round(time.time() - hist[-1]["t"], 2) if hist else None),
           "rows": [], "ratio": None,
           "total": {"down": 0.0, "up": 0.0},
           "tunnel": {"down": 0.0, "up": 0.0},
           "error": err or ""}
    if not supported:
        out["note"] = (f"接口级流速暂只支持 macOS 与 Windows（当前 {PLATFORM}）。")
        return out

    # 只保留窗口里真正动过的接口 —— 本机常有二十多个死接口，全塞给前端没意义
    active = set()
    for h in hist:
        for nm, (di, do_) in h["if"].items():
            if di > 1 or do_ > 1:
                active.add(nm)
    last = hist[-1]["if"] if hist else {}
    for nm in sorted(active):
        dser = [h["if"].get(nm, [0.0, 0.0])[0] for h in hist]
        user = [h["if"].get(nm, [0.0, 0.0])[1] for h in hist]
        cur = last.get(nm) or [0.0, 0.0]
        out["rows"].append({
            "name": nm, "kind": _flow_kind(nm),
            "down": round(cur[0], 1), "up": round(cur[1], 1),
            "peak_down": round(max(dser), 1), "peak_up": round(max(user), 1),
            "hist_down": [int(v) for v in dser],
            "hist_up": [int(v) for v in user],
        })

    phys = [r for r in out["rows"] if r["kind"] == "物理"]
    tun = [r for r in out["rows"] if r["kind"] == "隧道"]
    t_dn = sum(r["down"] for r in tun)
    t_up = sum(r["up"] for r in tun)
    p_dn = sum(r["down"] for r in phys)
    p_up = sum(r["up"] for r in phys)
    if p_dn <= 1 and p_up <= 1:
        # 认不出物理网卡（例如 Windows 中文适配器名）→ 退回「所有非回环接口之和」
        others = [r for r in out["rows"] if r["kind"] != "回环"]
        p_dn, p_up = sum(r["down"] for r in others), sum(r["up"] for r in others)
    out["tunnel"] = {"down": round(t_dn, 1), "up": round(t_up, 1)}
    out["total"] = {"down": round(p_dn, 1), "up": round(p_up, 1)}
    # 隧道流量会双层计数（明文过 utun、密文再过 en0），所以这个比例是**近似下限**
    if p_dn > 1:
        out["ratio"] = round(min(1.0, t_dn / p_dn), 3)
    if not hist:
        out["note"] = "正在取第一个采样点（速率要两次采样差分才能算出来）。"
    elif not out["rows"]:
        out["note"] = "最近 60 秒所有接口都是零流量 —— 现在没有数据在走。"
    return out


def flow_get():
    """取流速快照；首个请求会拉起采样线程，闲置 3 分钟后线程自行退出。"""
    with _FLOW_LOCK:
        if not _FLOW["running"]:
            _FLOW["running"] = True
            _FLOW["hist"] = []
            _FLOW["error"] = ""
            _FLOW["started_at"] = time.time()
            threading.Thread(target=_flow_loop, daemon=True).start()
        _FLOW["last_req"] = time.time()
        hist = list(_FLOW["hist"])
        err = _FLOW["error"]
    return _flow_assemble(hist, err)


# ----------------------------------------------------------------------
# 诊断规则库（表驱动，便于扩展）
# ----------------------------------------------------------------------

def steam_diagnose(facts):
    """把观测事实映射成「原因 + 建议」。没有证据就不下结论。"""
    out = []

    def add(level, title, detail, advice=""):
        out.append({"level": level, "title": title, "detail": detail,
                    "advice": advice})

    env = facts.get("env") or {}
    if not env.get("installed"):
        add("info", "没找到 Steam 安装",
            "按该平台的常见路径都没找到 Steam 目录，下面所有检测都没有对象。",
            "先装好 Steam 并至少登录一次。")
        return out
    if not env.get("running"):
        add("info", "Steam 当前没在运行",
            "「连接日志」里的记录是上一次连接时写下的，可能已经过期；"
            "游戏进程相关的判断也会缺数据。",
            "开着 Steam 再做体检更准。")

    # R1 加速器接管了 SDR 中继 ★最重要的一条
    relays = facts.get("relays") or []
    tun_relays = [r for r in relays if r.get("is_tunnel")]
    if tun_relays:
        names = "、".join(f"{r['pop']}({r['ip']})" for r in tun_relays[:4])
        add("high", "加速器正在接管 SDR 中继",
            f"{len(tun_relays)} 个中继点（{names}）的流量走了隧道接口而不是物理网卡。"
            "杀戮尖塔这类游戏联机走的是 Steam Datagram Relay（Valve 自己的骨干中继），"
            "绕经加速器只会多一跳、还把可用 MTU 压小。",
            "在加速器里针对该游戏关闭加速，或整体停掉加速后重测。")

    # R2 隧道 MTU 偏小
    low = facts.get("low_mtu_tunnels") or []
    if low:
        names = "、".join(f"{n}（MTU {m}）" for n, m in low)
        add("high", "隧道 MTU 偏小，UDP 大包会被分片丢弃",
            f"{names} 的 MTU 低于 1400。游戏联机走 UDP，大包一旦分片，"
            "任何一片丢失都要整包重传 —— 表现就是「能进游戏但频繁瞬卡或掉线」。",
            "关掉这些隧道，或在客户端里把 MTU 调大。")

    # R3 实际命中的中继点
    cap = facts.get("capture") or {}
    an = cap.get("analysis") or {}
    hit = an.get("hit_relays") or []
    unknown = an.get("unknown_peers") or []
    if hit:
        pops = sorted({h["pop"] for h in hit})
        txt = "、".join(f"{h['pop']}（{h.get('pop_cn') or '?'}）{h['ip']}:{h['port']}"
                        for h in hit[:4])
        if "hkg" not in pops:
            add("mid", "实际连的中继不是香港",
                f"采样期间对端是 {txt}。国内玩家最近的 SDR 中继在香港（hkg），"
                "命中别的 pop 说明去香港的链路可能异常，或加速器改掉了选点。",
                "对比 hkg 各中继的 RTT 后再决定是否关加速。")
        else:
            add("info", "实际连的中继在香港",
                f"采样期间对端是 {txt} —— 这是国内玩家最理想的中继位置。")
        sub_only = [h for h in hit if h.get("match") == "subnet"]
        if sub_only:
            add("info", "有中继是按同网段推断的归属",
                "、".join(f"{h['ip']}（{h['pop']}）" for h in sub_only[:4])
                + " 不在本地缓存的 SDR 名单里，是按同一个 /24 网段推断出来的。"
                "Steam 的中继 IP 会换号，本地缓存只在上次联网时更新。",
                "点「刷新 SDR 名单」从官方接口重拉一次，归属会更准。")
    elif unknown:
        add("info", "抓到了对端，但认不出是哪个中继",
            "采样期间该进程连过 " + "、".join(f"{u['ip']}:{u['port']}"
                                        for u in unknown[:4])
            + "，这些 IP 不在已知中继名单里。可能是较新的中继（本地 SDR 缓存偏旧），"
            "也可能根本不是 Steam 的中继流量。",
            "点「刷新 SDR 名单」后重测，或进入对局后再采样一次。")
    elif cap.get("done"):
        add("info", "没抓到游戏的对端 IP",
            "采样期间该进程没有出现公网 UDP/TCP 对端。可能当时不在联机中，"
            "也可能游戏走的是别的进程。",
            "进入对局后再采样一次。")

    # R4 断续与乱序
    zr = an.get("zero_ratio")
    if zr is not None and zr > 0.2:
        add("mid", f"联机流量断续：{int(zr * 100)}% 的秒数没有数据",
            f"采样 {an.get('active_seconds')} 个有效秒里有 {an.get('zero_seconds')} 秒"
            "收发都为 0。" + ("期间目标进程还消失了 "
                          f"{an.get('missing_seconds')} 秒（可能已退出对局）。"
                          if an.get("missing_seconds") else ""),
            "配合下面「走哪条路」的判断一起看，先排除加速器与 MTU 问题。")
    if (an.get("rx_ooo_delta") or 0) > 0 or (an.get("re_tx_delta") or 0) > 0:
        add("mid", "出现乱序 / 重传",
            f"采样期间累计乱序 {an.get('rx_ooo_delta')} 字节、"
            f"重传 {an.get('re_tx_delta')} 次。这是「卡一下再跳回来」的直接物证。",
            "如果同时存在隧道接管或 MTU 偏小，优先处理那两项。")

    # R5 Steam 客户端自身反复重连（只算最近 24 小时，避免把历史累积误读成现状）
    cl = facts.get("console") or {}
    r24 = cl.get("restarts_24h") or 0
    if r24 >= 8:
        add("mid", "Steam 客户端反复重连",
            f"最近 24 小时的日志里出现 {r24} 次「Game process added」，"
            "说明客户端层在反复起停游戏进程 —— 这与加速器无关。",
            "先确认 Steam 自身网络正常，再看联机质量。")

    # R6 商店 / 社区
    tun_store = [d for d in (facts.get("store") or []) if d.get("is_tunnel")]
    if tun_store:
        add("mid", "商店 / 社区流量被隧道接管",
            "、".join(f"{d['host']}（{d['via']}）" for d in tun_store[:4])
            + "。商店和社区被绕进隧道后，常见症状是登录转圈、社区打不开。",
            "如果只是要开社区，考虑把这几个域名切到直连再试。")

    # R7 下载 CDN
    tun_cdn = [c for c in (facts.get("cdn") or []) if c.get("is_tunnel")]
    if tun_cdn:
        add("mid", "下载 CDN 被隧道接管",
            "、".join(f"{c['host']}（{c['via']}）" for c in tun_cdn[:4])
            + "。Steam 下载走的是国内 CDN，被加速器绕出去通常只会更慢。",
            "下载时建议关掉加速器。")

    # R8 ICMP 几乎全不可达 —— 如实说明这只是参考值
    if relays:
        dead = [r for r in relays if not r.get("icmp_ok")]
        if len(dead) > len(relays) * 0.6:
            add("info", "多数中继不回 ICMP",
                f"{len(dead)}/{len(relays)} 个中继点 ping 不通。"
                "SDR 走 UDP，中继不回 ICMP 是常见现象，**不代表游戏连不上**，"
                "别据此判断联机质量。",
                "以「实测联机」与「采样」的结论为准。")

    # R9 SDR 配置拿不到
    if (facts.get("sdr_meta") or {}).get("error"):
        add("info", "SDR 中继列表不完整",
            (facts.get("sdr_meta") or {}).get("error") or "",
            "中继探测结果可能不全，等 Steam 客户端跑过一次再试。")

    # R10 还没采样
    if not cap.get("done"):
        add("info", "还没做过联机采样",
            "P2P 稳定性必须在对局中边跑边采样才能判断，单看配置得不出结论。",
            "进游戏开一局，点「开始采样」，样本越长越准（建议 60 秒）。")

    return out


# ----------------------------------------------------------------------
# 对外入口
# ----------------------------------------------------------------------

def steam_summary():
    """给 /api/scan 用的**轻量摘要**：只读进程 + 日志尾部，不跑任何网络探测。

    必须保持在几十毫秒量级 —— 不能把扫描拖慢。
    """
    if not IS_MAC and not IS_WIN:
        return {"supported": False}
    env = steam_env()
    if not env.get("installed"):
        return {"supported": True, "installed": False, "running": False}
    cl = parse_steam_conn_log()
    best = (cl.get("cm") or [None])[0]
    last = (cl.get("latest") or [None])[-1]
    if last:
        last = dict(last)
        _iface, _verdict = _local_ip_verdict(last.get("local_ip"))
        last["local_iface"], last["verdict"] = _iface, _verdict
    return {
        "supported": True,
        "installed": True,
        "running": env.get("running"),
        "cell_id": env.get("cell_id"),
        "game_name": env.get("game_name"),
        "running_game": (env.get("running_game") or {}).get("app_dir", ""),
        "cm_best": ({"dc": best.get("dc"), "dc_cn": best.get("dc_cn"),
                     "ms": best.get("ms")} if best else None),
        "cm_count": len(cl.get("cm") or []),
        "last_conn": ({"at": last.get("at"), "server_ip": last.get("server_ip"),
                       "local_ip": last.get("local_ip"),
                       "local_iface": last.get("local_iface"),
                       "verdict": last.get("verdict")} if last else None),
        "log_at": cl.get("at") or "",
        "log_error": cl.get("error") or "",
        "capture": capture_state(),
    }


def do_steam_overview():
    """快照：安装/运行/账号/下载区域 + 平台网（CM 延迟）+ 游戏进程 + 采样状态。"""
    t0 = time.time()
    env = steam_env()
    cl = parse_steam_conn_log()
    csl = parse_steam_console_log()
    cl["latest"] = annotate_conn_rows(cl.get("latest") or [])
    return {
        "ok": True, "at": time.time(),
        "elapsed_ms": round((time.time() - t0) * 1000),
        "env": env, "cm": cl, "console": csl,
        "store_domains": STEAM_STORE_DOMAINS,
        "capture": capture_state(),
        "sdr_meta": {"source": "local" if env.get("sdr_cache") else "",
                     "error": ""},
    }


def do_steam_probe(appid=None, cell=None, force_online=False):
    """排行：CM 集群 / SDR 中继 / CDN / 商店 —— 真解析、真连、真看第一跳。"""
    if not IS_MAC:
        return {"error": f"实时探测暂仅支持 macOS（当前 {PLATFORM}）"}
    t0 = time.time()
    env = steam_env()
    appid, app_name = (str(appid), "") if appid else steam_guess_appid(env)
    cell_id = int(cell) if cell else env.get("cell_id") or STEAM_CDN_CELL

    pops, sdr_meta = steam_sdr_pops(appid, prefer_online=force_online)
    relays = sdr_relay_targets(pops, limit=12)
    phys, phys_gw = phys_iface_guess()
    am = local_addr_map()

    # 中继：先 ICMP（网络层参考值），再判它走哪条路。
    # 这里**不做第一跳** —— 每个目标 ping 一次要等超时，几十个目标会把体检拖到一分钟。
    # 判定「走没走加速器」靠源地址 + 路由声明就够了（和 quick_egress 同口径）。
    rtts = parallel_map(lambda r: icmp_probe(r["ip"]), relays, workers=12)
    for r, pair in zip(relays, rtts):
        ok, ms = pair or (False, None)
        r["icmp_ok"], r["icmp_ms"] = ok, ms
        p = steam_path_of(r["ip"], am, phys_gw, want_hop=False)
        for k in ("declared_iface", "src_ip", "src_iface", "first_hop",
                  "is_tunnel", "is_phys", "mismatch", "via"):
            r[k] = p[k]

    # CM 集群（平台网）
    cms = cm_targets(cell_id, limit=6)
    crows = parallel_map(
        lambda c: probe_host(c["host"], int(c["port"] or 443), am, phys_gw,
                             want_hop=False), cms, workers=6)
    for c, row in zip(cms, crows):
        c.update(row or {"via": "解析失败"})

    # 商店 / 社区 / API —— 这一组开第一跳：它是「直连还是加速器」证据最强的一栏
    stores = parallel_map(
        lambda d: probe_host(d, 443, am, phys_gw, want_hop=True),
        STEAM_STORE_DOMAINS, workers=4)

    # 内容分发网：官方列表 + 历史真实主机
    cdn = steam_cdn_servers(cell_id)
    for c in steam_cdn_history():
        if c["host"] not in [x["host"] for x in cdn]:
            cdn.append(c)
    cdn = cdn[:10]
    crows2 = parallel_map(
        lambda c: probe_host(c["host"], 80, am, phys_gw, want_hop=False),
        cdn, workers=6)
    for c, row in zip(cdn, crows2):
        c.update(row or {"via": "解析失败"})

    # 隧道 MTU 事实
    low_mtu = []
    try:
        for i in scan_interfaces_mac():
            if (i.get("status") == "active" and is_tunnel_iface(i["name"])
                    and i.get("mtu") and i["mtu"] < 1400):
                low_mtu.append((i["name"], i["mtu"]))
    except Exception:       # noqa: BLE001 —— 拿不到就不报
        pass

    return {
        "ok": True, "at": time.time(),
        "elapsed_ms": round((time.time() - t0) * 1000),
        "appid": appid, "app_name": app_name,
        "cell_id": cell_id,
        "phys_iface": phys, "phys_gw": phys_gw,
        "sdr_meta": sdr_meta, "pop_count": len(pops),
        "relays": relays, "cm": cms, "store": stores, "cdn": cdn,
        "low_mtu_tunnels": low_mtu,
        "capture": capture_result(relays),
    }


def do_steam_diagnose(appid=None, cell=None):
    """体检结论：把三类观测汇到规则库，产出「原因 + 建议」。"""
    if not IS_MAC:
        return {"error": f"暂仅支持 macOS（当前 {PLATFORM}）"}
    ov = do_steam_overview()
    pb = do_steam_probe(appid=appid, cell=cell)
    if pb.get("error"):
        return pb
    facts = {
        "env": ov.get("env") or {},
        "cm": ov.get("cm") or {},
        "console": ov.get("console") or {},
        "relays": pb.get("relays") or [],
        "cms": pb.get("cm") or [],
        "store": pb.get("store") or [],
        "cdn": pb.get("cdn") or [],
        "sdr_meta": pb.get("sdr_meta") or {},
        "low_mtu_tunnels": pb.get("low_mtu_tunnels") or [],
        "capture": pb.get("capture") or {},
    }
    findings = steam_diagnose(facts)
    hi = [f for f in findings if f["level"] == "high"]
    mid = [f for f in findings if f["level"] == "mid"]
    if hi:
        summary = f"发现 {len(hi)} 项高优先级问题：" + hi[0]["title"]
    elif mid:
        summary = f"发现 {len(mid)} 项需要注意的问题：" + mid[0]["title"]
    else:
        summary = "没有发现明显问题（已完成的观测范围内）"
    return {
        "ok": True, "at": time.time(),
        "appid": pb.get("appid"), "app_name": pb.get("app_name"),
        "cell_id": pb.get("cell_id"),
        "elapsed_ms": (ov.get("elapsed_ms") or 0) + (pb.get("elapsed_ms") or 0),
        "summary": summary,
        "counts": {"high": len(hi), "mid": len(mid),
                   "info": len(findings) - len(hi) - len(mid)},
        "findings": findings,
        "relays": pb.get("relays") or [],
        "cm": pb.get("cm") or [],
        "store": pb.get("store") or [],
        "cdn": pb.get("cdn") or [],
        "capture": pb.get("capture") or {},
        "sdr_meta": pb.get("sdr_meta") or {},
        "low_mtu_tunnels": pb.get("low_mtu_tunnels") or [],
        "phys_iface": pb.get("phys_iface"), "phys_gw": pb.get("phys_gw"),
    }


