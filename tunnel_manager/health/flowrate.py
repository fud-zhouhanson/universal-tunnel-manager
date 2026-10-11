# -*- coding: utf-8 -*-
"""tunnel_manager.health/flowrate — 真实流速（接口级累计字节差分）

由 P2 从 health/flowrate.py 的第 1–235 行**原样拆出**，正文逐字未改（与 P1 一样，只搬不改）。

【切片规则 —— 这不是漏写 import】
本项目按设计保持**单一扁平命名空间**：
  · 开发期入口 `python -m tunnel_manager.main` → 把所有切片拼进一个命名空间再执行；
  · 构建期 `bundle.py` → 同样顺序拼接成单文件 `dist/tunnel-manager.py`（纯源码，不含 exec）。
所以本文件里可以直接引用其它切片定义的函数与常量，无需 import。跨切片调用是既有事实。
本模块对外提供：flow_get
本模块依赖其它切片：_base、detect/iface、util、win/probe
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

