# -*- coding: utf-8 -*-
"""tunnel_manager.steam/trace — Steam 路径追踪（连接日志 / 控制台日志解析）

由 P2 从 steam/diagnose.py 的第 484–665 行**原样拆出**，正文逐字未改（与 P1 一样，只搬不改）。

【切片规则 —— 这不是漏写 import】
本项目按设计保持**单一扁平命名空间**：
  · 开发期入口 `python -m tunnel_manager.main` → 把所有切片拼进一个命名空间再执行；
  · 构建期 `bundle.py` → 同样顺序拼接成单文件 `dist/tunnel-manager.py`（纯源码，不含 exec）。
所以本文件里可以直接引用其它切片定义的函数与常量，无需 import。跨切片调用是既有事实。
本模块对外提供：annotate_conn_rows、parse_steam_conn_log、parse_steam_console_log、probe_host
本模块依赖其它切片：_base、detect/iface、detect/route、health/dns、health/probe、steam/paths
"""
>>>SLICE_BODY<<<
def probe_host(host, port=443, am=None, phys_gw="", want_hop=False):
    """真解析 + 真连一次（TCP 握手 RTT）+ 看它走哪条路。"""
    row = {"host": host, "port": port, "ips": [], "resolve_ms": None,
           "resolve_error": "", "tcp_ok": False, "tcp_ms": None,
           "src_ip": "", "src_iface": "", "declared_iface": "", "first_hop": "",
           "is_tunnel": False, "is_phys": False, "mismatch": False, "via": ""}
    ips, rms, rerr = sys_resolve(host)
    row["ips"], row["resolve_ms"], row["resolve_error"] = ips, rms, rerr
    if not ips:
        row["via"] = "解析失败"
        return row
    ip = ips[0]
    ok, tcp_ms, src = tcp_probe(ip, port, timeout=3)
    if not ok:
        # 443 不通时退一步试 80 —— 「连不上」本身也是有用的事实，但要尽量拿到 RTT
        ok2, tcp_ms2, src2 = tcp_probe(ip, 80, timeout=2)
        if ok2:
            row["port_fallback"] = 80
            ok, tcp_ms, src = ok2, tcp_ms2, src2
    row["tcp_ok"], row["tcp_ms"], row["src_ip"] = ok, tcp_ms, src
    am = local_addr_map() if am is None else am
    iface = am.get(src, "")
    decl = iface_of_mac(ip)
    hop = first_hop(ip) if (want_hop and IS_MAC) else ""
    row.update({"src_iface": iface, "declared_iface": decl, "first_hop": hop})
    tun = bool(iface and is_tunnel_iface(iface)) or bool(decl and is_tunnel_iface(decl))
    phi = bool(hop and phys_gw and hop == phys_gw) or bool(iface and is_phys_iface(iface))
    row["is_tunnel"], row["is_phys"] = tun, phi
    row["mismatch"] = bool(decl and iface and decl != iface)
    if phi and tun:
        row["via"] = "隧道声明 · 物理实际（不一致）"
    elif tun:
        row["via"] = "隧道接管"
    elif phi:
        row["via"] = "物理直连"
    else:
        row["via"] = iface or "未知"
    return row


# ----------------------------------------------------------------------
# 日志解析：Steam 自己写的「事实」
# ----------------------------------------------------------------------

_STEAM_CM_MS_RE = re.compile(
    r"\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\].*?"
    r"PingWebSocketCM\(\)\s*\(([^\s:()]+):(\d+)\)\s*results:\s*([0-9.]+)ms")
_STEAM_CONN_RE = re.compile(
    r"\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\].*?"
    r"ConnectionCompleted\(\)\s*\((\d+\.\d+\.\d+\.\d+):(\d+),\s*([^)]*)\)\s*"
    r"local address\s*\(([^:()]+):(\d+)\)")
_STEAM_EXT_RE = re.compile(r"external address\s*=\s*'([^']+)'")
_STEAM_CM_HOST_RE = re.compile(r"cmp\d+-([a-z]+\d?)\.steamserver\.net")


def parse_steam_conn_log():
    """解析 connection_log.txt 尾部。

    这里记着「连到哪个 Steam 服务器」和「用了哪个本地地址」——
    **本地地址就是「走没走加速器」的铁证**（172.21.0.2 = 加速器隧道；192.168.x.x = 物理网卡），
    是 Steam 自己写的，不需要抓包。
    """
    p = steam_path("logs", "connection_log.txt")
    row = {"ok": False, "error": "", "path": p, "cm": [], "latest": [],
           "external_ip": "", "at": "", "mtime": None}
    if not p or not os.path.isfile(p):
        row["error"] = "找不到 connection_log.txt（Steam 可能从未运行过）"
        return row
    try:
        row["mtime"] = os.path.getmtime(p)
    except OSError:
        pass
    txt = read_tail(p, STEAM_LOG_TAIL)
    if not txt:
        row["error"] = "日志读不到（权限或文件被占用）"
        return row
    row["ok"] = True

    cm = {}
    latest = []
    for line in txt.splitlines():
        m = _STEAM_CM_MS_RE.search(line)
        if m:
            at, host, port, ms = m.group(1), m.group(2), m.group(3), float(m.group(4))
            mm = _STEAM_CM_HOST_RE.search(host)
            dc = mm.group(1) if mm else host.split(".")[0]
            prev = cm.get(dc)
            if not prev or at >= prev["at"]:
                cm[dc] = {"dc": dc, "dc_cn": STEAM_POP_NAMES.get(dc, ""),
                          "host": host, "port": port,
                          "ms": round(ms, 1), "at": at}
            row["at"] = max(row["at"], at)
            continue
        m = _STEAM_CONN_RE.search(line)
        if m:
            at, ip, port, proto, laddr, lport = m.groups()
            latest.append({"at": at, "server_ip": ip, "server_port": port,
                           "proto": proto.strip(), "local_ip": laddr,
                           "local_port": lport})
            row["at"] = max(row["at"], at)
            continue
        m = _STEAM_EXT_RE.search(line)
        if m:
            row["external_ip"] = m.group(1)

    row["cm"] = sorted(cm.values(), key=lambda x: x["ms"])
    row["latest"] = latest[-8:]
    if not row["cm"] and not row["latest"]:
        row["error"] = "日志尾部没有可解析的连接记录（格式可能与预期不同）"
    return row


_STEAM_GAME_EVT_RE = re.compile(
    r"\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\]\s*Game process (added|removed)")


def _local_ip_verdict(ip, am=None):
    """本地地址 → (接口, 结论)。这是「走没走加速器」的判定核心。

    注意：connection_log 里 UDP 那条记的可能是 `0.0.0.0`（当时还没绑定本地地址），
    这时必须如实说「未知」，不能猜成物理网卡。
    """
    if not ip or ip in ("0.0.0.0", "::", "*"):
        return "", "未知"
    am = local_addr_map() if am is None else am
    iface = am.get(ip, "")
    if iface and is_tunnel_iface(iface):
        return iface, "隧道（加速已生效）"
    if iface and is_phys_iface(iface):
        return iface, "物理网卡（没走加速）"
    if iface:
        return iface, "其他接口"
    return "", "认不出的接口"


def annotate_conn_rows(rows):
    """给「最近连接」逐条标上本地地址属于哪个接口、以及结论。"""
    am = local_addr_map()
    for r in (rows or []):
        iface, verdict = _local_ip_verdict(r.get("local_ip"), am)
        r["local_iface"], r["verdict"] = iface, verdict
    return rows


def parse_steam_console_log():
    """console_log.txt：游戏进程的启停与启动参数（含 `--relay IP:port`）。"""
    p = steam_path("logs", "console_log.txt")
    row = {"ok": False, "error": "", "path": p, "events": [], "restarts": 0,
           "relay": "", "last_at": "", "running": False}
    if not p or not os.path.isfile(p):
        row["error"] = "找不到 console_log.txt"
        return row
    txt = read_tail(p, STEAM_LOG_TAIL)
    if not txt:
        row["error"] = "日志读不到"
        return row
    row["ok"] = True
    evts, relay, last_at = [], "", ""
    for line in txt.splitlines():
        m = _STEAM_GAME_EVT_RE.search(line)
        if m:
            evts.append({"at": m.group(1), "act": m.group(2)})
            last_at = m.group(1)
        mr = re.search(r"--relay\s+(\d+\.\d+\.\d+\.\d+):(\d+)", line)
        if mr:
            relay = f"{mr.group(1)}:{mr.group(2)}"
    row["events"] = evts[-40:]
    row["restarts"] = sum(1 for e in evts if e["act"] == "added")
    # 只看最近 24 小时 —— 不然会把历史累积的启动次数误读成「现在在反复重连」
    cutoff = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time() - 86400))
    row["restarts_24h"] = sum(1 for e in evts
                              if e["act"] == "added" and e["at"] >= cutoff)
    row["relay"] = relay
    row["last_at"] = last_at
    row["running"] = bool(evts and evts[-1]["act"] == "added")
    return row


# ----------------------------------------------------------------------
# SDR 中继：这个游戏实际会用到哪些中继点
# ----------------------------------------------------------------------

