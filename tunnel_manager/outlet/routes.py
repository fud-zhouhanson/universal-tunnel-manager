# -*- coding: utf-8 -*-
"""tunnel_manager.outlet/routes — 路由命令与旁路目标识别

由 P2 从 outlet/routes.py 的第 1–218 行**原样拆出**，正文逐字未改（与 P1 一样，只搬不改）。

【切片规则 —— 这不是漏写 import】
本项目按设计保持**单一扁平命名空间**：
  · 开发期入口 `python -m tunnel_manager.main` → 把所有切片拼进一个命名空间再执行；
  · 构建期 `bundle.py` → 同样顺序拼接成单文件 `dist/tunnel-manager.py`（纯源码，不含 exec）。
所以本文件里可以直接引用其它切片定义的函数与常量，无需 import。跨切片调用是既有事实。
本模块对外提供：TSRV_CACHE_FILE、TSRV_TTL、bypass_targets、detect_bypass_routes、excluded_ips、managed_domains 等 9 个
本模块依赖其它切片：_base、autotrack、config、consts、detect/scan、util、win/nat_net、win/nat_sys、win/probe
"""
>>>SLICE_BODY<<<
# ======================================================================
# 九、路由操作（内置，不依赖外部脚本）
# ======================================================================

def route_add_cmd(ip, gw):
    if IS_WIN:
        return f"route delete {ip} > $null 2>&1; route -p add {ip} MASK 255.255.255.255 {gw}"
    return f"route -n delete -host {ip} 2>/dev/null; route add -host {ip} {gw}"


def route_del_cmd(ip):
    """删路由。加 `|| true` 让单条失败不拖垮整批（路由可能已被客户端刷掉）。"""
    if IS_WIN:
        return f"route delete {ip} > $null 2>&1"
    return f"route -n delete -host {ip} >/dev/null 2>&1 || true"


def detect_bypass_routes(phys_gw, phys_iface):
    """从**当前路由表**实时找出「本程序加的 /32 直连路由」。

    特征（缺一不可）：主机路由 + 下一跳=物理网关 + 出口=物理网卡
                    + Flags 含 H(主机) 与 S(静态，system 自己加的不带 S)
    这样即使状态文件丢了，也能知道有哪些路由要交还。
    """
    if not phys_gw or not phys_iface:
        return []
    if IS_WIN:
        return _detect_bypass_win(phys_gw, phys_iface)
    rc, out, _ = run(["netstat", "-rn", "-f", "inet"])
    if rc != 0:
        return []
    found = []
    for line in out.splitlines():
        p = line.split()
        if len(p) < 4:
            continue
        dest, gw, flags, netif = p[0], p[1], p[2], p[3]
        # netstat 打印主机路由时目标不带 /xx 后缀；带后缀的是网段路由，跳过
        if not re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", dest):
            continue
        if gw != phys_gw or netif != phys_iface:
            continue
        if "H" not in flags or "S" not in flags:
            continue
        found.append(dest)
    return sorted(set(found))


def _detect_bypass_win(phys_gw, phys_iface):
    """从路由表实时找「本程序加的 /32 直连路由」：主机路由 + 下一跳=物理网关。"""
    if not ps_available()[0]:
        found = []
        for r in (_nat_route_print().get("routes") or []):
            if r["mask"] != "255.255.255.255" or r["gw"] != phys_gw:
                continue
            if phys_iface and (_nat_alias_by_ip(r["ip"]) or r["ip"]) != phys_iface:
                continue
            found.append(r["dest"])
        return sorted(set(found))
    ps = (
        "Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue | "
        "Where-Object { $_.PrefixLength -eq 32 -and $_.NextHop -eq '" + phys_gw + "' } | "
        "Select-Object -ExpandProperty DestinationPrefix"
    )
    rc, out, _ = run_ps(ps)
    if rc != 0:
        return []
    found = []
    for line in out.splitlines():
        ip = line.strip().split("/")[0]
        if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", ip):
            found.append(ip)
    return sorted(set(found))


def managed_domains():
    """本程序管理的域名 = 配置表 + 自动追踪到的（**去重**）。

    扫描展示与撤销操作都用这一份口径，避免「界面显示 3 条、撤销动了 5 条」这类不一致。
    去重是必须的：同一个域名可能既在配置表里、又被浏览器历史追踪到，
    重复会让 do_apply 对同一批 IP 连发两条 route add，第二条报错、把整条命令链的返回码带偏。
    """
    out, seen = [], set()
    for d in load_config() + get_auto_domains():
        key = (d or "").strip().lower()
        if key and key not in seen:
            seen.add(key)
            out.append(d)
    return out


# ----------------------------------------------------------------------
# 隧道客户端**自身服务器 IP**的识别与排除
#
# 为什么必须排除：隧道客户端（aTrust / Clash / ZeroTier …）要用一条**外层连接**
# 连到自己的服务器，这条通路是隧道的生命线。若把服务器 IP 也纳入管理：
#   · apply 时给它加 /32 直连路由 —— 让工具插手 VPN 客户端自己的保活路由，越权且无意义；
#   · undo 时误删它的路由 —— 可能直接让隧道的外层流量被卷进隧道内部（递归封装），隧道立刻瘫痪。
# 实测：某些校内 / 企业 VPN 客户端（如 aTrust）的服务器就是「客户端自带域名」，
#       而用户可能对照着把它加进了自建域名表 —— 所以必须靠机器识别 + 自动排除，
#       不能只依赖「用户别把它加进来」。
# ----------------------------------------------------------------------

TSRV_CACHE_FILE = os.path.join(CONFIG_DIR, "tunnel_servers.json")
TSRV_TTL = 120          # 秒；探测本身很快（lsof ~0.04s），但没必要每次扫描都跑
_tsrv_cache = (0.0, [], False)   # (过期时间, ip列表, 是否刚探测过)


def _proc_keywords():
    kws = []
    for e in TUNNEL_KNOWLEDGE:
        kws.extend(e.get("proc") or [])
    return sorted({k.lower() for k in kws})


def _probe_tunnel_server_ips():
    """探测隧道客户端对外连接的服务器 IP（只看公网地址）。"""
    if IS_WIN:
        return _probe_tunnel_server_ips_win()
    rc, out, _ = run(["lsof", "-nP", "-iTCP", "-iUDP"], timeout=15)
    if not out:
        return set()
    kws = _proc_keywords()
    found = set()
    for line in out.splitlines()[1:]:
        low = line.lower()
        if not any(k in low for k in kws):
            continue
        for m in re.finditer(r"->(\d{1,3}(?:\.\d{1,3}){3}):", line):
            ip = m.group(1)
            if is_public_ip(ip):
                found.add(ip)
    return found


def _probe_tunnel_server_ips_win():
    kws = _proc_keywords()
    if not ps_available()[0]:
        return _nat_tunnel_server_ips(kws)   # netstat -ano + tasklist
    kw_expr = ",".join("'" + k + "'" for k in kws)
    ps = (
        f"$kws = @({kw_expr}); "
        "Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | "
        "Where-Object { $_.RemoteAddress -notmatch '^(10\\.|127\\.|169\\.254\\.|192\\.168\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.)' } | "
        "ForEach-Object { $c = $_; $p = Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue; "
        "if ($p) { $n = $p.ProcessName.ToLower(); "
        "if ($kws | Where-Object { $n.Contains($_) }) { $c.RemoteAddress } } }"
    )
    rc, out, _ = run_ps(ps)
    found = set()
    for line in out.splitlines():
        ip = line.strip()
        if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", ip) and is_public_ip(ip):
            found.add(ip)
    return found


def tunnel_server_ips(force=False):
    """隧道客户端服务器 IP（内存缓存 + 磁盘持久化）。

    持久化是必要的：隧道**断开时**探测不到任何连接，但服务器 IP 依然必须保持排除，
    否则会在这个窗口里被 apply/undo 误处理。
    """
    global _tsrv_cache
    now = time.time()
    if not force and _tsrv_cache[0] > now:
        return _tsrv_cache[1]

    known = set()
    try:
        with open(TSRV_CACHE_FILE, encoding="utf-8") as f:
            known = {ip for ip in json.load(f).get("ips", [])
                     if isinstance(ip, str) and is_public_ip(ip)}
    except (OSError, ValueError):
        pass

    probed = _probe_tunnel_server_ips()
    merged = sorted(known | probed)
    if merged != sorted(known):
        try:
            os.makedirs(CONFIG_DIR, exist_ok=True)
            with open(TSRV_CACHE_FILE, "w", encoding="utf-8") as f:
                json.dump({"ips": merged}, f, ensure_ascii=False, indent=2)
        except OSError:
            pass
    _tsrv_cache = (now + TSRV_TTL, merged, True)
    return merged


def excluded_ips():
    """绝不由本工具托管的 IP。"""
    return set(tunnel_server_ips())


def bypass_targets(domains, phys_gw, phys_iface):
    """要交还隧道的 IP 集合 = 状态文件记录 ∪ 路由表实测到的「属于我们域名」的路由。

    两道过滤：
      1. 只删「目标 IP 属于我们管理域名」的（路由表里可能有别的程序加的路由）；
      2. 排除隧道客户端**自身服务器 IP**（误删会把隧道外层流量卷进隧道内部）。
    """
    excluded = excluded_ips()
    recorded = [ip for ip in read_state() if ip not in excluded]
    detected = [ip for ip in detect_bypass_routes(phys_gw, phys_iface)
                if ip not in excluded]

    # 我们管理的域名对应的公网 IP
    ours = set()
    for d in domains:
        for ip in resolve_a(d):
            if is_public_ip(ip) and ip not in excluded:
                ours.add(ip)

    safe = [ip for ip in detected if ip in ours]
    # 状态文件里的记录一律认账（哪怕域名已从列表移除）
    return sorted(set(recorded) | set(safe)), detected


