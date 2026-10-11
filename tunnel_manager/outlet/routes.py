# -*- coding: utf-8 -*-
"""tunnel_manager.outlet/routes — 路由操作（内置，不依赖外部脚本）

由 P1 从 server.py 的第 6099–6491 行**整块搬迁**而来，正文逐字未改。

【切片规则 —— 这不是漏写 import】
本项目按设计保持**单一扁平命名空间**：
  · 开发期入口 `python -m tunnel_manager.main` → 把所有切片拼进一个命名空间再执行；
  · 构建期 `bundle.py` → 同样顺序拼接成单文件 `dist/tunnel-manager.py`（纯源码，不含 exec）。
所以本文件里可以直接引用其它切片定义的函数与常量，无需 import。跨切片调用是既有事实。
本模块对外提供：CORE_CANDIDATES、TSRV_CACHE_FILE、TSRV_TTL、bypass_targets、detect_bypass_routes、do_apply 等 14 个
本模块依赖其它切片：_base、config、consts、detect/iface、detect/route、detect/scan、util、win/native
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


def do_apply(pw=None):
    # ⚠️ 必须用 managed_domains()（配置表 + 自动追踪），不能只用 load_config()。
    # 以前这里只读配置表，于是「自动追踪」追踪到的网站**永远不会被应用** ——
    # 面板里列得满满当当、主表也标着「被隧道接管」，点「应用」却一条都不变。
    cfg_domains = load_config()
    auto_domains = get_auto_domains()
    # 追踪到的可能已经在配置表里 → 只补差集，避免对同一批 IP 重复 route add
    cfg_set = {(d or "").strip().lower() for d in cfg_domains}
    auto_only = [d for d in auto_domains
                 if (d or "").strip().lower() not in cfg_set]
    domains = cfg_domains + auto_only

    if IS_MAC:
        def_iface, _ = default_route_mac()
        phys_iface = def_iface if not is_tunnel_iface(def_iface) else ""
        if not phys_iface:
            for i in scan_interfaces_mac():
                if is_phys_iface(i["name"]) and i["status"] == "active" and i["ipv4"]:
                    phys_iface = i["name"]
                    break
        gw = phys_gateway_mac(phys_iface)
    else:
        snap = win_snapshot()
        phys_iface = ""
        for i in scan_interfaces_win():
            if i.get("type") in (6, 71) and i.get("status") == "active":
                phys_iface = i["name"]
                break
        gw = next((r.get("NextHop", "") for r in snap.get("routes", [])
                   if r.get("InterfaceAlias") == phys_iface), "")

    # 网关本身必须是合法 IPv4（防注入）
    if not re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", gw or ""):
        return False, "找不到合法物理网关，无法添加直连路由"

    excluded = excluded_ips()
    cmds, state_ips = [], []
    skipped = 0
    skipped_vpn = []
    for d in domains:
        for ip in resolve_a(d):
            # 双保险：resolve_a 已过滤私网，这里再验一次
            if not is_public_ip(ip):
                skipped += 1
                continue
            # 隧道客户端自己的服务器：绝不托管（见 excluded_ips 的说明）
            if ip in excluded:
                skipped_vpn.append(ip)
                continue
            cmds.append(route_add_cmd(ip, gw))
            state_ips.append(ip)
    if not cmds:
        return False, "没有可用的公网 IP（可能解析失败或命中私网保护）"

    cmd_str = " ; ".join(cmds) if not IS_WIN else "\n".join(cmds)
    rc, out, err = run_root(cmd_str, pw)
    if rc == 403:
        return None, "NEED_SUDO"
    if IS_WIN and rc == -1:
        # Windows 的提权是 UAC，没有密码可输 —— 取消/超时时回 NEED_ADMIN，
        # 免得前端弹一个在 Windows 上根本没用的密码框。
        return None, "NEED_ADMIN"
    if rc != 0:
        return False, f"执行失败 (rc={rc})：{err or out}"

    vpn_note = (f"，并已跳过 {len(set(skipped_vpn))} 个隧道客户端自身服务器 IP"
                f"（{'、'.join(sorted(set(skipped_vpn)))}）") if skipped_vpn else ""
    if auto_only:
        src_note = (f"（配置表 {len(cfg_domains)} 个 + 自动追踪 {len(auto_only)} 个"
                    f"，追踪的是临时的，超过 {AUTO_EXPIRE // 60} 分钟没再看会自动移除）")
    else:
        src_note = f"（配置表 {len(cfg_domains)} 个，当前没有追踪到域名）"
    saved = write_state(state_ips)
    if not saved:
        # 记录写不进去也必须让用户知道 —— 否则下次 undo 无从下手
        return True, (f"完成：新增 {len(state_ips)} 条直连路由，出口 {phys_iface} ({gw})"
                      f"{src_note}{vpn_note}。⚠ 但状态文件写入失败（{STATE_FILE}），"
                      f"撤销时将以路由表实测结果为准。")
    return True, (f"完成：新增 {len(state_ips)} 条直连路由，出口 {phys_iface} ({gw})"
                  f"{src_note}{vpn_note}")


def do_undo(pw=None):
    """把直连路由交还隧道。

    不依赖状态文件也能work：以**路由表实测**为准，
    只删「下一跳=物理网关 且 IP 属于我们配置域名」的主机路由，避免误伤其它程序。
    """
    if IS_MAC:
        def_iface, _ = default_route_mac()
        phys_iface = def_iface if not is_tunnel_iface(def_iface) else ""
        if not phys_iface:
            for i in scan_interfaces_mac():
                if is_phys_iface(i["name"]) and i["status"] == "active" and i["ipv4"]:
                    phys_iface = i["name"]
                    break
        gw = phys_gateway_mac(phys_iface)
    else:
        snap = win_snapshot()
        phys_iface = ""
        for i in scan_interfaces_win():
            if i.get("type") in (6, 71) and i.get("status") == "active":
                phys_iface = i["name"]
                break
        gw = next((r.get("NextHop", "") for r in snap.get("routes", [])
                   if r.get("InterfaceAlias") == phys_iface), "")

    targets, detected = bypass_targets(managed_domains(), gw, phys_iface)
    if not targets:
        # 没有可安全删除的；若路由表里还有别的静态主机路由，告知用户但不动它
        leftovers = [ip for ip in detected if ip not in targets]
        if leftovers:
            return False, (f"没找到属于本程序域名的直连路由。路由表里另有 "
                           f"{len(leftovers)} 条主机路由疑似其它程序（如 VPN 客户端自身）"
                           f"添加的，未做改动以免影响隧道。")
        return False, "没有生效中的直连路由，无需撤销"

    cmds = [route_del_cmd(ip) for ip in targets]
    cmd_str = " ; ".join(cmds) if not IS_WIN else "\n".join(cmds)
    rc, out, err = run_root(cmd_str, pw)
    if rc == 403:
        return None, "NEED_SUDO"
    if IS_WIN and rc == -1:
        return None, "NEED_ADMIN"
    if rc != 0:
        return False, f"执行失败 (rc={rc})：{err or out}"

    # 事后校验：只看**路由表实测**（不能用 bypass_targets —— 它还会读状态文件，
    # 而状态文件此刻尚未删除，会导致永远误判为「没删干净」）
    if gw and phys_iface:
        still = [ip for ip in detect_bypass_routes(gw, phys_iface) if ip in targets]
    else:
        still = []

    if still:
        write_state(still)          # 保留没删掉的，下次还能重试
        return False, (f"部分交还失败：仍有 {len(still)} 条直连路由未清除 "
                       f"（{', '.join(still[:5])}{'…' if len(still) > 5 else ''}），"
                       f"已保留记录，可再点一次「交回隧道」重试。")

    try:
        os.remove(STATE_FILE)
    except OSError:
        pass
    return True, f"完成：撤销 {len(targets)} 条直连路由，流量已交回隧道管理"


CORE_CANDIDATES = [
    "/usr/local/bin/tunnel-bypass",
    os.path.expanduser("~/.workbuddy/skills/atrust-jitter-fallback/scripts/atrust-bypass.sh"),
    os.path.expanduser("~/atrust-tunnel-fallback/atrust-bypass.sh"),
]


def find_core():
    if not IS_MAC:
        return None
    for c in CORE_CANDIDATES:
        if os.path.isfile(c):
            return c
    return None


def do_daemon(action, pw=None):
    core = find_core()
    if not core:
        return False, "找不到守护脚本（仅 macOS 提供守护，需安装 skill）"
    sub = "daemon-install" if action == "install" else "daemon-remove"
    cmd = f"bash {core} {sub}"
    rc, out, err = run_root(cmd, pw)
    if rc == 403:
        return None, "NEED_SUDO"
    return rc == 0, out or err


