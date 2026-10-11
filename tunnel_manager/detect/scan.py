# -*- coding: utf-8 -*-
"""tunnel_manager.detect/scan — 统一扫描（汇总各层证据）

由 P1 从 server.py 的第 5801–6098 行**整块搬迁**而来，正文逐字未改。

【切片规则 —— 这不是漏写 import】
本项目按设计保持**单一扁平命名空间**：
  · 开发期入口 `python -m tunnel_manager.main` → 把所有切片拼进一个命名空间再执行；
  · 构建期 `bundle.py` → 同样顺序拼接成单文件 `dist/tunnel-manager.py`（纯源码，不含 exec）。
所以本文件里可以直接引用其它切片定义的函数与常量，无需 import。跨切片调用是既有事实。
本模块对外提供：assemble、do_scan、read_state、scan_domains、scan_domains_mac、scan_mac 等 8 个
本模块依赖其它切片：_base、config、detect/iface、detect/judge、detect/process、detect/route、health/flow、health/flowrate、outlet/manager、outlet/routes、outlet/scene、util、win/native
"""
>>>SLICE_BODY<<<
# ======================================================================
# 八、统一扫描
# ======================================================================

def do_scan():
    domains = load_config()
    procs_blob = list_processes()
    software = detect_software(procs_blob)

    if IS_MAC:
        res = scan_mac(domains, software)
    elif IS_WIN:
        res = scan_win(domains, software)
    else:
        return {"error": f"暂不支持的平台：{PLATFORM}"}

    if isinstance(res, dict) and not res.get("error"):
        res["scene"] = detect_scene(res)
        res["outlets"] = discover_outlets(res)
        res["active_outlet"] = remembered_outlet()
        res["health_saved"] = os.path.isfile(HEALTH_FILE)
        if IS_MAC:
            try:
                res["egress_truth"] = quick_egress(res)
            except Exception as e:      # noqa: BLE001 —— 体检失败不该拖垮整个扫描
                res["egress_truth"] = []
                res["egress_truth_error"] = str(e)
        # Steam 摘要：只读进程 + 日志尾部，不跑网络探测（必须保持在几十毫秒量级）
        try:
            res["steam"] = steam_summary()
        except Exception as e:          # noqa: BLE001 —— 同上，绝不拖垮扫描
            res["steam"] = {"supported": True, "error": str(e)}
    return res


def scan_mac(domains, software):
    def_iface, def_gw = default_route_mac()
    raw = scan_interfaces_mac()
    egress_counts = probe_egress_mac()

    # 物理出口
    phys_iface = def_iface if not is_tunnel_iface(def_iface) else ""
    if not phys_iface:
        for i in raw:
            if is_phys_iface(i["name"]) and i["status"] == "active" and i["ipv4"]:
                phys_iface = i["name"]
                break
    phys_gw = def_gw if phys_iface == def_iface else ""
    if phys_iface and not phys_gw:
        phys_gw = phys_gateway_mac(phys_iface)

    interfaces = []
    for i in raw:
        name = i["name"]
        if is_system_iface(name):
            kind = "系统虚拟"
            owner = "macOS 系统接口（非业务隧道）"
        elif is_tunnel_iface(name):
            kind = "隧道"
            owner = classify_tunnel(
                name, "", i["ipv4"], i["ipv6_ula"], i["mtu"],
                def_iface, phys_iface, software, egress_counts)
        elif is_phys_iface(name):
            kind = "物理"
            owner = classify_phys(name, "", phys_iface)
        elif name == "lo0":
            kind = "回环"
            owner = "回环"
        else:
            kind = "其他"
            owner = "其他虚拟网卡"
        interfaces.append({
            "name": name, "kind": kind, "owner": owner,
            "ipv4": i["ipv4"], "ipv6_ula": i["ipv6_ula"],
            "mtu": i["mtu"], "status": i["status"],
            "is_default": name == def_iface, "is_phys": name == phys_iface,
        })

    domain_rows, tun_n, direct_n = scan_domains_mac(domains, phys_iface)
    # 直连路由：状态文件记录 ∪ 路由表实测（后者保证记录丢了也能显示 / 撤销）
    bypass_ips, _detected = bypass_targets(managed_domains(), phys_gw, phys_iface)
    bypass_recovered = bool(set(bypass_ips) - set(read_state()))

    # 自动追踪的域名也一起算路由走向
    auto_doms = get_auto_domains()
    auto_rows, auto_tun, auto_direct = scan_domains_mac(auto_doms, phys_iface)

    # 聚合路由接管检测：多点抽查里隧道接口命中数
    tunnel_probe = {k: v for k, v in egress_counts.items()
                    if is_tunnel_iface(k) and k != phys_iface}
    main_egress = max(egress_counts, key=egress_counts.get) if egress_counts else ""

    return assemble(
        software=software, phys_iface=phys_iface, phys_gw=phys_gw,
        def_iface=def_iface, interfaces=interfaces,
        domain_rows=domain_rows, tun_n=tun_n, direct_n=direct_n,
        bypass_ips=bypass_ips,
        egress_counts=egress_counts,
        tunnel_probe=tunnel_probe,
        main_egress=main_egress,
        auto_domains=auto_doms, auto_rows=auto_rows,
        auto_tun=auto_tun, auto_direct=auto_direct,
        bypass_recovered=bypass_recovered)


def scan_win(domains, software):
    snap = win_snapshot()
    def_iface, def_gw = default_route_win(snap)
    raw = scan_interfaces_win()

    phys_iface = ""
    for i in raw:
        if is_loopback_iface(i.get("name"), i.get("desc")):
            continue                       # 回环口也「有 IP、算 active」，必须排掉
        if i.get("type") in (6, 71) and i.get("status") == "active":
            phys_iface = i["name"]
            break
    if not phys_iface:
        for i in raw:
            if is_loopback_iface(i.get("name"), i.get("desc")):
                continue
            if not is_tunnel_iface(i["name"], i["desc"]) and i.get("status") == "active":
                phys_iface = i["name"]
                break
    if not phys_iface:
        phys_iface = def_iface if not is_tunnel_iface(def_iface) else ""

    gw_by_iface = {}
    for r in snap.get("routes", []):
        gw_by_iface.setdefault(r.get("InterfaceAlias", ""), r.get("NextHop", ""))
    phys_gw = gw_by_iface.get(phys_iface, "") or def_gw

    interfaces = []
    for i in raw:
        name = i["name"]
        if is_tunnel_iface(name, i["desc"]):
            kind = "隧道"
            owner = classify_tunnel(
                name, i["desc"], i["ipv4"], i["ipv6_ula"], i["mtu"],
                def_iface, phys_iface, software, {})
        elif i.get("type") in (6, 71):
            kind = "物理"
            owner = classify_phys(name, i["desc"], phys_iface)
        else:
            kind = "其他"
            owner = "其他虚拟网卡"
        interfaces.append({
            "name": name, "kind": kind, "owner": owner,
            "ipv4": i["ipv4"], "ipv6_ula": i["ipv6_ula"],
            "mtu": i["mtu"], "status": i["status"],
            "desc": i["desc"],
            "is_default": name == def_iface, "is_phys": name == phys_iface,
        })

    all_ips = []
    for d in domains:
        all_ips.extend(resolve_a(d))
    iface_map = iface_of_win_batch(list(dict.fromkeys(all_ips)))
    domain_rows, tun_n, direct_n = scan_domains(domains, iface_map, phys_iface)
    bypass_ips, _detected = bypass_targets(managed_domains(), phys_gw, phys_iface)
    bypass_recovered = bool(set(bypass_ips) - set(read_state()))

    auto_doms = get_auto_domains()
    auto_rows, auto_tun, auto_direct = scan_domains(auto_doms, iface_map, phys_iface)

    return assemble(
        software=software, phys_iface=phys_iface, phys_gw=phys_gw,
        def_iface=def_iface, interfaces=interfaces,
        domain_rows=domain_rows, tun_n=tun_n, direct_n=direct_n,
        bypass_ips=bypass_ips, egress_counts={}, tunnel_probe={},
        main_egress=phys_iface,
        auto_domains=auto_doms, auto_rows=auto_rows,
        auto_tun=auto_tun, auto_direct=auto_direct,
        bypass_recovered=bypass_recovered)


def scan_domains_mac(domains, phys_iface):
    rows = []
    tun_n = direct_n = 0
    for d in domains:
        ips = resolve_a(d)
        if not ips:
            rows.append({"domain": d, "ips": []})
            continue
        entries = []
        for ip in ips:
            cur = iface_of_mac(ip)
            is_tun = bool(cur) and is_tunnel_iface(cur)
            direct = bool(cur) and cur == phys_iface and not is_tun
            if is_tun:
                tun_n += 1
            elif direct:
                direct_n += 1
            entries.append({"ip": ip, "iface": cur, "direct": direct,
                            "tunnel": is_tun})
        rows.append({"domain": d, "ips": entries})
    return rows, tun_n, direct_n


def scan_domains(domains, iface_map, phys_iface):
    rows = []
    tun_n = direct_n = 0
    for d in domains:
        ips = resolve_a(d)
        if not ips:
            rows.append({"domain": d, "ips": []})
            continue
        entries = []
        for ip in ips:
            cur = iface_map.get(ip, "")
            is_tun = bool(cur) and is_tunnel_iface(cur)
            direct = bool(cur) and cur == phys_iface and not is_tun
            if is_tun:
                tun_n += 1
            elif direct:
                direct_n += 1
            entries.append({"ip": ip, "iface": cur, "direct": direct,
                            "tunnel": is_tun})
        rows.append({"domain": d, "ips": entries})
    return rows, tun_n, direct_n


def read_state():
    """读「我们加过的直连 IP」记录。新位置优先，同时兼容旧版本的位置。"""
    for path in (STATE_FILE, LEGACY_STATE_FILE):
        if not path:
            continue
        try:
            with open(path) as f:
                ips = [l.strip() for l in f if l.strip()]
            if ips:
                return ips
        except OSError:
            continue
    return []


def write_state(ips):
    """state 文件写 600 权限，防其他用户读取。

    返回 True/False —— 调用方必须检查返回值：早期版本忽略了它，
    而文件系统写入失败时（比如写 /var/run）会静默丢记录。
    """
    try:
        os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
        fd = os.open(STATE_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(ips) + "\n")
        return True
    except OSError:
        return False


def assemble(software, phys_iface, phys_gw, def_iface, interfaces,
             domain_rows, tun_n, direct_n, bypass_ips,
             egress_counts, tunnel_probe, main_egress,
             auto_domains=None, auto_rows=None, auto_tun=0, auto_direct=0,
             bypass_recovered=False):
    mode = "mixed" if (tun_n and direct_n) else ("tunnel" if tun_n else "direct")
    return {
        "platform": PLATFORM,
        "mode": mode,
        "mode_text": {"direct": "本机直连", "tunnel": "隧道接管", "mixed": "混合"}[mode],
        "phys_iface": phys_iface,
        "phys_gw": phys_gw,
        "default_iface": def_iface,
        "running_software": [{"name": s["name"], "cat": s["cat"]}
                             for s in software],
        "interfaces": interfaces,
        "domains": domain_rows,
        "tunnel_ip_count": tun_n,
        "direct_ip_count": direct_n,
        "bypass_active_ips": bypass_ips,
        "bypass_recovered": bool(bypass_recovered),
        # 被自动排除的隧道客户端自身服务器 IP（不由本工具托管）
        "excluded_vpn_ips": tunnel_server_ips(),
        "egress_counts": egress_counts,
        "tunnel_probe": tunnel_probe,
        "main_egress": main_egress,
        "auto_domains": auto_domains or [],
        "auto_rows": auto_rows or [],
        "auto_enabled": auto_tracker_enabled(),
        # 最近一次历史库扫描的实况（读到了哪些浏览器、为什么没读到）
        "auto_status": get_auto_status(),
        # Windows 上哪些系统读取通道可用（PowerShell 被策略禁了没、原生回退顶没顶上）
        "win_env": win_env_status(),
        # 现在是只读还是有提权能力 —— 界面据此提前挂出「只读提示」，
        # 而不是等用户点了「应用到系统」才弹密码框
        "priv": priv_status(),
        # 追踪的域名是「临时」的：多久没再看就会被移除，多久扫一次
        "auto_window": AUTO_WINDOW,
        "auto_expire": AUTO_EXPIRE,
        "auto_max": AUTO_MAX,
        "daemon_installed": IS_MAC and os.path.isfile(
            "/Library/LaunchDaemons/com.local.tunnel-manager.plist"),
        "is_root": (os.geteuid() == 0) if not IS_WIN else False,
        "domains_config": load_config(),
        "csrf_token": _csrf_token,
    }


