# -*- coding: utf-8 -*-
"""tunnel_manager.outlet/apply — 应用 / 撤销 / daemon 入口

由 P2 从 outlet/routes.py 的第 219–393 行**原样拆出**，正文逐字未改（与 P1 一样，只搬不改）。

【切片规则 —— 这不是漏写 import】
本项目按设计保持**单一扁平命名空间**：
  · 开发期入口 `python -m tunnel_manager.main` → 把所有切片拼进一个命名空间再执行；
  · 构建期 `bundle.py` → 同样顺序拼接成单文件 `dist/tunnel-manager.py`（纯源码，不含 exec）。
所以本文件里可以直接引用其它切片定义的函数与常量，无需 import。跨切片调用是既有事实。
本模块对外提供：CORE_CANDIDATES、do_apply、do_daemon、do_undo、find_core
本模块依赖其它切片：_base、autotrack、config、consts、detect/iface、detect/route、detect/scan、outlet/routes、util
"""
>>>SLICE_BODY<<<
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
    # 前置探测：没权限就别再往下走（这台机器上解析域名要好几秒，
    # 让用户干等之后才弹密码框，体感上就是「卡住了」）。
    can, code, _t = priv_capability(pw)
    if not can:
        return None, code
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
    can, code, _t = priv_capability(pw)
    if not can:
        return None, code
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
    # 前置探测的意义在这里最实：daemon-install 是一支**多步**脚本
    # （拷 plist → chown → launchctl load），做到一半失败会留下半个守护作业。
    can, code, _t = priv_capability(pw)
    if not can:
        return None, code
    rc, out, err = run_root(cmd, pw)
    if rc == 403:
        return None, "NEED_SUDO"
    return rc == 0, out or err


