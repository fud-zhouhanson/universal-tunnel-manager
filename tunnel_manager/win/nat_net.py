# -*- coding: utf-8 -*-
"""tunnel_manager.win/nat_net — Windows 原生读取 · 路由与网卡

由 P2 从 win/native.py 的第 114–391 行**原样拆出**，正文逐字未改（与 P1 一样，只搬不改）。

【切片规则 —— 这不是漏写 import】
本项目按设计保持**单一扁平命名空间**：
  · 开发期入口 `python -m tunnel_manager.main` → 把所有切片拼进一个命名空间再执行；
  · 构建期 `bundle.py` → 同样顺序拼接成单文件 `dist/tunnel-manager.py`（纯源码，不含 exec）。
所以本文件里可以直接引用其它切片定义的函数与常量，无需 import。跨切片调用是既有事实。
本模块对外提供：（无公开符号）
本模块依赖其它切片：detect/iface、util、win/probe
"""
>>>SLICE_BODY<<<
def _nat_route_print():
    """解析 `route print -4` → {"ifaces": {序号: {...}}, "routes": [...]}。

    只认结构不认词：接口列表行是「序号 + 点 + [MAC + 点] + 名字」，
    路由表行是 5 列地址/数字。这两处在中英文 Windows 上完全一样。
    """
    def _load():
        rc, out, _ = run(["route", "print", "-4"], timeout=25)
        if rc != 0 or not out:
            rc, out, _ = run(["route", "print"], timeout=25)
        if rc != 0 or not out:
            return {"ifaces": {}, "routes": []}
        ifaces, routes = {}, []
        for line in out.splitlines():
            m = _RE_ROUTE_ROW.match(line)
            if m:
                dest, mask, gw, ip, metric = m.groups()
                routes.append({"dest": dest, "mask": mask, "gw": gw,
                               "ip": ip, "metric": int(metric)})
                continue
            m = re.match(r"^\s*(\d{1,4})\.{3,}(.*)$", line)
            if not m:
                continue
            idx, rest = int(m.group(1)), m.group(2).strip()
            m2 = re.match(r"^(?:[0-9a-fA-F]{2}(?:\s+[0-9a-fA-F]{2})+)[\s.]*(.*)$",
                          rest)
            name = (m2.group(1) if m2 else rest.lstrip(".")).strip()
            # 名字里必须有字母/汉字，免得把别的东西误认成接口
            if name and re.search(r"[A-Za-z\u4e00-\u9fff]", name):
                ifaces.setdefault(idx, {"index": idx, "name": name})
        return {"ifaces": ifaces, "routes": routes}
    return _nat_cached("route_print", _load)


def _nat_arp_map():
    """`arp -a` 里「接口: 192.168.1.5 --- 0x5」→ {接口 IP: 接口序号}。

    标题行会随系统语言变（接口/Interface），但这行本身中英文一致。
    """
    def _load():
        rc, out, _ = run(["arp", "-a"], timeout=20)
        m = {}
        if rc != 0 or not out:
            return m
        for line in out.splitlines():
            r = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})\s*-{2,}\s*0x([0-9a-fA-F]+)",
                          line)
            if r:
                m[r.group(1)] = int(r.group(2), 16)
        return m
    return _nat_cached("arp", _load)


def _nat_netsh_ifaces():
    """`netsh interface ipv4 show interfaces` → {序号: {name,up,mtu,metric}}。

    表头是本地化的，但列本身固定是「序号 跃点 MTU 状态 名称」，
    所以按位置切即可（名称可能含空格，split(None, 4) 一次切完）。
    """
    def _load():
        rc, out, _ = run(["netsh", "interface", "ipv4", "show", "interfaces"],
                         timeout=25)
        res = {}
        if rc != 0 or not out:
            return res
        for line in out.splitlines():
            p = line.split(None, 4)
            if len(p) < 5 or not p[0].isdigit():
                continue
            try:
                idx, metric, mtu = int(p[0]), int(p[1]), int(p[2])
            except ValueError:
                continue
            state = p[3].strip()
            low = state.lower()
            if "断开" in state or "disconnect" in low:
                up = False           # 明确断开
            elif "连接" in state or "connect" in low:
                up = True
            else:
                up = None            # 认不出来 → 交给别的证据（见 _nat_iface_table）
            res[idx] = {"index": idx, "name": p[4].strip(), "mtu": mtu,
                        "metric": metric, "up": up}
        return res
    return _nat_cached("netsh_if", _load)


def _nat_netsh_addrs():
    """`netsh interface ipv4 show addresses` → {友好名: {ip, gw, metric}}。

    标签是本地化的，所以按「关键词 + 值长什么样」判，而不是按列位置。
    """
    def _load():
        rc, out, _ = run(["netsh", "interface", "ipv4", "show", "addresses"],
                         timeout=25)
        res = {}
        if rc != 0 or not out:
            return res
        cur = None
        for line in out.splitlines():
            s = line.strip()
            m = re.search(r'"([^"]+)"\s*$', s)
            if m and ("接口" in s or "interface" in s.lower()):
                cur = m.group(1)
                res.setdefault(cur, {"ip": "", "gw": "", "metric": None})
                continue
            if cur is None:
                continue
            ips = re.findall(r"\d{1,3}(?:\.\d{1,3}){3}", s)
            if not ips:
                continue
            low = s.lower()
            if "网关" in s or "gateway" in low:
                if not res[cur]["gw"] and "跃点" not in s and "metric" not in low:
                    res[cur]["gw"] = ips[0]
            elif "掩码" in s or "mask" in low or "前缀" in s or "prefix" in low:
                continue                      # 子网前缀那一行不能当 IP
            else:
                res[cur]["ip"] = res[cur]["ip"] or ips[0]
        return res
    return _nat_cached("netsh_addr", _load)


def _nat_iface_table():
    """把几个源头合成 {序号: {index,name,desc,ip,gw,up,mtu,metric,src}}。"""
    def _load():
        rp = _nat_route_print()
        rp_ifaces = rp.get("ifaces") or {}
        ns_if = _nat_netsh_ifaces()
        ns_addr = _nat_netsh_addrs()
        ip2idx = _nat_arp_map()
        live_ips = {r["ip"] for r in (rp.get("routes") or [])}

        table = {}
        for idx, nm in ns_if.items():
            table[idx] = {"index": idx, "name": nm["name"], "desc": "",
                          "ip": "", "gw": "", "up": nm.get("up"),
                          "mtu": nm.get("mtu") or 0, "metric": nm.get("metric")}
        for idx, info in rp_ifaces.items():
            t = table.setdefault(idx, {"index": idx, "name": info["name"],
                                       "desc": "", "ip": "", "gw": "",
                                       "up": None, "mtu": 0, "metric": None})
            t["desc"] = info["name"]
            if not t["name"]:
                t["name"] = info["name"]

        # 友好名 → IP / 网关
        for name, a in ns_addr.items():
            for t in table.values():
                if t["name"] == name:
                    t["ip"] = t["ip"] or (a.get("ip") or "")
                    t["gw"] = t["gw"] or (a.get("gw") or "")
                    break
        # 接口 IP → 序号（arp 这条链最靠得住）
        for ip, idx in ip2idx.items():
            t = table.get(idx)
            if t is not None and not t["ip"]:
                t["ip"] = ip
        # 兜底：路由表里出现过、却没有任何接口认领的 IP。
        # ⚠️ 只在「一个待认领 IP + 一个缺 IP 的接口」这种确定情形下才敢挂，
        #    否则宁可不填 —— 挂错 IP 比没有 IP 更坏（会指鹿为马）。
        claimed = {t["ip"] for t in table.values() if t["ip"]}
        orphan_ip = [ip for ip in live_ips if ip not in claimed]
        no_ip = [t for t in table.values() if not t["ip"]]
        if len(orphan_ip) == 1 and len(no_ip) == 1:
            no_ip[0]["ip"] = orphan_ip[0]
        for t in table.values():
            if t["up"] is None:
                t["up"] = bool(t["ip"]) and t["ip"] in live_ips
        return table
    return _nat_cached("iface_table", _load, ttl=3.0)


def _nat_alias_by_ip(ip):
    for t in _nat_iface_table().values():
        if t.get("ip") == ip:
            return t.get("name") or t.get("desc") or ""
    return ""


def _nat_interfaces():
    """→ 与 scan_interfaces_win() 同形的接口列表。"""
    out = []
    for idx in sorted(_nat_iface_table()):
        t = _nat_iface_table()[idx]
        name = t["name"] or t["desc"]
        if not name:
            continue
        desc = t["desc"] or name
        blob = (name + " " + desc).lower()
        wireless = any(k in blob for k in ("wi-fi", "wifi", "wireless", "wlan",
                                           "802.11", "无线", "WLAN".lower()))
        if is_loopback_iface(name, desc):
            itype = 0
        elif wireless:
            itype = 71
        else:
            itype = 6 if t["ip"] else 0
        out.append({"name": name, "desc": desc, "type": itype,
                    "status": "active" if t["up"] else "inactive",
                    "ipv4": t["ip"] or "", "ipv6_ula": "",
                    "mtu": t["mtu"] or 0})
    return out


def _nat_snapshot():
    """→ 与 win_snapshot() 同形（只留默认路由，与 PowerShell 版口径一致）。

    跃点用的是「路由跃点 + 接口跃点」的有效值 —— Windows 真正据以选路的是它。
    """
    def _load():
        tbl = _nat_route_print()
        table = _nat_iface_table()
        by_ip = {t["ip"]: t for t in table.values() if t.get("ip")}
        routes = []
        for r in tbl.get("routes") or []:
            if not (r["dest"] == "0.0.0.0" and r["mask"] == "0.0.0.0"):
                continue
            t = by_ip.get(r["ip"]) or {}
            eff = r["metric"] + (t.get("metric") or 0)
            routes.append({"InterfaceAlias": _nat_alias_by_ip(r["ip"]) or r["ip"],
                           "NextHop": r["gw"], "InterfaceMetric": eff,
                           "DestinationPrefix": "0.0.0.0/0"})
        if not routes:
            return {}
        routes.sort(key=lambda x: x.get("InterfaceMetric") or 9999)
        return {"routes": routes}
    return _nat_cached("snap", _load, ttl=2.0)


def _nat_iface_of_batch(ips):
    """自家长前缀匹配：某个目标 IP 按当前路由表会从哪个接口出去。

    路由表本身是纯数字，所以这一步没有任何本地化风险 —— 比 PowerShell 那版
    还稳（那边要靠 Find-NetRoute 的 cmdlet）。
    """
    out = {}
    if not ips:
        return out
    rules = []
    for r in (_nat_route_print().get("routes") or []):
        net, mask = _ip_int(r["dest"]), _ip_int(r["mask"])
        if net is None or mask is None:
            continue
        rules.append((mask, r.get("metric") or 0, net & mask, r["ip"]))
    # 掩码长的优先；同为 /0 这种打平时按跃点数小的赢 ——
    # Windows 真正据以选路的就是「掩码最长 → 跃点最小」，少这一步会在
    # 隧道和物理口都挂着默认路由时挑错出口。
    rules.sort(key=lambda x: (-x[0], x[1]))
    for ip in ips:
        v = _ip_int(ip)
        if v is None:
            out[ip] = ""
            continue
        hit = ""
        for mask, _metric, net, iface_ip in rules:
            if v & mask == net:
                hit = _nat_alias_by_ip(iface_ip) or iface_ip
                break
        out[ip] = hit
    return out


def _nat_routes_snapshot():
    """→ {(前缀, 接口名)}，与 macOS 版口径对齐（默认路由写成 "default"）。"""
    def _load():
        out = set()
        for r in (_nat_route_print().get("routes") or []):
            mask = _ip_int(r["mask"])
            if mask is None:
                continue
            plen = _mask_len(mask)
            dest = "default" if plen == 0 else "%s/%d" % (r["dest"], plen)
            out.add((dest, _nat_alias_by_ip(r["ip"]) or r["ip"]))
        return out
    return _nat_cached("routes_snap", _load, ttl=2.0)


