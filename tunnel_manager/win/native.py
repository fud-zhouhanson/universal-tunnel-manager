# -*- coding: utf-8 -*-
"""tunnel_manager.win/native — Windows 原生回退层（不依赖 PowerShell）

由 P1 从 server.py 的第 1809–3304 行**整块搬迁**而来，正文逐字未改。

【切片规则 —— 这不是漏写 import】
本项目按设计保持**单一扁平命名空间**：
  · 开发期入口 `python -m tunnel_manager.main` → 把所有切片拼进一个命名空间再执行；
  · 构建期 `bundle.py` → 同样顺序拼接成单文件 `dist/tunnel-manager.py`（纯源码，不含 exec）。
所以本文件里可以直接引用其它切片定义的函数与常量，无需 import。跨切片调用是既有事实。
本模块对外提供：FP_FILE、SNAP_FILE、cancel_switch、discover_outlets、forget_fingerprint、identify_outlet 等 15 个
本模块依赖其它切片：_base、consts、detect/iface、detect/scan、outlet/manager、outlet/routes、outlet/scene、util
"""
>>>SLICE_BODY<<<
# ======================================================================
# 四.9 Windows 原生回退层（不依赖 PowerShell）
# ======================================================================
# 背景（2026-10-11 真机报告）：有一台 Windows 11 上 powershell.exe 被管理员
#   策略拦死 —— subprocess 直接抛
#     OSError [WinError 786] 管理员用策略规则限制了对 powershell.exe 的访问
#   而 System32 里的原生命令（route / ipconfig / arp / sc / tasklist / netsh）
#   全部正常。此时若仍只认 PowerShell，程序就「不崩溃但全瞎」：
#   网卡 0 个、隧道 0 个、出口只剩「物理直连」、域名走向全未知。
#
# 所以这一层**全部只吃原生命令**，并且尽量挑不受系统语言影响的部分：
#   route print -4    接口列表 = 序号 + 点 + 名字（中英文行格式一致）；路由表是纯数字
#   arp -a            「192.168.1.5 --- 0x5」这个模式中英文完全一致
#   netsh interface   给出「序号 ↔ 友好名 ↔ IP/网关/跃点」的对应关系
#   sc query          字段名恒为英文（SERVICE_NAME / DISPLAY_NAME / STATE）
#   tasklist /fo csv  列是 CSV，镜像名恒为 ASCII
#   winreg            标准库直读注册表，比 reg query 稳
#   rasphone.pbk      系统 VPN 就是个 INI 文件，读文件即可
#
# ⚠️ 与 PowerShell 那层一样，本层**没有真机验证过**（本机是 macOS）。
#    自检脚本专门有一段把这些命令的原始输出打出来，按真机回传收紧解析。

_PS_LOCK = threading.Lock()
_PS_STATE = {"ok": None, "err": "", "at": 0.0}
_PS_TTL = 300.0              # PowerShell 可用性缓存 5 分钟

_NAT_LOCK = threading.Lock()
_NAT_CACHE = {}              # {名字: (时刻, 值)} —— 同一次扫描里别反复起进程
_NAT_TTL = 3.0


def ps_available(force=False):
    """PowerShell 能不能用 → (bool, 错误文本)。结果缓存 5 分钟。

    先探一次再决定走哪条路：否则每次调用都要白挨一次 `[WinError 786]`，
    而且 PowerShell 失败时往往还要等超时才返回。
    """
    if not IS_WIN:
        return False, "非 Windows"
    now = time.time()
    with _PS_LOCK:
        if not force and _PS_STATE["ok"] is not None \
                and now - _PS_STATE["at"] < _PS_TTL:
            return _PS_STATE["ok"], _PS_STATE["err"]
    rc, out, err = run(["powershell.exe", "-NoProfile", "-NonInteractive",
                        "-Command", "'__TM_PS_OK__'"], timeout=20)
    ok = rc == 0 and "__TM_PS_OK__" in (out or "")
    msg = "" if ok else (err or out or "无输出").strip()[:400]
    with _PS_LOCK:
        _PS_STATE.update({"ok": ok, "err": msg, "at": now})
    if not ok:
        print("[*] PowerShell 不可用，改用原生命令解析：%s" % msg)
    return ok, msg


def _nat_cached(name, loader, ttl=None):
    """原生解析的短缓存（默认 3 秒）—— 一次扫描里好几个地方都要路由表。"""
    ttl = _NAT_TTL if ttl is None else ttl
    now = time.time()
    with _NAT_LOCK:
        hit = _NAT_CACHE.get(name)
    if hit and now - hit[0] < ttl:
        return hit[1]
    val = loader()
    with _NAT_LOCK:
        _NAT_CACHE[name] = (now, val)
    return val


def _ip_int(s):
    """'192.168.1.1' → 整数；不是合法 IPv4 返回 None。"""
    if not isinstance(s, str):
        return None
    parts = s.strip().split(".")
    if len(parts) != 4:
        return None
    try:
        nums = [int(p) for p in parts]
    except ValueError:
        return None
    if any(n < 0 or n > 255 for n in nums):
        return None
    return (nums[0] << 24) | (nums[1] << 16) | (nums[2] << 8) | nums[3]


def _mask_len(mask_int):
    """255.255.255.0 → 24。"""
    n = 0
    for i in range(31, -1, -1):
        if mask_int & (1 << i):
            n += 1
        else:
            break
    return n


def _mask_from_len(n):
    """24 → 255.255.255.0；越界返回 None。"""
    if not isinstance(n, int) or n < 0 or n > 32:
        return None
    v = (0xFFFFFFFF << (32 - n)) & 0xFFFFFFFF if n else 0
    return "%d.%d.%d.%d" % ((v >> 24) & 255, (v >> 16) & 255,
                            (v >> 8) & 255, v & 255)


_RE_ROUTE_ROW = re.compile(
    r"^\s*(\d{1,3}(?:\.\d{1,3}){3})\s+"      # 目标网络
    r"(\d{1,3}(?:\.\d{1,3}){3})\s+"          # 掩码
    r"(\S+)\s+"                              # 网关（可能是「在链路上」On-link）
    r"(\d{1,3}(?:\.\d{1,3}){3})\s+"          # 接口自身 IP
    r"(\d+)\s*$")                            # 跃点


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


def _nat_registry_apps():
    """直接读注册表三个「卸载」键 —— 标准库 winreg，不需要 PowerShell。"""
    try:
        import winreg
    except ImportError:
        return []
    out, seen = [], set()
    sub = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
    roots = [(winreg.HKEY_LOCAL_MACHINE, winreg.KEY_WOW64_64KEY),
             (winreg.HKEY_LOCAL_MACHINE, winreg.KEY_WOW64_32KEY),
             (winreg.HKEY_CURRENT_USER, 0)]
    for hive, flag in roots:
        try:
            key = winreg.OpenKey(hive, sub, 0, winreg.KEY_READ | flag)
        except OSError:
            continue
        try:
            count = winreg.QueryInfoKey(key)[0]
            for i in range(count):
                try:
                    child = winreg.EnumKey(key, i)
                    with winreg.OpenKey(key, child) as sk:
                        def _gv(v):
                            try:
                                return winreg.QueryValueEx(sk, v)[0]
                            except OSError:
                                return ""
                        dn = str(_gv("DisplayName") or "")
                        if not dn or dn.lower() in seen:
                            continue
                        seen.add(dn.lower())
                        out.append({"name": dn,
                                    "loc": str(_gv("InstallLocation") or ""),
                                    "icon": str(_gv("DisplayIcon") or "")})
                except OSError:
                    continue
        finally:
            try:
                winreg.CloseKey(key)
            except OSError:
                pass
    return out


def _nat_service_list():
    """`sc query type= service state= all` —— 字段名恒为英文，不受语言影响。"""
    rc, out, _ = run(["sc.exe", "query", "type=", "service", "state=", "all"],
                     timeout=45)
    if rc != 0 or not out:
        return []
    res, cur = [], None
    for line in out.splitlines():
        s = line.strip()
        if s.startswith("SERVICE_NAME:"):
            if cur and cur.get("name"):
                res.append(cur)
            cur = {"name": s.split(":", 1)[1].strip(),
                   "display": "", "running": False}
        elif cur is not None and s.startswith("DISPLAY_NAME:"):
            cur["display"] = s.split(":", 1)[1].strip()
        elif cur is not None and s.startswith("STATE"):
            v = s.split(":", 1)[1].strip().upper()
            cur["running"] = v.startswith("4") or "RUNNING" in v
    if cur and cur.get("name"):
        res.append(cur)
    return res


def _nat_vpn_list():
    """系统 VPN = rasphone.pbk（INI 文件）。读文件，不需要 PowerShell。"""
    bases = [os.environ.get("APPDATA") or "",
             os.environ.get("PROGRAMDATA") or ""]
    out, seen = [], set()
    for base in bases:
        if not base:
            continue
        path = os.path.join(base, "Microsoft", "Network", "Connections",
                            "Pbk", "rasphone.pbk")
        try:
            with open(path, "rb") as f:
                raw = f.read()
        except OSError:
            continue
        txt = ""
        for enc in ("utf-8-sig", "gbk", "utf-16", "latin-1"):
            try:
                txt = raw.decode(enc)
                if "[" in txt:
                    break
            except (UnicodeDecodeError, LookupError):
                continue
        if not txt:
            continue
        for blk in re.split(r"^\[", txt, flags=re.M)[1:]:
            lines = blk.splitlines()
            if not lines:
                continue
            name = lines[0].strip().rstrip("]").strip()
            if not name or name in seen:
                continue
            body = "\n".join(lines[1:])
            srv = ""
            for pat in (r"^\s*PhoneNumber\s*=\s*(\S+)",
                        r"^\s*ServerAddress\s*=\s*(\S+)",
                        r"^\s*Address\s*=\s*(\S+)"):
                m = re.search(pat, body, re.M | re.I)
                if m:
                    srv = m.group(1)
                    break
            seen.add(name)
            out.append({"name": name, "server": srv, "status": ""})
    return out


def _nat_processes():
    """`tasklist /fo csv /nh` → 进程名（ASCII），比 Get-Process 更便宜。"""
    rc, out, _ = run(["tasklist", "/fo", "csv", "/nh"], timeout=40)
    if rc != 0 or not out:
        return ""
    names = []
    for line in out.splitlines():
        m = re.match(r'\s*"([^"]+)"', line)
        if m:
            names.append(m.group(1).lower())
    return " ".join(names)


def _nat_tunnel_server_ips(keywords):
    """`netstat -ano` + `tasklist` 代替 Get-NetTCPConnection。"""
    rc, out, _ = run(["netstat", "-ano"], timeout=30)
    if rc != 0 or not out:
        return set()
    pid2name = {}
    rc2, tbl, _ = run(["tasklist", "/fo", "csv", "/nh"], timeout=40)
    if rc2 == 0:
        for line in tbl.splitlines():
            m = re.match(r'\s*"([^"]+)","(\d+)"', line)
            if m:
                pid2name[m.group(2)] = m.group(1).lower()
    found = set()
    for line in out.splitlines():
        p = line.split()
        if len(p) < 5 or p[0].upper() != "TCP" or p[3].upper() != "ESTABLISHED":
            continue
        host = p[2].rsplit(":", 1)[0].strip("[]")
        if not re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host):
            continue
        if not is_public_ip(host):
            continue
        name = pid2name.get(p[4], "")
        if name and any(k in name for k in keywords):
            found.add(host)
    return found


def run_elevated_win_cmd(commands):
    """PowerShell 不可用时的提权通道：`cmd.exe /c <临时 bat>`。

    与 PowerShell 版一样靠「脚本自己写结果文件 + 末尾哨兵」回读，
    不看退出码（cmd 的 errorlevel 会被中间命令带偏）。
    bat 一律写 **GBK**（本项目的既定约定：Windows 上不能指望 chcp）。
    """
    import ctypes
    out_tmp = os.path.join(tempfile.gettempdir(),
                           "tunmgr_out_%d.txt" % os.getpid())
    try:
        os.remove(out_tmp)
    except OSError:
        pass
    lines = ["@echo off",
             'set "TM_OUT=%s"' % out_tmp,
             '>>"%TM_OUT%" echo __TM_BEGIN__']
    lines.extend(commands)
    lines.append('>>"%TM_OUT%" echo __TM_DONE__')
    bat = os.path.join(tempfile.gettempdir(), "tunmgr_%d.bat" % os.getpid())
    text = "\r\n".join(lines) + "\r\n"
    try:
        data = text.encode("gbk")
    except UnicodeEncodeError:
        data = text.encode("gbk", "replace")
    try:
        with open(bat, "wb") as f:
            f.write(data)
    except OSError as e:
        return False, "临时脚本写不进去：%s" % e, False
    params = '/c "%s"' % bat if " " not in bat else '/c ""%s""' % bat
    try:
        rc = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", "cmd.exe", params, None, 0)
    except OSError as e:
        return False, "UAC 启动失败: %s" % e, False
    if rc <= 32:
        return False, "UAC 被取消或被拒绝", True
    deadline = time.time() + 90
    content = ""
    finished = False
    while time.time() < deadline:
        time.sleep(0.4)
        try:
            with open(out_tmp, "rb") as f:
                raw = f.read()
        except OSError:
            continue
        for enc in ("utf-8", "gbk", "utf-16"):
            try:
                content = raw.decode(enc)
                break
            except UnicodeDecodeError:
                continue
        else:
            content = raw.decode("utf-8", "replace")
        if "__TM_DONE__" in content:
            finished = True
            break
    for p in (bat, out_tmp):
        try:
            os.remove(p)
        except OSError:
            pass
    if not finished:
        return False, "提权命令执行超时（90 秒）", False
    body = content.replace("__TM_BEGIN__", "").replace("__TM_DONE__", "")
    body = "\n".join(l for l in body.splitlines() if l.strip())
    ok = "__TM_FAIL__" not in body
    return ok, body.strip(), False


def win_env_status():
    """Windows 上「读取通道到底通不通」—— 让界面能解释「为什么一片空白」。

    非 Windows 返回空 dict（前端据此不显示这块）。
    """
    if not IS_WIN:
        return {}
    ok, err = ps_available()
    if ok:
        return {"powershell": True, "powershell_error": "",
                "native_fallback": False, "native_ifaces": 0,
                "note": ""}
    try:
        n = len(_nat_interfaces())
    except Exception:                    # noqa: BLE001 —— 诊断信息本身不该炸
        n = 0
    if n:
        note = "PowerShell 被系统策略禁用，已改用原生命令读取（当前读到 %d 个网卡）" % n
    else:
        note = ("PowerShell 被系统策略禁用，原生命令也没读上网卡信息 —— "
                "本机可能装了企业安全管理软件。程序仍能启动，但「网卡 / 隧道 / "
                "出口」这些依赖系统查询的功能会不全。")
    return {"powershell": False, "powershell_error": err[:300],
            "native_fallback": n > 0, "native_ifaces": n, "note": note}


def _win_registry_apps():
    """从注册表三个「卸载」键读出已安装程序（名称 / 安装位置 / 图标）。"""
    if not ps_available()[0]:
        return _nat_registry_apps()          # winreg 直读，不依赖 PowerShell
    rc, out, _ = run_ps(
        "[Console]::OutputEncoding=[Text.Encoding]::UTF8;"
        "$k=@('HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',"
        "'HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',"
        "'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*');"
        "Get-ItemProperty $k -ErrorAction SilentlyContinue | "
        "Where-Object { $_.DisplayName } | "
        "Select-Object DisplayName,InstallLocation,DisplayIcon | "
        "ConvertTo-Json -Depth 3"
    )
    if rc != 0 or not out:
        return []
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return []
    if isinstance(data, dict):
        data = [data]
    return [{"name": str(d.get("DisplayName") or ""),
             "loc": str(d.get("InstallLocation") or ""),
             "icon": str(d.get("DisplayIcon") or "")}
            for d in data if d.get("DisplayName")]


def _win_service_list():
    """Windows 服务清单（Name / DisplayName / 是否在跑）。"""
    if not ps_available()[0]:
        return _nat_service_list()           # sc query，字段名恒英文
    rc, out, _ = run_ps(
        "[Console]::OutputEncoding=[Text.Encoding]::UTF8;"
        "Get-Service | Select-Object Name,DisplayName,Status | ConvertTo-Json -Depth 3"
    )
    if rc != 0 or not out:
        return []
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return []
    if isinstance(data, dict):
        data = [data]
    res = []
    for d in data:
        try:
            running = int(d.get("Status")) == 4     # ServiceControllerStatus.Running
        except (TypeError, ValueError):
            running = False
        res.append({"name": str(d.get("Name") or ""),
                    "display": str(d.get("DisplayName") or ""),
                    "running": running})
    return res


def _win_installed_apps():
    return _win_cached("apps", 120, _win_registry_apps)


def _win_services():
    return _win_cached("svcs", 30, _win_service_list)


def _win_exe_of(app, keywords, max_scan=400):
    """在安装目录里挑一个最像「主程序」的 exe。"""
    icon = (app.get("icon") or "").strip().strip('"')
    if icon.lower().endswith(".exe") and os.path.isfile(icon):
        return icon
    loc = (app.get("loc") or "").strip().strip('"')
    if not loc or not os.path.isdir(loc):
        return ""
    try:
        names = sorted(os.listdir(loc))[:max_scan]
    except OSError:
        return ""
    first = ""
    for n in names:
        low = n.lower()
        if not low.endswith(".exe"):
            continue
        if any(k in low for k in keywords):
            return os.path.join(loc, n)
        if not first and "unins" not in low:
            first = os.path.join(loc, n)
    return first


def _find_apps_win(keywords):
    """按关键词找已安装客户端的主程序（对应 macOS 的 _find_apps）。"""
    hits = []
    for a in _win_installed_apps():
        blob = (a["name"] + " " + a["loc"]).lower()
        if not any(k in blob for k in keywords):
            continue
        exe = _win_exe_of(a, keywords)
        if exe:
            hits.append(exe)
    return hits


def _find_services_win(keywords):
    """按关键词找 Windows 服务（对应 macOS 的 _find_launchd）。

    短于 4 个字符的关键词一律不参与服务匹配 —— 否则 `wg` / `ssr` 这类
    会和系统自带服务撞名，把不相干的 SCM 条目认成隧道客户端。
    """
    kw = [k for k in keywords if len(k) >= 4]
    if not kw:
        return []
    hits = []
    for s in _win_services():
        blob = (s["name"] + " " + s["display"]).lower()
        if any(k in blob for k in kw):
            hits.append(s)
    return hits


def _win_vpn_list():
    """Windows 自带 VPN 连接（可脱离客户端 App，直接用 rasdial 启停）。"""
    if not ps_available()[0]:
        return _nat_vpn_list()               # 读 rasphone.pbk
    rc, out, _ = run_ps(
        "[Console]::OutputEncoding=[Text.Encoding]::UTF8;"
        "Get-VpnConnection -ErrorAction SilentlyContinue | "
        "Select-Object Name,ServerAddress,ConnectionStatus | ConvertTo-Json -Depth 3"
    )
    if rc != 0 or not out:
        return []
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return []
    if isinstance(data, dict):
        data = [data]
    res = []
    for d in data:
        name = str(d.get("Name") or "")
        if name:
            res.append({"name": name,
                        "server": str(d.get("ServerAddress") or ""),
                        "status": str(d.get("ConnectionStatus") or "")})
    return res


def _win_outlet_parts(entry, keywords):
    """Windows 上一个出口的「应用 / 服务 / 提示」。

    返回 (apps, services, kind, hint)；services 是服务字典列表。
    停与启用的是同一批服务 —— Windows 上没有 launchd 那种「域/标签」的区分。

    ⚠️ `OUTLET_RULES` 里给 aTrust 写死的 stop_jobs 是 **macOS 的 launchd 标签**，
    在 Windows 上根本不存在。所以这里**不读那张表**，一律以实测枚举到的
    SCM 服务为准（只有 `mode: manual` 的意思在 Windows 上依然成立）。
    """
    rule = OUTLET_RULES.get(entry["name"]) or {}
    apps = _find_apps_win(keywords)
    manual = rule.get("mode") == "manual"
    services = [] if manual else _find_services_win(keywords)
    if manual:
        hint = rule.get("reason") or "需要在它自己的界面里手动开关"
    elif services:
        hint = f"停止 Windows 服务（{len(services)} 个）"
    elif apps:
        hint = "打开它的 App，再在里面手动开启"
    else:
        hint = "需要手动操作"
    kind = "service" if services else ("app" if apps else "manual")
    return apps, services, kind, hint


def system_vpns():
    """macOS 原生 VPN 列表（scutil --nc）—— 启停不需要 root。"""
    out = []
    for line in _sh("scutil --nc list").splitlines():
        m = re.match(r'\s*(\*)?\s*\(([^)]*)\)\s+([0-9A-Fa-f-]{8,})\s+"([^"]+)"', line)
        if m:
            out.append({"name": m.group(4), "id": m.group(3),
                        "status": m.group(2), "selected": bool(m.group(1))})
    return out


def _outlet_ifaces(entry_name, ifaces, egress, owners=None):
    """该客户端当前拥有的隧道接口，以及其中在承载公网的。"""
    owned, carrying = [], []
    for i in ifaces:
        if i.get("kind") != "隧道":
            continue
        name = i["name"]
        own = ((owners or {}).get(name) or {}).get("owner") or i.get("owner") or ""
        if own != entry_name:
            continue
        owned.append(name)
        try:
            if int(egress.get(name, 0) or 0) > 0:
                carrying.append(name)
        except (TypeError, ValueError):
            pass
    return owned, carrying


def _app_name(path):
    return os.path.basename(path)[:-4] if path.endswith(".app") else os.path.basename(path)


def discover_outlets(res=None):
    """列出本机所有可用出口（含自动探测到的启停方式）。"""
    if not isinstance(res, dict) or res.get("error"):
        res = do_scan()
    running = {s["name"] for s in (res.get("running_software") or [])}
    ifaces = res.get("interfaces") or []
    egress = res.get("egress_counts") or {}
    scene_key = (res.get("scene") or {}).get("key") or ""
    owners = _iface_owners(res)
    fingerprints = load_fingerprints()

    outlets = [{
        "key": DIRECT_OUTLET, "name": "物理直连", "cat": "直连",
        "desc": "不走任何隧道，全部经物理网卡出去",
        "running": True, "in_use": scene_key == "direct", "installed": True,
        "owned": [], "carrying": [],
        "adapter": {"kind": "direct", "apps": [],
                    "stop_jobs": [], "start_plists": []},
        "can_stop": True, "can_start": True,
        "hint": "停掉所有隧道客户端",
    }]

    for entry in TUNNEL_KNOWLEDGE:
        if entry.get("cat") not in OUTLET_CATS:
            continue                       # 覆盖网络 / 虚拟网卡不是「出口」
        kws = _kb_keywords(entry)
        owned, carrying = _outlet_ifaces(entry["name"], ifaces, egress, owners)

        if IS_WIN:
            # Windows：三个可控点只剩「注册表里的应用」与「SCM 服务」。
            apps, services, kind, hint = _win_outlet_parts(entry, kws)
            daemons, agents = [], []
            stop_jobs = start_plists = [s["name"] for s in services]
            can_stop = bool(services)
            can_start = bool(services or apps)
            installed = bool(apps or services)
            bits = ([_app_name(a) for a in apps]
                    + [s["display"] or s["name"] for s in services])
        else:
            apps = _find_apps(kws)
            daemons, agents = _find_launchd(kws)
            installed = bool(apps or daemons or agents)

            rule = OUTLET_RULES.get(entry["name"]) or {}
            if rule.get("mode") == "manual":
                stop_jobs, start_plists = [], []
                kind, can_stop, can_start = "manual", False, False
                hint = rule.get("reason") or "需要在它自己的界面里手动开关"
            else:
                cand = _stoppable(daemons + agents)
                stop_jobs = rule.get("stop_jobs") or [
                    f"{j['domain']}/{j['label']}" for j in cand]
                start_plists = rule.get("start_plists") or [j["plist"] for j in cand]
                can_stop = bool(stop_jobs)
                can_start = bool(start_plists or apps)
                kind = ("launchd" if (stop_jobs or start_plists)
                        else "app" if apps else "manual")
                hint = ("bootout 守护作业" if stop_jobs
                        else "打开它的 App，再在里面手动开启" if apps else "需要手动操作")

            bits = ([_app_name(a) for a in apps]
                    + [j["label"] for j in daemons + agents])

        if not installed and not owned:
            continue                       # 本机没装也没跑 → 不进列表
        outlets.append({
            "key": entry["name"], "name": entry["name"], "cat": entry["cat"],
            "desc": " / ".join(bits[:3]) or "仅检测到接口残留",
            "confirmed": entry["name"] in fingerprints,
            "fp_routes": len((fingerprints.get(entry["name"]) or {}).get("routes") or []),
            # 区分两件事：进程在跑 ≠ 它正在当出口。
            # 只有「它的接口在承载公网」才算真的在用。
            "running": bool(entry["name"] in running),
            "in_use": bool(carrying),
            "installed": installed,
            "owned": owned, "carrying": carrying,
            "adapter": {"kind": kind, "apps": apps,
                        "stop_jobs": stop_jobs, "start_plists": start_plists},
            "can_stop": can_stop, "can_start": can_start,
            "hint": hint,
        })

    # Windows 自带 VPN：连接名是用户自己起的，没法用关键词匹配，
    # 所以在 TUNNEL_KNOWLEDGE 之外单独枚举，一个连接一个出口。
    # 这类出口的好处是**不依赖任何客户端 App** —— rasdial 就能开关。
    if IS_WIN:
        for v in _win_vpn_list():
            key = VPN_PREFIX + v["name"]
            if any(o["key"] == key for o in outlets):
                continue
            conn = (v.get("status") or "").lower() == "connected"
            outlets.append({
                "key": key, "name": v["name"] + "（系统 VPN）", "cat": "系统VPN",
                "desc": v.get("server") or "Windows 自带的 VPN 连接",
                "confirmed": key in fingerprints,
                "fp_routes": len((fingerprints.get(key) or {}).get("routes") or []),
                "running": conn, "in_use": conn,
                "installed": True, "owned": [], "carrying": [],
                "adapter": {"kind": "vpn", "apps": [],
                            "stop_jobs": [], "start_plists": [],
                            "vpn": v["name"]},
                "can_stop": conn, "can_start": not conn,
                "hint": "用 rasdial 连接 / 断开，不必打开任何客户端",
            })
    return outlets


def _outlet_by_key(key, res=None):
    for o in discover_outlets(res):
        if o["key"] == key:
            return o
    return None


def _bootstrap_target(plist):
    """launchctl bootstrap 需要「域 + plist」两个参数。"""
    if "/Library/LaunchDaemons/" in plist:
        return f"system {plist}"
    return f"gui/{os.getuid()} {plist}"


def _ps_try_lines(verb, names):
    """生成「逐个 try/catch + 末尾报成败」的 PowerShell 片段。

    末尾必须输出 `__TM_OK__` / `__TM_FAIL__` —— 调用方靠这个标记判定，
    而不是靠返回码（见 `_win_elevated` 的说明）。
    """
    lines = ["$ok=$true"]
    for n in names:
        s = str(n).replace("'", "''")
        lines.append("try { %s -Name '%s' -ErrorAction Stop } catch { $ok=$false; "
                     "Write-Output ('ERR %s: ' + $_.Exception.Message) }"
                     % (verb, s, s))
    lines.append("if ($ok) { Write-Output '__TM_OK__' } "
                 "else { Write-Output '__TM_FAIL__' }")
    return lines


def _cmd_try(cmds):
    """给 cmd 命令行补上「失败就写 __TM_FAIL__」的尾巴。

    与 `_ps_try_lines` 同一个约定：成败由脚本自己喊出来，不看退出码
    （cmd 的 errorlevel 会被中间命令带偏，跟 PowerShell 的
    `$LASTEXITCODE` 一样不可信）。
    命令里可以用 `%TM_OUT%` 引用结果文件 —— 那由 run_elevated_win_cmd 设好。
    """
    out = []
    for c in cmds:
        out.append('%s >nul 2>&1 && >>"%%TM_OUT%%" echo __TM_OK__ '
                   '|| >>"%%TM_OUT%%" echo __TM_FAIL__ "%s"'
                   % (c, _cmd_safe(c)))
    return out


def _cmd_safe(s, n=70):
    """把一段命令名塞进 echo 里的安全形式（去掉 cmd 的元字符）。"""
    return re.sub(r'[&|<>^"\r\n]', " ", str(s))[:n]


def _cmd_start_stop(verb, names):
    """sc start / sc stop 的 cmd 行（对应 PowerShell 的 Start/Stop-Service）。"""
    lines = []
    for n in names:
        s = str(n).strip()
        lines.append('sc.exe %s "%s"' % (verb, s.replace('"', "")))
    return _cmd_try(lines)


def _cmd_set_dns(alias, servers):
    """netsh 版 DNS 设置（对应 Set-DnsClientServerAddress）。"""
    a = str(alias).replace('"', "")
    cmds = []
    if servers:
        cmds.append('netsh interface ipv4 set dns name="%s" static %s primary'
                    % (a, servers[0]))
        if len(servers) > 1:
            cmds.append('netsh interface ipv4 add dns name="%s" %s index=2'
                        % (a, servers[1]))
    else:
        cmds.append('netsh interface ipv4 set dns name="%s" source=dhcp' % a)
    return _cmd_try(cmds)


def _cmd_remove_routes(dests):
    """route delete 的 cmd 行（对应 Remove-NetRoute）。

    `route delete` 不吃 CIDR，得拆成「网络 + mask」，所以这里先转换；
    转不了的（比如 macOS netstat 那种「192.168.1」裸网络）就原样交给 route。
    """
    cmds = []
    for d in dests:
        s = str(d).strip()
        if "/" in s:
            net, _, plen = s.partition("/")
            mask = _mask_from_len(int(plen)) if plen.isdigit() else None
            if mask:
                cmds.append("route.exe delete %s mask %s" % (net, mask))
                continue
        cmds.append("route.exe delete %s" % s)
    return _cmd_try(cmds)


def _win_elevated(ps_lines, native_cmds=None):
    """跑一段提权操作。返回 (ok, 文本, 是否被取消了授权)。

    ⚠️ 为什么不能看返回码：`run_elevated_win` **从不返回 403**（403 是 sudo 的约定），
    它用 `rc=-1` 表示「UAC 被取消 / 执行超时」，而其余返回码的语义并不可靠
    （PowerShell 的 cmdlet 根本不设置 `$LASTEXITCODE`）。
    所以这里改用「脚本自己喊一句 `__TM_OK__`」的约定来判定成败。
    另外把整段包进 `& { … }`，这样 `*>&1 | Out-File` 才能把**每一行**输出都收进文件
    （否则只有最后一条语句的输出会被重定向，出错信息会丢）。

    PowerShell 被策略拦死时（真机实测有这种机器），改走 `cmd + 原生命令`。
    ⚠️ 刻意**不做「PS 失败后再补一次原生」的兜底** —— 那会让用户连着吃两个 UAC 弹窗。
    走哪条路只看 `ps_available()` 的探测结论。
    """
    if not ps_available()[0]:
        if native_cmds is None:
            return False, "PowerShell 被策略禁止，且该操作没有 cmd 等价写法", False
        return run_elevated_win_cmd(native_cmds)
    script = "& {\n" + "\n".join(ps_lines) + "\n}\n"
    rc, out, err = run_root(script, None)
    body = (out or "").strip()
    if rc == -1 and err:
        return False, err, True
    if "__TM_OK__" in body:
        return True, body.replace("__TM_OK__", "").strip(), False
    return False, (body.replace("__TM_FAIL__", "").strip()
                   or err or "执行失败"), False


def outlet_stop(key, pw=None, res=None):
    """停掉一个出口。返回 (ok, message)；message 为 NEED_SUDO 表示缺密码。"""
    o = _outlet_by_key(key, res)
    if not o:
        return False, f"未知出口：{key}"
    ad = o["adapter"]
    kind = ad.get("kind")
    if kind == "direct":
        return False, "「物理直连」不是一个可停止的客户端"

    if IS_WIN:
        if kind == "vpn":
            rc, out, err = run(["rasdial", ad.get("vpn") or "", "/disconnect"],
                               timeout=60)
            if rc != 0:
                return False, ("断开「%s」失败（rc=%s）：%s"
                               % (ad.get("vpn"), rc,
                                  (err or out or "").strip()[:160]))
            return True, "已断开系统 VPN「%s」" % ad.get("vpn")
        names = ad.get("stop_jobs") or []
        if not names:
            return False, ("%s 没有可自动停止的服务（%s）"
                           % (o["name"], o.get("hint") or "需要手动操作"))
        ok, text, cancelled = _win_elevated(
            _ps_try_lines("Stop-Service -Force", names),
            _cmd_start_stop("stop", names))
        if cancelled:
            return False, "NEED_ADMIN"
        if not ok:
            return False, ("停止「%s」未成功：%s"
                           % (o["name"], text[:200] or "未知原因"))
        return True, "已停止 %s（%d 个服务）" % (o["name"], len(names))

    jobs = ad.get("stop_jobs") or []
    if not jobs:
        return False, (f"{o['name']} 没有可自动关闭的守护作业"
                       f"（{o.get('hint') or '需要手动操作'}）")
    cmd = " ; ".join(f"launchctl bootout {j} 2>/dev/null || true" for j in jobs)
    rc, _o, _e = run_root(cmd, pw)
    if rc == 403:
        return False, "NEED_SUDO"
    # ⚠️ 这里过去只看「是不是 403」就报成功 —— 其它非零返回码（命令跑不动、
    #    作业名写错）会被说成「已停止」，用户以为关掉了其实没关。现在如实判定。
    if rc != 0:
        return False, (f"停止「{o['name']}」未成功（rc={rc}）："
                       f"{(_e or _o or '')[:160]}")
    return True, f"已停止 {o['name']}（bootout {len(jobs)} 个作业）"


def outlet_start(key, pw=None, res=None):
    """启动一个出口。"""
    o = _outlet_by_key(key, res)
    if not o:
        return False, f"未知出口：{key}"
    ad = o["adapter"]
    kind = ad.get("kind")
    if kind == "direct":
        return True, "物理直连无需启动"

    if IS_WIN:
        if kind == "vpn":
            rc, out, err = run(["rasdial", ad.get("vpn") or ""], timeout=90)
            if rc != 0:
                return False, ("连接「%s」失败（rc=%s）：%s"
                               % (ad.get("vpn"), rc,
                                  (err or out or "").strip()[:160]))
            return True, "已连接系统 VPN「%s」" % ad.get("vpn")

        msgs = []
        names = ad.get("start_plists") or []
        if names:
            ok, text, cancelled = _win_elevated(
                _ps_try_lines("Start-Service", names),
                _cmd_start_stop("start", names))
            if cancelled:
                return False, "NEED_ADMIN"
            if not ok:
                return False, ("启动「%s」的服务未成功：%s"
                               % (o["name"], text[:200] or "未知原因"))
            msgs.append("已启动 %d 个服务" % len(names))
        for app in ad.get("apps") or []:
            opener = getattr(os, "startfile", None)
            if opener is None:
                msgs.append("无法自动打开 %s" % _app_name(app))
                continue
            try:
                opener(app)
                msgs.append("已打开 " + _app_name(app))
            except OSError as e:
                msgs.append("打开 %s 失败：%s" % (_app_name(app), e))
        if not msgs:
            return False, f"{o['name']} 需要你在它的界面里手动开启"
        return True, "；".join(msgs)

    msgs = []
    plists = ad.get("start_plists") or []
    if plists:
        cmd = " ; ".join(f"launchctl bootstrap {_bootstrap_target(p)} 2>/dev/null || true"
                         for p in plists)
        rc, _o, _e = run_root(cmd, pw)
        if rc == 403:
            return False, "NEED_SUDO"
        msgs.append(f"已恢复 {len(plists)} 个守护作业")
    for app in ad.get("apps") or []:
        _sh(f'open -a "{app}"')
    if ad.get("apps"):
        msgs.append("已打开 " + "、".join(_app_name(a) for a in ad["apps"]))
    if not msgs:
        return False, f"{o['name']} 需要你在它的界面里手动开启"
    return True, "；".join(msgs)


def switch_outlet(key, pw=None, res=None):
    """切到某个出口 = 停掉其它在跑的出口 + 启动目标 + 清残留路由。"""
    if not isinstance(res, dict) or res.get("error"):
        res = do_scan()
    outlets = discover_outlets(res)
    target = next((o for o in outlets if o["key"] == key), None)
    if not target:
        return {"ok": False, "target": key, "done": [], "manual": [],
                "message": f"未知出口：{key}"}

    done, manual, need_sudo = [], [], False

    # 缺权限时提示语分平台：Windows 是 UAC 弹窗，没有密码可输。
    priv_hint = "UAC 授权" if IS_WIN else "管理员密码"

    for o in outlets:
        if o["key"] == key or not o.get("in_use"):
            continue
        ok, msg = outlet_stop(o["key"], pw, res)
        if msg in PRIV_MSGS:
            need_sudo = True
            done.append({"name": o["name"], "action": "stop", "ok": False,
                         "detail": f"需要{priv_hint}"})
            continue
        done.append({"name": o["name"], "action": "stop", "ok": ok, "detail": msg})
        if not ok:
            manual.append(f"手动关闭「{o['name']}」：{msg}")

    if not need_sudo and target["key"] != DIRECT_OUTLET:
        ok, msg = outlet_start(key, pw, res)
        if msg in PRIV_MSGS:
            need_sudo = True
        done.append({"name": target["name"], "action": "start", "ok": ok,
                     "detail": msg})
        if not ok:
            manual.append(f"手动开启「{target['name']}」：{msg}")

    if not need_sudo:
        n, cmsg = clean_residual_routes(pw)
        if cmsg in PRIV_MSGS:
            need_sudo = True
        elif n:
            done.append({"name": "残留路由", "action": "clean", "ok": True,
                         "detail": cmsg})

    if target["key"] == DIRECT_OUTLET:
        manual.append("若仍有加速器在自行接管流量，请在它的界面里关掉加速")

    if need_sudo:
        msg = f"需要{priv_hint}才能完成自动步骤"
    elif manual:
        msg = "自动步骤已完成，请继续完成下面的手动步骤"
    else:
        msg = "切换完成"
    if not need_sudo:
        remember_outlet(key)
    return {"ok": not need_sudo, "target": key, "target_name": target["name"],
            "done": done, "manual": manual, "message": msg}


def cancel_switch(pw=None):
    """取消上一次「切到这里」。

    「已切换（待确认）」是**我们记的一笔账**，不是系统事实 —— 所以它是可以反悔的。
    取消做两件事：

      1) 若上次切到的是「本机直连」，那笔账伴随的是**真的加了 /32 直连路由**，
         所以要把它们交还隧道（`do_undo`，只删本程序加过的主机路由，不误伤别人）。
      2) 抹掉这笔记录 → 界面那一行从黄色「待确认」回到中性状态。

    切到**隧道客户端**的情况不回滚启停：用户很可能正靠它上网，
    自动把它停掉会直接断网。只清记录，并提示怎么彻底退出。
    """
    key = remembered_outlet()
    done, manual = [], []

    if key is None:
        forget_active_outlet()
        return {"ok": True, "cancelled": None, "done": [], "manual": [],
                "message": "没有待取消的切换记录"}

    ok = True
    if key == DIRECT_OUTLET:
        u_ok, umsg = do_undo(pw)
        if umsg == "NEED_SUDO":
            return {"ok": False, "cancelled": key, "done": [], "manual": [],
                    "message": "NEED_SUDO"}
        done.append({"name": "直连路由交还隧道", "action": "undo",
                     "ok": bool(u_ok), "detail": umsg})
        if not u_ok:
            ok = False

    forget_active_outlet()

    if key == DIRECT_OUTLET:
        msg = ("已取消：「本机直连」的记录已抹掉，直连路由已交还隧道" if ok
               else "记录已抹掉，但直连路由没能全部交还")
    else:
        msg = f"已取消「{key}」的切换记录（客户端启停未回滚）"
        manual.append(f"如需彻底退出「{key}」，请用它自己的界面关掉，或点该行的「停止」")
    return {"ok": ok, "cancelled": key, "done": done, "manual": manual,
            "message": msg}


# ----------------------------------------------------------------------
# 出口指纹：把「某个客户端独有哪几条路由 / 哪个接口」记下来
# ----------------------------------------------------------------------
#
# 为什么需要：TUN 接口认不出厂商（见 _iface_owners）。而**唯一可靠**的通用办法是
# 「停掉它，看哪些路由跟着消失」—— 我们把这个结果存成"指纹"，
# 之后就能一眼认出同样的接口是谁的，不用每次都重启客户端。
#
# 注：另一条路「拔掉某条路由看谁补回来」只对**有守护进程**的客户端有效
# （aTrust 有 aTrustTunnelWatchDog），实测**雷神不补路由**，所以不能作为通用方案。
FP_FILE = os.path.join(CONFIG_DIR, "outlet_fingerprints.json")


def load_fingerprints():
    try:
        with open(FP_FILE, encoding="utf-8") as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def save_fingerprint(key, ifaces, routes, note=""):
    fps = load_fingerprints()
    fps[key] = {"ifaces": sorted(set(ifaces)), "routes": sorted(set(routes)),
                "at": time.time(), "note": note}
    try:
        os.makedirs(CONFIG_DIR, exist_ok=True)
        with open(FP_FILE, "w", encoding="utf-8") as f:
            json.dump(fps, f, ensure_ascii=False, indent=2)
        return True, "ok"
    except OSError as e:
        return False, str(e)


def forget_fingerprint(key):
    """忘掉某个出口的归属记忆（确认错了、或换了客户端时用）。"""
    fps = load_fingerprints()
    if key not in fps:
        return False, f"{key} 没有已记录的归属记忆"
    fps.pop(key, None)
    try:
        with open(FP_FILE, "w", encoding="utf-8") as f:
            json.dump(fps, f, ensure_ascii=False, indent=2)
    except OSError as e:
        return False, str(e)
    return True, f"已忘掉「{key}」的归属记忆"


def _routes_snapshot():
    """当前 IPv4 路由集合：{(dest, iface)}。"""
    if IS_WIN:
        if not ps_available()[0]:
            return _nat_routes_snapshot()
        # Windows 用 Get-NetRoute，能和 macOS 一样拿到「接口别名」而不是 IP
        # （route print 的 Interface 列给的是 IP，还得再翻译一次）。
        rc, out, _ = run_ps(
            "[Console]::OutputEncoding=[Text.Encoding]::UTF8;"
            "Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue | "
            "Select-Object DestinationPrefix,InterfaceAlias | "
            "ConvertTo-Json -Depth 3"
        )
        if rc != 0 or not out:
            return set()
        try:
            data = json.loads(out)
        except json.JSONDecodeError:
            return set()
        if isinstance(data, dict):
            data = [data]
        res = set()
        for d in data:
            dest = str(d.get("DestinationPrefix") or "")
            if not dest:
                continue
            if dest == "0.0.0.0/0":
                dest = "default"          # 与 macOS 的写法对齐，好让上层统一过滤
            res.add((dest, str(d.get("InterfaceAlias") or "")))
        return res
    out = set()
    for line in _sh("netstat -rn -f inet").splitlines():
        p = line.split()
        if len(p) >= 4 and p[0] not in ("Destination", "Internet:"):
            out.add((p[0], p[3]))
    return out


SNAP_FILE = os.path.join(CONFIG_DIR, "identify_snap.json")


def _identify_twostep(key, name):
    """两段式归属确认 —— 给「不能自动停止」的客户端用（雷神 / 网易UU 这类）。

    第一次点：记下「关掉它之前」的路由/接口快照，并提示你去手动关；
    第二次点：对比，得出它独有的路由，存成指纹。
    """
    cur_r, cur_i = _routes_snapshot(), active_ifaces()

    try:
        with open(SNAP_FILE, encoding="utf-8") as f:
            pend = json.load(f)
    except (OSError, ValueError):
        pend = None

    if not isinstance(pend, dict) or pend.get("key") != key:
        try:
            os.makedirs(CONFIG_DIR, exist_ok=True)
            with open(SNAP_FILE, "w", encoding="utf-8") as f:
                json.dump({"key": key,
                           "routes": sorted(f"{d}|{i}" for d, i in cur_r),
                           "ifaces": sorted(cur_i), "at": time.time()},
                          f, ensure_ascii=False)
        except OSError as e:
            return {"ok": False, "message": f"快照写入失败：{e}"}
        return {"ok": True, "phase": "before", "key": key, "name": name,
                "message": f"已记下「关掉 {name} 之前」的状态。"
                           f"请现在手动把它关掉，然后回来再点一次「确认归属」。"}

    before_r = set()
    for r in pend.get("routes") or []:
        if "|" in r:
            d, i = r.split("|", 1)
            before_r.add((d, i))
    before_i = set(pend.get("ifaces") or [])
    gone_r = sorted(d for (d, _i) in (before_r - cur_r) if d != "default")
    gone_i = sorted(before_i - cur_i)
    try:
        os.remove(SNAP_FILE)
    except OSError:
        pass

    saved = False
    if gone_r or gone_i:
        saved, _ = save_fingerprint(key, gone_i, gone_r, note="由「手动关掉→对比」得出")

    parts = []
    if gone_i:
        parts.append("接口 " + "、".join(gone_i))
    if gone_r:
        parts.append(f"{len(gone_r)} 条路由")
    detail = "；".join(parts) if parts else "没有发现任何路由/接口随它消失（它可能本来就没在跑）"
    return {"ok": True, "phase": "after", "key": key, "name": name,
            "owned_ifaces": gone_i, "owned_routes": gone_r, "saved": saved,
            "message": f"{name} 的归属已确认：{detail}"
                       + ("（已存为指纹）" if saved else "")}


def identify_outlet(key, pw=None, wait=6):
    """确认某个出口的路由归属：停它 → 看哪些路由/接口跟着消失 → 立刻恢复。

    这是唯一**通用可靠**的归属确认法。代价是需要短暂停掉该客户端
    （aTrust 恢复后可能还要重新登录）。
    """
    res = do_scan()
    o = next((x for x in discover_outlets(res) if x["key"] == key), None)
    if not o:
        return {"ok": False, "message": f"未知出口：{key}"}
    if not o["can_stop"]:
        return _identify_twostep(key, o["name"])

    before_r, before_i = _routes_snapshot(), active_ifaces()

    ok, msg = outlet_stop(key, pw, res)
    if not ok:
        return {"ok": False, "message": msg}

    time.sleep(max(2, int(wait)))

    # ⚠️ 这里以前写的是 `_ifaces_snapshot()` —— 那个名字**从来没定义过**，
    #    所以凡是「能自动停止」的出口（aTrust 这类）一点「确认归属」就 NameError。
    #    它和上面 `before_i` 取的是同一个东西，直接用 active_ifaces()。
    mid_r, mid_i = _routes_snapshot(), active_ifaces()

    # 无论成败都要恢复
    ok2, msg2 = outlet_start(key, pw, res)

    gone_routes = sorted(d for (d, _i) in (before_r - mid_r) if d != "default")
    gone_ifaces = sorted(before_i - mid_i)

    saved = False
    if gone_routes or gone_ifaces:
        saved, _ = save_fingerprint(key, gone_ifaces, gone_routes,
                                    note="由「停掉→对比」实测得出")

    parts = []
    if gone_ifaces:
        parts.append("接口 " + "、".join(gone_ifaces))
    if gone_routes:
        parts.append(f"{len(gone_routes)} 条路由")
    detail = ("；".join(parts) if parts else "没有发现任何路由/接口随它消失")

    return {
        "ok": True, "key": key, "name": o["name"],
        "owned_ifaces": gone_ifaces, "owned_routes": gone_routes,
        "saved": saved, "restored": bool(ok2), "restore_detail": msg2,
        "message": f"{o['name']} 的归属已确认：{detail}"
                   + ("（已存为指纹）" if saved else ""),
    }


