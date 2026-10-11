# -*- coding: utf-8 -*-
"""tunnel_manager.health/flow — 真实流量体检 + 一键应急恢复

由 P1 从 server.py 的第 3305–4147 行**整块搬迁**而来，正文逐字未改。

【切片规则 —— 这不是漏写 import】
本项目按设计保持**单一扁平命名空间**：
  · 开发期入口 `python -m tunnel_manager.main` → 把所有切片拼进一个命名空间再执行；
  · 构建期 `bundle.py` → 同样顺序拼接成单文件 `dist/tunnel-manager.py`（纯源码，不含 exec）。
所以本文件里可以直接引用其它切片定义的函数与常量，无需 import。跨切片调用是既有事实。
本模块对外提供：FAKE_IP_RE、HEALTH_FILE、RESCUE_LOG、TRUTH_DOMAINS、TRUTH_TARGETS、dhcp_dns 等 24 个
本模块依赖其它切片：_base、detect/iface、detect/route、outlet/scene、util、win/native
"""
>>>SLICE_BODY<<<
# ======================================================================
# 七·五、真实流量体检（"流量到底去哪了"）+ 一键应急恢复
# ======================================================================
#
# 为什么不能只读配置：路由表和 DNS 都是「声明」，不是「事实」。
# DNS 与隧道被倒腾乱之后，最典型的三类故障，光看配置全都"正常"：
#   1) 声明走物理、实际被拽进隧道，或干脆被黑洞 —— 配置看不出任何问题
#   2) DNS 被隧道改写，把域名解析进假 IP 池（198.18.x.x 之类）——
#      表现就是"显示在加速但没效果"
#   3) DNS 服务器早已失效 / 指向不存在的地址
# 所以这里一律用「观测」：真解析一次、真连一次、真看第一跳。

TRUTH_TARGETS = [
    ("腾讯", "119.29.29.29"),
    ("阿里 DNS", "223.5.5.5"),
    ("百度", "110.242.68.66"),
    ("Cloudflare", "1.1.1.1"),
    ("GitHub", "140.82.112.3"),
]

TRUTH_DOMAINS = ["www.baidu.com", "www.qq.com", "github.com"]

# 假 IP 池 / 保留段：正常的公网域名不该解析到这里
FAKE_IP_RE = re.compile(
    r"^(0\.0\.0\.0|127\.|169\.254\.|198\.1[89]\.|100\.6[4-9]\.|100\.[7-9]\d\.|"
    r"100\.1[0-2]\d\.|240\.0\.0\.|255\.255\.255\.255)$")

HEALTH_FILE = os.path.join(CONFIG_DIR, "health.json")
RESCUE_LOG = os.path.join(CONFIG_DIR, "rescue.log")


def local_addr_map(interfaces=None):
    """IPv4 → 接口名。用来把内核选中的源地址翻译成「实际从哪出去」。"""
    m = {}
    if interfaces:
        for i in interfaces:
            if i.get("ipv4"):
                m[i["ipv4"]] = i["name"]
        if m:
            return m
    if IS_WIN:
        for i in scan_interfaces_win():
            if i.get("ipv4"):
                m[i["ipv4"]] = i["name"]
        return m
    cur = ""
    for line in _sh("ifconfig").splitlines():
        if line and not line[0].isspace():
            cur = line.split(":")[0].strip()
        else:
            mm = re.search(r"\binet\s+(\d+\.\d+\.\d+\.\d+)", line)
            if mm and cur:
                m[mm.group(1)] = cur
    return m


def src_addr_for(ip, port=53, timeout=1.0):
    """UDP connect 一个包都不发，但内核会按路由表选路并挑好源地址 ——
    这是「实际会从哪出去」最直接的证据，比读路由表更接近事实。"""
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        return s.getsockname()[0]
    except OSError:
        return ""
    finally:
        if s:
            s.close()


def tcp_probe(ip, port=443, timeout=2.0):
    s = None
    t0 = time.time()
    try:
        s = socket.create_connection((ip, port), timeout=timeout)
        return True, round((time.time() - t0) * 1000), s.getsockname()[0]
    except OSError:
        return False, None, ""
    finally:
        if s:
            try:
                s.close()
            except OSError:
                pass


def first_hop(ip):
    """第一跳到底是谁 —— 这是**实测**，不是读路由表。

    做法：发一个 TTL=1 的 ping，逼第一跳路由器回一条 "Time to live exceeded"，
    从回复里把它的地址读出来。macOS 的 ping 是 setuid 的，普通用户就能跑
    （这点比 traceroute 强 —— 后者在很多受限环境里会被拒）。
    实在拿不到再退回 traceroute。
    """
    if IS_WIN:
        # Windows 的 ping 用 `-i` 指定 TTL、`-w` 是毫秒超时。
        # TTL=1 会逼第一跳回一条 "Reply from x.x.x.x: TTL expired in transit."
        rc, out, _ = run(["ping", "-n", "1", "-i", "1", "-w", "1000", ip],
                         timeout=6)
        m = re.search(r"[Rr]eply from\s+(\d+\.\d+\.\d+\.\d+)", out or "")
        return m.group(1) if m else ""
    out = _sh(f"ping -c 1 -m 1 -W 400 -t 2 {ip} 2>&1", timeout=4)
    m = re.search(r"from\s+\S+\s+\((\d+\.\d+\.\d+\.\d+)\)", out)
    if m:
        return m.group(1)
    m = re.search(r"[Ff]rom\s+(\d+\.\d+\.\d+\.\d+)", out)
    if m:
        return m.group(1)
    return ""


def parallel_map(fn, items, workers=6):
    """小并发跑一批「只读探测」（ping / DNS / TCP）。

    体检如果全串行要 10 秒以上，点一下按钮等十秒太难受；
    这些操作彼此完全独立、也没有共享状态，并发起来能压到 2 秒左右。
    """
    items = list(items)
    if not items:
        return []
    out = [None] * len(items)
    pending = list(range(len(items)))
    lock = threading.Lock()

    def worker():
        while True:
            with lock:
                if not pending:
                    return
                i = pending.pop(0)
            try:
                out[i] = fn(items[i])
            except Exception:       # noqa: BLE001 —— 单个探测失败不影响其它
                out[i] = None

    threads = [threading.Thread(target=worker, daemon=True)
               for _ in range(max(1, min(workers, len(items))))]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return out


def dhcp_dns(iface):
    """物理网卡从 DHCP 拿到的 DNS —— 「没被任何隧道或手动配置污染」的原始值。"""
    if not iface:
        return []
    if IS_WIN:
        # Windows 没有命令行办法读回「DHCP 当初下发的那组 DNS」——
        # 一旦被改过，Get-DnsClientServerAddress 只会给当前值。
        # 这里如实返回空，上层的「DNS 是否被覆盖」判定在 Windows 上会跳过。
        return []
    rc, out, _ = run(["ipconfig", "getoption", iface, "domain_name_server"])
    if rc != 0 or not out.strip():
        return []
    return [x.strip() for x in re.split(r"[,\s]+", out.strip()) if x.strip()]


def system_dns_servers():
    """当前系统实际生效的 DNS（只看主解析器，避免把 VPN 推送的一堆都算进来）。"""
    if IS_WIN:
        rc, out, _ = run_ps(
            "[Console]::OutputEncoding=[Text.Encoding]::UTF8;"
            "Get-DnsClientServerAddress -AddressFamily IPv4 "
            "-ErrorAction SilentlyContinue | "
            "Where-Object { $_.ServerAddresses.Count -gt 0 } | "
            "Select-Object -ExpandProperty ServerAddresses | ConvertTo-Json"
        )
        if rc != 0 or not out:
            return []
        try:
            data = json.loads(out)
        except json.JSONDecodeError:
            return []
        if isinstance(data, str):
            data = [data]
        srv = []
        for s in data or []:
            s = str(s).strip()
            if s and s not in srv:
                srv.append(s)
        return srv[:6]
    srv = []
    out = _sh("scutil --dns 2>/dev/null")
    block = out.split("resolver #")[1] if "resolver #" in out else out
    for m in re.finditer(r"nameserver\[\d+\]\s*:\s*(\S+)", block):
        if m.group(1) not in srv:
            srv.append(m.group(1))
    if not srv:
        _rc, o2, _e = run(["cat", "/etc/resolv.conf"])
        for m in re.finditer(r"^\s*nameserver\s+(\S+)", o2 or "", re.M):
            if m.group(1) not in srv:
                srv.append(m.group(1))
    return srv[:6]


def ipv4_dns_servers(servers=None):
    """直查用的 DNS 列表 —— 只要 IPv4。

    scutil 常常把 `fe80::10%en0` 这种链路本地地址排在最前，但那是 IPv6，
    用 IPv4 的 UDP socket 根本发不出去（查了也是白查）。
    """
    src = servers if servers is not None else system_dns_servers()
    out = []
    for s in src:
        s2 = s.split("%")[0]
        if ":" in s2:
            continue
        if re.match(r"^\d+\.\d+\.\d+\.\d+$", s2) and s2 not in out:
            out.append(s2)
    return out


def _dns_skip_name(data, off):
    while off < len(data):
        n = data[off]
        if n == 0:
            return off + 1
        if n & 0xC0 == 0xC0:
            return off + 2
        off += 1 + n
    return off


def dns_query(server, name, timeout=2.0):
    """直接向指定 DNS 服务器发一个 A 查询（纯 stdlib，不依赖 dnspython）。

    返回 (rcode, [ip])；rcode 为 None 表示无响应（超时 / 被拦 / 响应 ID 不匹配）。
    """
    tid = secrets.randbits(16)
    pkt = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    qname = b""
    for part in name.strip(".").split("."):
        if part:
            qname += bytes([len(part)]) + part.encode("ascii", "ignore")
    pkt += qname + b"\x00" + struct.pack(">HH", 1, 1)

    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(pkt, (server, 53))
        data, _ = s.recvfrom(2048)
    except OSError:
        return None, []
    finally:
        if s:
            s.close()

    if len(data) < 12 or struct.unpack(">H", data[0:2])[0] != tid:
        return None, []          # ID 不匹配 → 可能收到了伪造 / 错包响应
    rcode = data[3] & 0x0F
    qd = struct.unpack(">H", data[4:6])[0]
    an = struct.unpack(">H", data[6:8])[0]
    off = 12
    for _ in range(qd):
        off = _dns_skip_name(data, off) + 4
    ips = []
    for _ in range(an):
        if off >= len(data):
            break
        off = _dns_skip_name(data, off)
        if off + 10 > len(data):
            break
        atype, _cls, _ttl, rdlen = struct.unpack(">HHIH", data[off:off + 10])
        off += 10
        if atype == 1 and rdlen == 4 and off + 4 <= len(data):
            ips.append(socket.inet_ntoa(data[off:off + 4]))
        off += rdlen
    return rcode, ips


def sys_resolve(name):
    """走系统解析器（会经过隧道改写，也走系统缓存）。"""
    t0 = time.time()
    try:
        infos = socket.getaddrinfo(name, None, socket.AF_INET)
        ips = sorted({i[4][0] for i in infos})
        return ips, round((time.time() - t0) * 1000), ""
    except OSError as e:
        return [], None, str(e)


def phys_iface_guess():
    """猜物理出口：默认路由那条若非隧道就用它，否则找第一个活跃的物理口。"""
    if IS_WIN:
        def_iface, def_gw = default_route()
        phys = def_iface if is_phys_iface(def_iface) else ""
        if not phys:
            for i in scan_interfaces_win():
                if i.get("status") != "active":
                    continue
                if is_phys_iface(i["name"], i.get("desc") or ""):
                    phys = i["name"]
                    break
        gw = def_gw if phys == def_iface else (phys_gateway(phys) if phys else def_gw)
        return phys, gw
    def_iface, def_gw = default_route_mac()
    phys = def_iface if is_phys_iface(def_iface) else ""
    if not phys:
        for _ip, n in sorted(local_addr_map().items()):
            if is_phys_iface(n):
                phys = n
                break
    return phys, (def_gw if phys == def_iface else (phys_gateway_mac(phys) if phys else def_gw))


def quick_egress(res):
    """轻量版「声明 vs 实测」：只做 UDP 选路（不发包、微秒级），可随每次扫描跑。

    Windows 的「声明」要一次问完 —— Find-NetRoute 每条都起一次 PowerShell
    太慢，所以先把这几个目标凑成一批。
    """
    am = local_addr_map(res.get("interfaces"))
    targets = TRUTH_TARGETS[:4]
    if IS_WIN:
        decls = iface_of_win_batch([ip for _l, ip in targets])
    else:
        decls = {ip: iface_of_mac(ip) for _l, ip in targets}
    rows = []
    for label, ip in targets:
        decl = decls.get(ip, "")
        src = src_addr_for(ip)
        sif = am.get(src, "")
        rows.append({
            "label": label, "ip": ip,
            "declared_iface": decl, "src_ip": src, "src_iface": sif,
            "mismatch": bool(decl and sif and decl != sif),
        })
    return rows


def do_trace():
    """真实流量体检：不看配置，只看事实。返回结构化报告 + 一句话结论。"""
    t0 = time.time()
    phys, phys_gw = phys_iface_guess()
    def_iface, def_gw = default_route()
    dhcp = dhcp_dns(phys)
    cur_dns = system_dns_servers()
    query_dns = ipv4_dns_servers(cur_dns) or ["223.5.5.5"]   # 直查只用 IPv4

    # ---- 面板 1：路由（声明 vs 实测）----
    # 用固定 IP 而不是域名 —— 这样即使 DNS 已经挂了，这一栏照样能出结论
    am = local_addr_map()
    hops = parallel_map(first_hop, [ip for _l, ip in TRUTH_TARGETS], workers=6)
    decl_map = (iface_of_win_batch([ip for _l, ip in TRUTH_TARGETS])
                if IS_WIN
                else {ip: iface_of_mac(ip) for _l, ip in TRUTH_TARGETS})
    routes = []
    for (label, ip), hop in zip(TRUTH_TARGETS, hops):
        hop = hop or ""                          # 实测：TTL=1 逼出来的第一跳
        decl = decl_map.get(ip, "")              # 声明：路由表怎么写的
        src = src_addr_for(ip)                   # 实测：内核给这个目标挑了哪个源地址
        sif = am.get(src, "")

        hop_is_phys = bool(hop and phys_gw and hop == phys_gw)
        hop_other = bool(hop and not hop_is_phys)
        if hop_is_phys:
            actual = phys
        elif hop_other:
            actual = f"非物理（{hop}）"
        else:
            actual = sif or "?"

        mismatch = False
        if decl and is_tunnel_iface(decl) and hop_is_phys:
            mismatch = True                      # 路由说走隧道，包却从物理出去了
        elif decl and is_phys_iface(decl) and hop_other:
            mismatch = True                      # 路由说走物理，包却被拽到别处
        elif decl and sif and decl != sif and not hop:
            mismatch = True

        routes.append({
            "label": label, "ip": ip, "declared_iface": decl,
            "src_ip": src, "src_iface": sif, "first_hop": hop,
            "actual": actual, "mismatch": mismatch,
        })

    # ---- 面板 2：DNS（系统解析 vs 绕过系统直查）----
    servers = query_dns[:2]
    resolved = parallel_map(sys_resolve, TRUTH_DOMAINS, workers=4)
    pairs = [(srv, dom) for dom in TRUTH_DOMAINS for srv in servers]
    raws = parallel_map(lambda p: dns_query(p[0], p[1], timeout=2.5), pairs, workers=6)

    dns_rows, sys_cache = [], {}
    for i, dom in enumerate(TRUTH_DOMAINS):
        ips, ms, err = resolved[i] or ([], None, "")
        sys_cache[dom] = ips
        direct = []
        for j, srv in enumerate(servers):
            rc_, d_ips = raws[i * len(servers) + j] or (None, [])
            direct.append({"server": srv, "rcode": rc_, "ips": d_ips})
        fake = sorted({p for p in ips if FAKE_IP_RE.match(p)})
        dset = set()
        for d in direct:
            dset |= set(d["ips"])
        dns_rows.append({
            "domain": dom, "sys_ips": ips, "sys_ms": ms, "sys_err": err,
            "direct": direct, "fake_ips": fake,
            "disagree": bool(ips and dset and not (set(ips) & dset)),
        })

    # ---- 面板 3：连通性（照 DNS 结果真连一次）----
    probe_list = [(dom, ip) for dom in TRUTH_DOMAINS
                  for ip in (sys_cache.get(dom) or [])[:2]]
    pres = parallel_map(lambda t: tcp_probe(t[1], 443, timeout=3), probe_list, workers=6)
    phops = parallel_map(lambda t: first_hop(t[1]), probe_list, workers=6)
    conns_map = {dom: [] for dom in TRUTH_DOMAINS}
    for (dom, ip), pr, ph in zip(probe_list, pres, phops):
        ok_c, ms_c, _s = pr or (False, None, "")
        conns_map[dom].append({"ip": ip, "ok": ok_c, "ms": ms_c,
                               "first_hop": ph or ""})
    conns = [{"domain": dom, "ips": conns_map[dom],
              "ok": any(e["ok"] for e in conns_map[dom])} for dom in TRUTH_DOMAINS]

    # ---- 面板 4：汇总判定 ----
    issues, notes = [], []
    mm = [r for r in routes if r["mismatch"]]
    if mm:
        issues.append(f"{len(mm)} 个探测点的「路由表说的」和「实际走的」不一致")
    no_hop = [r for r in routes if not r["first_hop"]]
    if no_hop:
        notes.append(f"{len(no_hop)} 个探测点没拿到第一跳（丢包，或该目标不回 TTL 超时包）")
    fake_dom = [d for d in dns_rows if d["fake_ips"]]
    if fake_dom:
        issues.append("、".join(d["domain"] for d in fake_dom)
                      + f" 被解析进假 IP 池（如 {fake_dom[0]['fake_ips'][0]}）—— 典型的隧道接管特征")
    bad_dns = [d for d in dns_rows if not d["sys_ips"]]
    if bad_dns:
        issues.append("、".join(d["domain"] for d in bad_dns) + " 解析失败（DNS 可能已失效）")
    dis = [d for d in dns_rows if d["disagree"] and not d["fake_ips"]]
    if dis:
        issues.append("、".join(d["domain"] for d in dis)
                      + " 的系统解析结果与直查不一致（可能被改写，也可能只是 CDN 差异）")
    down = [c for c in conns if not c["ok"]]
    if down:
        issues.append("、".join(c["domain"] for c in down) + " 连不上（可能被黑洞或被拦）")
    dns_overridden = bool(dhcp and cur_dns and not (set(dhcp) & set(cur_dns)))
    if dns_overridden:
        issues.append("系统 DNS 与物理网络 DHCP 给的（" + "、".join(dhcp) + "）完全不同，DNS 已被覆盖")

    phys_n = sum(1 for r in routes if r["actual"] == phys)
    via_summary = (f"{len(routes)} 个探测点里 {phys_n} 个确认从物理网卡"
                   f"（{phys or def_iface or '?'}）出去，{len(routes) - phys_n} 个走了别的路径")

    if not issues:
        summary = (f"流量正常：{via_summary}；"
                   f"DNS（{'、'.join(cur_dns) or '系统默认'}）解析正常，"
                   f"{len(conns)} 个网站都能连通")
    else:
        summary = f"发现 {len(issues)} 项异常：" + "；".join(issues)

    return {
        "ok": True, "at": time.time(),
        "elapsed_ms": round((time.time() - t0) * 1000),
        "clean": not issues,
        "phys_iface": phys, "phys_gw": phys_gw,
        "default_iface": def_iface, "default_gw": def_gw,
        "dns_now": cur_dns, "dns_dhcp": dhcp, "dns_query_used": query_dns,
        "dns_overridden": dns_overridden,
        "routes": routes, "dns": dns_rows, "conns": conns,
        "via_summary": via_summary,
        "issues": issues, "notes": notes, "summary": summary,
    }


# ----------------------------------------------------------------------
# 应急恢复
# ----------------------------------------------------------------------

def net_service_for_iface(iface):
    """networksetup 要的是「网络服务名」（如 Wi-Fi），不是接口名 en0。"""
    if not iface:
        return ""
    out = _sh("networksetup -listnetworkserviceorder 2>/dev/null")
    for m in re.finditer(r"\(\d+\)\s*(.+?)\n\(Hardware Port:.*?Device:\s*([^\)\n]+)\)", out):
        if m.group(2).strip() == iface:
            return m.group(1).strip()
    return ""


def health_snapshot():
    """采集一份「健康基线」：物理出口 / 网关 / 网络服务名 / 各级 DNS。"""
    phys, gw = phys_iface_guess()
    if not phys:
        return None
    return {
        "at": time.time(),
        "phys_iface": phys,
        "phys_gw": gw,
        "net_service": net_service_for_iface(phys),
        "dns_dhcp": dhcp_dns(phys),
        "dns_now": system_dns_servers(),
        "default_iface": default_route_mac()[0],
    }


def save_health():
    snap = health_snapshot()
    if not snap:
        return False, "识别不出物理网卡，无法保存基线"
    try:
        os.makedirs(CONFIG_DIR, exist_ok=True)
        with open(HEALTH_FILE, "w", encoding="utf-8") as f:
            json.dump(snap, f, ensure_ascii=False, indent=2)
    except OSError as e:
        return False, f"写入失败：{e}"
    return True, (f"健康基线已保存：物理出口 {snap['phys_iface']} / 网关 "
                  f"{snap.get('phys_gw') or '?'} / DNS "
                  f"{'、'.join(snap.get('dns_dhcp') or []) or '由 DHCP 自动分配'}")


def load_health():
    try:
        with open(HEALTH_FILE, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def fake_pool_routes():
    """路由表里指向「假 IP 池」网段的条目（隧道接管的典型痕迹）。"""
    found = []
    for dest, _alias in _routes_snapshot():
        if "/" not in dest:
            continue
        if re.match(r"^(198\.1[89]\.|100\.6[4-9]\.|240\.0\.0\.)", dest.split("/")[0]):
            found.append(dest)
    return sorted(set(found))


def _rescue_log(lines):
    try:
        os.makedirs(CONFIG_DIR, exist_ok=True)
        if os.path.isfile(RESCUE_LOG) and os.path.getsize(RESCUE_LOG) > 512_000:
            os.replace(RESCUE_LOG, RESCUE_LOG + ".1")
        with open(RESCUE_LOG, "a", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
    except OSError:
        pass


def _win_do_rescue():
    """Windows 版应急恢复。

    与 macOS 同一条原则：**只做恢复，不做优化**；每步记 before/after；
    不做不可逆的事。但有三处必须如实区别对待：

      · 默认出口：**不自动改接口跃点数**。Windows 的跃点数是持久化的网络配置，
        乱改会在换网络以后留下后遗症 —— 代价大于收益。这里只报告 + 指路。
      · 残留路由：与 macOS 同口径，只删「指向已消失接口」的条目，绝不动默认路由。
      · DNS：交回 DHCP 自动派生（ResetServerAddresses），并清一次解析缓存。

    ⚠️ 提权走 UAC，**没有密码可输** —— 用户点了「否」我们只能如实说没做完，
    绝不返回 NEED_SUDO 去要密码。
    """
    steps, manual = [], []
    need_admin = False

    snap = load_health() or {}
    phys = snap.get("phys_iface") or ""
    if not phys:
        phys, _gw = phys_iface_guess()
    gw = snap.get("phys_gw") or ""
    if not gw and phys:
        gw = phys_gateway(phys)

    before = {
        "at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "default_route": list(default_route()),
        "dns": system_dns_servers(),
    }

    def add(name, ok, detail):
        steps.append({"name": name, "ok": bool(ok), "detail": detail})

    # 1) 默认出口：只报告，不自动改（见 docstring）
    d_iface, d_gw = before["default_route"]
    if d_iface and is_tunnel_iface(d_iface):
        add("默认出口 → 物理网卡", False,
            "默认路由现在在隧道「%s」上。本工具不自动改接口跃点数"
            "（那是持久化配置，换网络后会留下后遗症）—— "
            "请用上面的「出口管理」把隧道停掉。" % d_iface)
    else:
        add("默认出口 → 物理网卡", True,
            "已在物理口 %s 上，无需改动"
            % ("/".join(x for x in (d_iface, d_gw) if x) or "?"))

    # 2) 残留黑洞路由（指向已消失的接口）
    n, msg = clean_residual_routes()
    if msg == "NEED_SUDO":
        need_admin = True
        add("清理残留黑洞路由", False, "管理员授权被取消")
    else:
        add("清理残留黑洞路由", not msg.startswith("清理未完全成功"), msg)

    # 3) 假 IP 池路由
    fake = fake_pool_routes()
    if not fake:
        add("清除假 IP 池路由", True, "未发现假 IP 池路由")
    else:
        lines = ["$ok=$true"]
        for d in fake:
            s = str(d).replace("'", "''")
            lines.append("try { Remove-NetRoute -DestinationPrefix '%s' "
                         "-Confirm:$false -ErrorAction Stop } catch { $ok=$false; "
                         "Write-Output ('ERR %s: ' + $_.Exception.Message) }"
                         % (s, s))
        lines.append("if ($ok) { Write-Output '__TM_OK__' } "
                     "else { Write-Output '__TM_FAIL__' }")
        ok, text, cancelled = _win_elevated(lines, _cmd_remove_routes(fake))
        if cancelled:
            need_admin = True
            add("清除假 IP 池路由", False, "管理员授权被取消")
        else:
            add("清除假 IP 池路由", ok,
                ("删除 %d 条（%s）" % (len(fake), ", ".join(fake[:5]))) if ok
                else (text[:160] or "未知原因"))

    # 4) DNS：优先恢复保存过的健康基线，否则交回 DHCP
    if not phys:
        add("DNS 恢复", False, "识别不出物理网卡，跳过")
    else:
        saved = load_health()
        base_dns = ipv4_dns_servers((saved or {}).get("dns_now") or [])
        cur = before["dns"]
        if base_dns and set(cur) == set(base_dns):
            add("DNS 恢复", True, "已是 %s，无需改动" % "、".join(cur))
        else:
            alias = str(phys).replace("'", "''")
            arg = ("-ServerAddresses '%s'" % ",".join(base_dns)) if base_dns \
                else "-ResetServerAddresses"
            ok, text, cancelled = _win_elevated([
                "try { Set-DnsClientServerAddress -InterfaceAlias '%s' %s "
                "-ErrorAction Stop; Write-Output '__TM_OK__' } "
                "catch { Write-Output '__TM_FAIL__'; "
                "Write-Output ('ERR ' + $_.Exception.Message) }" % (alias, arg)],
                _cmd_set_dns(phys, base_dns))
            if cancelled:
                need_admin = True
                add("DNS 恢复", False, "管理员授权被取消")
            else:
                after_txt = "、".join(base_dns) if base_dns else "由 DHCP 自动分配"
                add("DNS 恢复", ok,
                    ("%s → %s（%s）" % ("、".join(cur) or "(空)", after_txt,
                                       "恢复到保存的健康基线" if base_dns
                                       else "交回 DHCP 自动分配")) if ok
                    else (text[:160] or "未知原因"))

    # 5) 刷新 DNS 缓存（Windows 上这一步不需要管理员）
    if ps_available()[0]:
        rc, out, err = run_ps("Clear-DnsClientCache; if ($?) { '__TM_OK__' }")
        ok5 = rc == 0 and "__TM_OK__" in (out or "")
        err5 = err
    else:
        rc5, out5, err5 = run(["ipconfig", "/flushdns"], timeout=30)
        ok5 = rc5 == 0
    add("刷新 DNS 缓存", ok5, "已清空解析缓存" if ok5 else (err5 or "清理失败")[:120])

    # 复验
    time.sleep(0.6)
    ok_v, ms_v, _ = tcp_probe("223.5.5.5", 443, timeout=3)
    ips_v, _ms_r, _err = sys_resolve("www.baidu.com")
    verify = {"tcp_ok": ok_v, "tcp_ms": ms_v, "dns_ok": bool(ips_v),
              "dns_ips": ips_v[:3], "phys_iface": phys}
    add("复验", bool(ok_v and ips_v),
        ("能" if ok_v else "不能") + "连通外网（%s ms）；"
        % (ms_v if ms_v is not None else "-")
        + ("DNS 解析成功 " + "、".join(ips_v[:2]) if ips_v else "DNS 解析仍失败"))
    after = {"default_route": list(default_route()), "dns": system_dns_servers()}
    _rescue_log(
        ["=" * 60, "[%s] 应急恢复（Windows）" % before["at"],
         "  before: 默认路由=%s  DNS=%s" % (before["default_route"], before["dns"]),
         "  after : 默认路由=%s  DNS=%s" % (after["default_route"], after["dns"])]
        + ["  %s: %s — %s" % (s["name"], "OK" if s["ok"] else "FAIL", s["detail"])
           for s in steps])

    manual.append("如果隧道客户端还在跑，它可能再次改写 DNS 和路由 —— "
                  "建议在它的界面里停止加速，或用上面的「出口管理」切到「物理直连」。")
    if not verify["dns_ok"]:
        manual.append("DNS 仍解析失败：多半是隧道客户端还在接管，或路由器本身的 DNS 有问题。"
                      "可以试着把 DNS 手动改成 223.5.5.5 / 119.29.29.29。")

    body = {"steps": steps, "manual": manual, "before": before,
            "after": after, "verify": verify}
    if need_admin:
        return {"ok": False,
                "message": "有步骤的「管理员授权」被取消或超时，没做完 —— 可以再点一次",
                "rescue": body}
    ok_all = all(s["ok"] for s in steps)
    return {
        "ok": ok_all,
        "message": ("应急恢复完成，网络已回到本机直连状态"
                    if ok_all else "应急恢复部分完成，请查看下面哪一步失败了"),
        "rescue": body,
    }


def do_rescue(pw=None):
    """一键应急恢复：把路由与 DNS 救回「本机直连」的干净状态。

    设计原则：
      · 只做「恢复」不做「优化」—— 目标是让网络回到能用，不是变快
      · 每步都记 before/after 并落 rescue.log，事后能审计、能对照
      · 不做不可逆的事（不删配置、不动 hosts、不卸软件）
    """
    if IS_WIN:
        return _win_do_rescue()
    if not IS_MAC:
        return {"ok": False, "message": f"暂仅支持 Windows / macOS（当前 {PLATFORM}）"}

    steps, manual = [], []
    need_pw = False

    snap = load_health() or health_snapshot() or {}
    phys = snap.get("phys_iface") or ""
    gw = snap.get("phys_gw") or ""
    svc = snap.get("net_service") or net_service_for_iface(phys)

    before = {
        "at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "default_route": list(default_route_mac()),
        "dns": system_dns_servers(),
    }

    def add(name, ok, detail):
        steps.append({"name": name, "ok": bool(ok), "detail": detail})

    # 1) 默认路由回到物理网关
    d_iface, d_gw = before["default_route"]
    if phys and gw:
        if d_iface == phys and (not d_gw or d_gw == gw):
            add("默认路由 → 物理网关", True, f"已是 {phys} / {gw}，无需改动")
        else:
            rc, _o, _e = run_root(f"route -n change default {gw}", pw)
            if rc == 403:
                need_pw = True
                add("默认路由 → 物理网关", False, "需要管理员密码")
            else:
                add("默认路由 → 物理网关", rc == 0,
                    f"{d_iface or '?'}/{d_gw or '?'} → {phys}/{gw}")
    else:
        add("默认路由 → 物理网关", False, "识别不出物理网卡或网关，跳过")

    # 2) 残留黑洞路由（指向已消失的接口）
    if not need_pw:
        n, msg = clean_residual_routes(pw)
        if msg == "NEED_SUDO":
            need_pw = True
            add("清理残留黑洞路由", False, "需要管理员密码")
        else:
            add("清理残留黑洞路由", True, msg)

    # 3) 假 IP 池路由
    if not need_pw:
        fake = fake_pool_routes()
        if not fake:
            add("清除假 IP 池路由", True, "未发现假 IP 池路由")
        else:
            rc, _o, _e = run_root(" ; ".join(_del_route_cmd(d) for d in fake), pw)
            if rc == 403:
                need_pw = True
                add("清除假 IP 池路由", False, "需要管理员密码")
            else:
                add("清除假 IP 池路由", rc == 0,
                    f"删除 {len(fake)} 条（{', '.join(fake[:5])}）")

    # 4) DNS 恢复
    #    优先恢复到「用户自己存过的健康基线」（尊重他本来就有的自定义 DNS）；
    #    没有基线就设成 Empty —— 即清掉一切自定义，交回 DHCP / 系统自动派生。
    #    不直接把 DNS 写死成路由器 IP：那样换个网络就失效了。
    if not need_pw:
        saved = load_health()
        base_dns = ipv4_dns_servers((saved or {}).get("dns_now") or [])
        cur = before["dns"]
        if base_dns:
            target, why = base_dns, "恢复到保存的健康基线"
        else:
            target, why = ["Empty"], "清掉自定义 DNS，交回 DHCP 自动分配"
        if not svc:
            add("DNS 恢复", False, f"找不到 {phys} 对应的网络服务名，跳过")
        elif cur and base_dns and set(cur) == set(base_dns):
            add("DNS 恢复", True, f"已是 {'、'.join(cur)}，无需改动")
        else:
            rc, _o, _e = run_root(
                f'networksetup -setdnsservers "{svc}" ' + " ".join(target), pw)
            if rc == 403:
                need_pw = True
                add("DNS 恢复", False, "需要管理员密码")
            else:
                after_txt = "、".join(base_dns) if base_dns else "由 DHCP 自动分配"
                add("DNS 恢复", rc == 0,
                    f"{'、'.join(cur) or '(空)'} → {after_txt}（{why}）")

    # 5) 刷新 DNS 缓存
    if not need_pw:
        rc, _o, _e = run_root("dscacheutil -flushcache; killall -HUP mDNSResponder", pw)
        if rc == 403:
            need_pw = True
            add("刷新 DNS 缓存", False, "需要管理员密码")
        else:
            add("刷新 DNS 缓存", rc == 0, "已清空缓存并让 mDNSResponder 重读配置")

    verify = after = None
    if not need_pw:
        time.sleep(0.6)
        ok_v, ms_v, _ = tcp_probe("223.5.5.5", 443, timeout=3)
        ips_v, ms_r, _err = sys_resolve("www.baidu.com")
        verify = {"tcp_ok": ok_v, "tcp_ms": ms_v, "dns_ok": bool(ips_v),
                  "dns_ips": ips_v[:3], "dns_ms": ms_r, "phys_iface": phys}
        add("复验", bool(ok_v and ips_v),
            ("能" if ok_v else "不能") + f"连通外网（{ms_v if ms_v is not None else '-'} ms）；"
            + ("DNS 解析成功 " + "、".join(ips_v[:2]) if ips_v else "DNS 解析仍失败"))
        after = {"default_route": list(default_route_mac()), "dns": system_dns_servers()}
        _rescue_log(
            ["=" * 60, f"[{before['at']}] 应急恢复",
             f"  before: 默认路由={before['default_route']}  DNS={before['dns']}",
             f"  after : 默认路由={after['default_route']}  DNS={after['dns']}"]
            + [f"  {s['name']}: {'OK' if s['ok'] else 'FAIL'} — {s['detail']}" for s in steps])

    manual.append("如果隧道客户端（aTrust / 雷神 / 网易UU 等）还在跑，它可能再次改写 DNS 和路由 —— "
                  "建议在它的界面里停止加速，或用上面的「出口管理」切到「物理直连」。")
    if verify and not verify["dns_ok"]:
        manual.append("DNS 仍解析失败：多半是隧道客户端还在接管，或路由器本身的 DNS 有问题。"
                      "可以试着把 DNS 手动改成 223.5.5.5 / 119.29.29.29。")

    if need_pw:
        return {"ok": False, "error": "NEED_SUDO", "message": "需要管理员密码",
                "rescue": {"steps": steps, "manual": manual, "before": before}}

    ok_all = all(s["ok"] for s in steps)
    return {
        "ok": ok_all,
        "message": ("应急恢复完成，网络已回到本机直连状态"
                    if ok_all else "应急恢复部分完成，请查看下面哪一步失败了"),
        "rescue": {"steps": steps, "manual": manual, "before": before,
                   "after": after, "verify": verify},
    }


