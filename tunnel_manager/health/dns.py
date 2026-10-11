# -*- coding: utf-8 -*-
"""tunnel_manager.health/dns — DNS 查询与系统 DNS 配置

由 P2 从 health/flow.py 的第 147–286 行**原样拆出**，正文逐字未改（与 P1 一样，只搬不改）。

【切片规则 —— 这不是漏写 import】
本项目按设计保持**单一扁平命名空间**：
  · 开发期入口 `python -m tunnel_manager.main` → 把所有切片拼进一个命名空间再执行；
  · 构建期 `bundle.py` → 同样顺序拼接成单文件 `dist/tunnel-manager.py`（纯源码，不含 exec）。
所以本文件里可以直接引用其它切片定义的函数与常量，无需 import。跨切片调用是既有事实。
本模块对外提供：dhcp_dns、dns_query、ipv4_dns_servers、sys_resolve、system_dns_servers
本模块依赖其它切片：_base、outlet/scene_ops、util
"""
>>>SLICE_BODY<<<
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


