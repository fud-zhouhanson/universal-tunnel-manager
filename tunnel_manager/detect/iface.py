# -*- coding: utf-8 -*-
"""tunnel_manager.detect/iface — 接口证据：扫网卡（IPv4 / IPv6-ULA / MTU）

由 P1 从 server.py 的第 471–619 行**整块搬迁**而来，正文逐字未改。

【切片规则 —— 这不是漏写 import】
本项目按设计保持**单一扁平命名空间**：
  · 开发期入口 `python -m tunnel_manager.main` → 把所有切片拼进一个命名空间再执行；
  · 构建期 `bundle.py` → 同样顺序拼接成单文件 `dist/tunnel-manager.py`（纯源码，不含 exec）。
所以本文件里可以直接引用其它切片定义的函数与常量，无需 import。跨切片调用是既有事实。
本模块对外提供：is_loopback_iface、is_phys_iface、is_system_iface、is_tunnel_iface、parse_ula_vendor、scan_interfaces_mac 等 7 个
本模块依赖其它切片：_base、consts、util、win/native
"""
>>>SLICE_BODY<<<
# ======================================================================
# 四、接口证据：扫网卡（v2：收集 IPv4/IPv6-ULA/MTU 三项特征）
# ======================================================================

def is_tunnel_iface(name, desc=""):
    blob = (name + " " + desc).lower()
    if TUNNEL_IFACE_RE.match(name):
        return True
    # ⚠️ Windows 的隧道网卡**名字不叫 utunN**，而是厂商描述，例如
    #    「Sangfor SSL VPN CS Support System VNIC」（aTrust 就是这个）。
    #    不认出来它就会被当成物理网卡 —— 整个「物理 vs 隧道」的判断都会反过来。
    return any(k in blob for k in ("tap-", "tun-", "virtual adapter",
                                   "virtual ethernet", "虚拟网卡",
                                   "vnic", "ssl vpn", "vpn adapter",
                                   "sangfor", "深信服", "easyconnect",
                                   "anyconnect", "openvpn", "wireguard",
                                   "forticlient", "secoclient", "pangolin"))


def is_phys_iface(name, desc=""):
    return bool(PHYS_IFACE_RE.match(name))


def is_loopback_iface(*names):
    """回环接口（lo0 / Loopback Pseudo-Interface 1 / 回环）。

    独立成一个判定是必要的：Windows 原生解析会拿到回环口，
    而它带 127.0.0.1、类型也像「有 IP 的以太网口」，
    不排掉就会被当成「物理网卡」——那会导致整份判断都错。
    """
    for n in names:
        b = (n or "").strip().lower()
        if not b:
            continue
        # ⚠️ 别用 startswith("lo") —— Windows 上常有叫
        #    「Local Area Connection」的**物理**网卡，会被误杀。
        if re.fullmatch(r"lo\d*", b) or b in ("loopback", "回环"):
            return True
        if "loopback" in b or "回环" in b or "pseudo-interface" in b:
            return True
    return False


def is_system_iface(name):
    """macOS 系统自带虚拟接口：gif/stf/bridge/awdl/llw/anpi —— 非业务隧道。"""
    return bool(SYSTEM_IFACE_RE.match(name))


def parse_ula_vendor(ipv6_line):
    """从 IPv6 ULA 前缀解出厂商指纹。
    厂商常把名字编进 fd 开头的 ULA：fd53:414e:4746:4f52… → 41 4e 47 46 4f 52 = SANGFOR
    """
    m = re.search(r"inet6 (fd[0-9a-f]{2}:[0-9a-f]{4}:[0-9a-f]{4}:[0-9a-f]{4})",
                  ipv6_line, re.I)
    if not m:
        return None
    hexes = m.group(1).replace(":", "")[2:]  # 去掉 fd 前缀
    try:
        raw = bytes.fromhex(hexes).decode("ascii", "ignore")
    except ValueError:
        return None
    return "".join(c for c in raw if c.isascii() and c.isupper()).upper() or None


def scan_interfaces_mac():
    """返回接口列表，每项含 name/ipv4/ipv6_ula/mtu/status/desc。"""
    rc, out, _ = run(["ifconfig", "-a"])
    if rc != 0:
        return []
    ifaces = []
    cur = None
    for line in out.splitlines():
        m = re.match(r"^([a-zA-Z]+\d+):", line)
        if m:
            if cur:
                ifaces.append(cur)
            cur = {"name": m.group(1), "ipv4": "", "ipv6_ula": "",
                   "mtu": 0, "status": "", "desc": ""}
            # macOS 的 MTU 与接口名同行：utun0: flags=... mtu 1380
            mm = re.search(r"mtu (\d+)", line)
            if mm:
                cur["mtu"] = int(mm.group(1))
            continue
        if cur is None:
            continue
        if not cur["ipv4"]:
            m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", line)
            if m:
                cur["ipv4"] = m.group(1)
        if not cur["ipv6_ula"]:
            v = parse_ula_vendor(line)
            if v:
                cur["ipv6_ula"] = v
        if not cur["mtu"]:
            m = re.search(r"mtu (\d+)", line)
            if m:
                cur["mtu"] = int(m.group(1))
        m = re.search(r"status:\s*(\w+)", line)
        if m:
            cur["status"] = m.group(1)
    if cur:
        ifaces.append(cur)
    return ifaces


def scan_interfaces_win():
    """接口列表：优先 PowerShell（信息最全），被策略拦住时退回原生命令解析。"""
    if ps_available()[0]:
        got = _scan_interfaces_win_ps()
        if got:
            return got
    return _nat_interfaces()


def _scan_interfaces_win_ps():
    rc, out, err = run_ps(
        "[Console]::OutputEncoding=[Text.Encoding]::UTF8;"
        "$a=Get-NetAdapter | Select Name,InterfaceDescription,InterfaceType,"
        "Status,MtuSize;"
        "$i=Get-NetIPAddress -AddressFamily IPv4 | "
        "Select InterfaceAlias,IPAddress;"
        "$a | ForEach-Object { $n=$_.Name; $ip=($i | Where-Object "
        "InterfaceAlias -eq $n | Select -First 1 -ExpandProperty IPAddress);"
        "[PSCustomObject]@{name=$_.Name; desc=$_.InterfaceDescription;"
        "type=$_.InterfaceType; status=$_.Status; ipv4=$ip; mtu=$_.MtuSize} } | "
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
    result = []
    for a in data:
        result.append({
            "name": a.get("name", ""),
            "desc": a.get("desc", ""),
            "type": a.get("type", None),
            "status": "active" if a.get("status") == "Up" else "inactive",
            "ipv4": a.get("ipv4") or "",
            "ipv6_ula": "",
            "mtu": a.get("mtu") or 0,
        })
    return result


