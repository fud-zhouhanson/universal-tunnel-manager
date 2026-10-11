# -*- coding: utf-8 -*-
"""tunnel_manager.detect/judge — 归属判定：四层证据融合

由 P1 从 server.py 的第 1164–1235 行**整块搬迁**而来，正文逐字未改。

【切片规则 —— 这不是漏写 import】
本项目按设计保持**单一扁平命名空间**：
  · 开发期入口 `python -m tunnel_manager.main` → 把所有切片拼进一个命名空间再执行；
  · 构建期 `bundle.py` → 同样顺序拼接成单文件 `dist/tunnel-manager.py`（纯源码，不含 exec）。
所以本文件里可以直接引用其它切片定义的函数与常量，无需 import。跨切片调用是既有事实。
本模块对外提供：classify_phys、classify_tunnel
本模块依赖其它切片：_base、consts
"""
>>>SLICE_BODY<<<
# ======================================================================
# 七、归属判定（v2：四层证据融合 + 系统噪音过滤）
# ======================================================================

def classify_tunnel(name, desc, ipv4, ipv6_ula, mtu, def_iface, phys_iface,
                    software, egress_counts):
    """判定一个隧道接口归属哪类软件。

    优先级：
      0. 无 IPv4 且是 utun → macOS 系统自带隧道（接力/隔空投送），非业务
      1. 接口名/描述精确匹配软件库
      2. IPv6 ULA 厂商指纹（SANGFOR / TAILSCALE …）
      3. MTU 特征（ZeroTier feth MTU 2800）
      4. 承载默认路由 → 全流量隧道
      5. 命名规律启发式
    """
    blob = (name + " " + desc).lower()

    # ---- 第 0 层：系统噪音过滤 ----
    # macOS 的 utun0-5 只有 link-local IPv6、无 IPv4 → 系统自带（接力/隔空投送）
    if not ipv4 and re.match(r"^utun\d+$", name, re.I):
        return "macOS 系统隧道（接力/隔空投送）"

    # ---- 第 1 层：接口名/描述精确匹配软件库 ----
    for sw in software:
        for pat in sw["iface"]:
            if pat and pat.lower() in blob:
                return sw["name"]
    for sw in TUNNEL_KNOWLEDGE:
        for pat in sw["iface"]:
            if pat and pat.lower() in blob:
                return sw["name"]

    # ---- 第 2 层：IPv6 ULA 厂商指纹 ----
    if ipv6_ula:
        for sw in TUNNEL_KNOWLEDGE:
            if ipv6_ula in sw.get("ula", []):
                return sw["name"]
        if ipv6_ula != "":
            return f"未知厂商隧道（ULA 指纹：{ipv6_ula}）"

    # ---- 第 3 层：MTU 特征（ZeroTier feth MTU 2800） ----
    if mtu and mtu == 2800 and re.match(r"^(feth|zt)", name, re.I):
        return "ZeroTier"

    # ---- 第 4 层：承载默认路由 → 全流量隧道 ----
    if name == def_iface:
        for sw in software:
            if sw["cat"] in ("企业VPN", "代理", "加速器"):
                return f"{sw['name']}（全流量）"
        return "未知全流量隧道"

    # ---- 第 5 层：命名规律启发式 ----
    if re.match(r"^(utun|feth)", name, re.I):
        if ipv4:
            return "第三方隧道接口（有 IPv4）"
        return "系统隧道接口（无业务流量）"
    if re.match(r"^(tap|tun)", name, re.I):
        return "Tap/Tun 隧道接口"
    if re.match(r"^wg", name, re.I):
        return "WireGuard 接口"
    if re.match(r"^ppp", name, re.I):
        return "PPTP/L2TP 拨号"
    return "未知隧道接口"


def classify_phys(name, desc, phys_iface):
    if name == phys_iface:
        return "物理网卡（系统出口）"
    return "物理网卡"


