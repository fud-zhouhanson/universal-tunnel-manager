# -*- coding: utf-8 -*-
"""tunnel_manager.consts — 已知隧道软件库（识别字典）

由 P1 从 server.py 的第 105–321 行**整块搬迁**而来，正文逐字未改。

【切片规则 —— 这不是漏写 import】
本项目按设计保持**单一扁平命名空间**：
  · 开发期入口 `python -m tunnel_manager.main` → 把所有切片拼进一个命名空间再执行；
  · 构建期 `bundle.py` → 同样顺序拼接成单文件 `dist/tunnel-manager.py`（纯源码，不含 exec）。
所以本文件里可以直接引用其它切片定义的函数与常量，无需 import。跨切片调用是既有事实。
本模块对外提供：PHYS_IFACE_RE、RESERVED_NETS、SYSTEM_IFACE_RE、TUNNEL_IFACE_RE、TUNNEL_KNOWLEDGE、ip_to_int 等 8 个
本模块依赖其它切片：_base
"""
>>>SLICE_BODY<<<
# ======================================================================
# 一、已知隧道软件库（识别字典）
# 每个条目：类别 + 跨平台进程关键字 + 关联的接口名特征 + MTU 特征
# ======================================================================

TUNNEL_KNOWLEDGE = [
    # ---- 企业零信任 / VPN ----
    {"name": "aTrust (深信服零信任)", "cat": "企业VPN",
     "proc": ["atrust", "sangfor"],
     "iface": ["sangfor"],
     "ula": ["SANGFOR"],
     "mtu": None},
    {"name": "EasyConnect (深信服)", "cat": "企业VPN",
     "proc": ["easyconnect", "ecagent", "svntool", "svnagent"],
     "iface": ["easyconnect"],
     "ula": ["SANGFOR"],
     "mtu": None},
    {"name": "天融信 VPN", "cat": "企业VPN",
     "proc": ["topsec", "t-vpn", "ngtop"],
     "iface": ["topsec"],
     "ula": [], "mtu": None},
    {"name": "华为 AnyOffice / SSL VPN", "cat": "企业VPN",
     "proc": ["secoclient", "secovpn"],
     "iface": ["seco", "huawei"],
     "ula": [], "mtu": None},
    {"name": "Cisco AnyConnect", "cat": "企业VPN",
     "proc": ["vpnagent", "anyconnect", "cscotun"],
     "iface": ["cscotun"],
     "ula": [], "mtu": None},
    {"name": "GlobalProtect (Palo Alto)", "cat": "企业VPN",
     "proc": ["pangpa", "pangps", "globalprotect"],
     "iface": ["pangp", "globalprotect"],
     "ula": [], "mtu": None},
    {"name": "FortiClient (飞塔)", "cat": "企业VPN",
     "proc": ["fortissl", "forticlient", "fortitray"],
     "iface": ["forti"],
     "ula": [], "mtu": None},

    # ---- 开源 / 商业 VPN ----
    {"name": "OpenVPN", "cat": "开源VPN",
     "proc": ["openvpn"],
     "iface": ["openvpn"],
     "ula": [], "mtu": None},
    {"name": "WireGuard", "cat": "开源VPN",
     "proc": ["wireguard", "wg-quick"],
     "iface": ["wg", "wireguard"],
     "ula": [], "mtu": None},
    {"name": "SoftEther VPN", "cat": "开源VPN",
     "proc": ["vpnclient", "vpnserver", "softether"],
     "iface": ["softether"],
     "ula": [], "mtu": None},
    {"name": "IPSec / L2TP / PPTP / IKEv2", "cat": "系统VPN",
     "proc": ["racoon", "charon", "iked", "xl2tpd", "pptpd", "l2tp"],
     "iface": ["ppp", "ipsec"],
     "ula": [], "mtu": None},

    # ---- 代理 / 梯子 ----
    {"name": "Clash / Mihomo", "cat": "代理",
     "proc": ["clash", "mihomo", "clash-verge", "clashx", "clash-meta"],
     "iface": ["mihomo", "clash"],
     "ula": [], "mtu": None},
    {"name": "V2Ray / Xray", "cat": "代理",
     "proc": ["v2ray", "xray", "v2fly"],
     "iface": ["v2ray", "xray"],
     "ula": [], "mtu": None},
    {"name": "Shadowsocks", "cat": "代理",
     "proc": ["ss-local", "ss-server", "shadowsocks", "ssr"],
     "iface": ["shadowsocks"],
     "ula": [], "mtu": None},
    {"name": "Trojan", "cat": "代理",
     "proc": ["trojan", "trojan-go"],
     "iface": ["trojan"],
     "ula": [], "mtu": None},
    {"name": "Hysteria", "cat": "代理",
     "proc": ["hysteria", "hysteria2"],
     "iface": ["hysteria"],
     "ula": [], "mtu": None},
    {"name": "NaiveProxy", "cat": "代理",
     "proc": ["naiveproxy", "naive"],
     "iface": ["naive"],
     "ula": [], "mtu": None},
    {"name": "Surge (Mac)", "cat": "代理",
     "proc": ["surge"],
     "iface": ["surge"],
     "ula": [], "mtu": None},
    {"name": "Quantumult X (Mac)", "cat": "代理",
     "proc": ["quantumult"],
     "iface": ["quantumult"],
     "ula": [], "mtu": None},
    {"name": "Stash (Mac)", "cat": "代理",
     "proc": ["stash"],
     "iface": ["stash"],
     "ula": [], "mtu": None},
    {"name": "sing-box", "cat": "代理",
     "proc": ["sing-box", "singbox"],
     "iface": ["singbox", "sing-box"],
     "ula": [], "mtu": None},
    {"name": "V2rayN / NekoBox (Win)", "cat": "代理",
     "proc": ["v2rayn", "nekobox", "nekoray"],
     "iface": ["nekoray", "v2rayn"],
     "ula": [], "mtu": None},

    # ---- 游戏加速器 ----
    {"name": "雷神加速器", "cat": "加速器",
     "proc": ["leigod", "leigodhelper"],
     "iface": ["leigod"],
     "ula": [], "mtu": None},
    {"name": "网易UU加速器", "cat": "加速器",
     "proc": ["uu", "uubooster", "uuhelper", "netease uu"],
     "iface": ["uu"],
     "ula": [], "mtu": None},
    {"name": "迅游加速器", "cat": "加速器",
     "proc": ["xunyou", "xunyousdk", "xyagent"],
     "iface": ["xunyou"],
     "ula": [], "mtu": None},
    {"name": "奇游加速器", "cat": "加速器",
     "proc": ["qiyou", "qiyouvpn", "qiagent"],
     "iface": ["qiyou"],
     "ula": [], "mtu": None},
    {"name": "biubiu 加速器", "cat": "加速器",
     "proc": ["biubiu", "txacc"],
     "iface": ["biubiu"],
     "ula": [], "mtu": None},

    # ---- 覆盖网络 / 组网 ----
    {"name": "ZeroTier", "cat": "覆盖网络",
     "proc": ["zerotier-one", "zerotier"],
     "iface": ["feth", "zt", "zerotier"],
     "ula": [],
     "mtu": 2800},   # macOS feth<数字> MTU 2800 是 ZeroTier 的标志
    {"name": "Tailscale", "cat": "覆盖网络",
     "proc": ["tailscale", "tailscaled"],
     "iface": ["tailscale"],
     "ula": ["TAILSCALE", "ts"], "mtu": None},
    {"name": "Hamachi (LogMeIn)", "cat": "覆盖网络",
     "proc": ["hamachi", "hamachi-2"],
     "iface": ["ham"],
     "ula": [], "mtu": None},
    {"name": "Radmin VPN", "cat": "覆盖网络",
     "proc": ["rvpn", "radminvpn"],
     "iface": ["radmin"],
     "ula": [], "mtu": None},
    {"name": "蒲公英 / 组网宝", "cat": "覆盖网络",
     "proc": ["pgyvpn", "oray", "sunlogin", "pgyvnp"],
     "iface": ["pgy"],
     "ula": [], "mtu": None},

    # ---- 虚拟网卡（非隧道，单列） ----
    {"name": "VMware 虚拟网卡", "cat": "虚拟网卡",
     "proc": ["vmnet", "vmware"],
     "iface": ["vmnet"],
     "ula": [], "mtu": None},
    {"name": "VirtualBox 虚拟网卡", "cat": "虚拟网卡",
     "proc": ["vbox", "virtualbox"],
     "iface": ["vboxnet"],
     "ula": [], "mtu": None},
    {"name": "Docker 网桥", "cat": "虚拟网卡",
     "proc": ["dockerd", "com.docker"],
     "iface": ["docker", "bridge"],
     "ula": [], "mtu": None},
]

# 隧道接口命名规律（判定「这是隧道吗」）
TUNNEL_IFACE_RE = re.compile(
    r"^(utun|feth|tap|tun|ppp|ipsec|wg|ham|zt|vpn|cscotun)",
    re.I)
# 物理网卡命名规律（前半段是 macOS/Linux 的口径，后半段是 Windows 的网卡描述）
PHYS_IFACE_RE = re.compile(
    r"^(en\d|eth\d|wlan|wi-fi|wifi|wireless|以太网|本地连接|wlp\d|wl\d|enp\d|"
    r"Ethernet|Intel\(R\)|Realtek|Broadcom|Qualcomm)", re.I)
# macOS 系统自带虚拟接口（非业务隧道）
SYSTEM_IFACE_RE = re.compile(r"^(gif|stf|bridge|awdl|llw|anpi|ap\d|nan\d)", re.I)

# 私网/保留地址段 —— 绝不允许加直连路由（防 DNS 投毒把域名指向内网）
RESERVED_NETS = [
    ("0.0.0.0", 8), ("10.0.0.0", 8), ("100.64.0.0", 10),
    ("127.0.0.0", 8), ("169.254.0.0", 16), ("172.16.0.0", 12),
    ("192.0.0.0", 24), ("192.0.2.0", 24), ("192.31.196.0", 24),
    ("192.52.193.0", 24), ("192.88.99.0", 24), ("192.168.0.0", 16),
    ("198.18.0.0", 15), ("198.51.100.0", 24), ("203.0.113.0", 24),
    ("240.0.0.0", 4), ("255.255.255.255", 32),
]


def ip_to_int(ip):
    parts = ip.split(".")
    if len(parts) != 4:
        return None
    try:
        n = 0
        for p in parts:
            v = int(p)
            if v < 0 or v > 255:
                return None
            n = (n << 8) | v
        return n
    except ValueError:
        return None


def is_reserved_ip(ip):
    """是否私网/保留地址（防 DNS 投毒：绝不给内网 IP 加直连路由）。"""
    n = ip_to_int(ip)
    if n is None:
        return True
    for net, prefix in RESERVED_NETS:
        base = ip_to_int(net)
        mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
        if (n & mask) == (base & mask):
            return True
    return False


def is_public_ip(ip):
    return not is_reserved_ip(ip)


