#!/usr/bin/env python3
"""
Universal Tunnel Manager — 通用隧道识别与切换系统 v2
====================================================

跨平台（macOS / Windows / Linux），零依赖（Python 标准库）。

识别策略（四层证据融合，v2 核心升级）：
  0. 系统噪音过滤：只有 link-local IPv6（fe80::）且无 IPv4 的 utun → macOS 系统
     自带隧道（接力/隔空投送/通用控制），不是业务隧道。utun0-5 属此类。
  1. 进程证据：扫描正在运行的已知隧道软件进程。
  2. 接口证据：IPv4 有无 + 接口名/描述关键字 + MTU 特征（ZeroTier feth MTU 2800）
     + IPv6 ULA 前缀指纹（厂商把名字编进 fd 开头 ULA，如 SANGFOR）。
  3. 路由证据：默认路由承载者 + **聚合路由多点抽查**（aTrust 保留 default→物理网关，
     改用 1/8…240/4 聚合路由隐性接管公网，只看默认路由会漏判）。

切换策略：只加 /32 主机路由指向物理网关。不停止、不卸载任何客户端，state 文件精确回滚。

安全设计（v2 新增）：
  · CSRF 防护：校验 Origin 头 + 前端请求必须带 X-TM-Token（跨域简单请求带不了自定义头）
  · DNS 投毒防护：拒绝给私网/保留地址加直连路由（防恶意 DNS 把域名指向内网）
  · 命令注入防护：所有拼进 shell 的参数严格正则校验
  · Host 头校验：只接受 127.0.0.1/localhost 访问（防 DNS rebinding）
  · state 文件 600 权限；sudo 密码只存内存、不落盘不进日志
"""

import base64
import hashlib
import json
import os
import platform
import re
import secrets
import shutil
import socket
import sqlite3
import struct
import subprocess
import ssl
import sys
import tempfile
import threading
import time
import urllib.parse
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PLATFORM = platform.system()  # Darwin / Windows / Linux
IS_MAC = PLATFORM == "Darwin"
IS_WIN = PLATFORM == "Windows"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_DIR = os.path.expanduser("~/.tunnel-manager")
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.json")

PORT_PREFERENCE = [7531, 7532, 7533, 7530, 7800, 0]  # 0 = 系统分配

# ---- 监听地址 --------------------------------------------------------
# 只绑 127.0.0.1（仅本机可访问）。这是刻意的安全边界：本工具会改路由与 DNS，
# 暴露到局域网等于把「修改你网络配置」的能力交出去。
#
# 下面两个常量与 local_ipv4s() 是早期为「--lan 内网模式」预留的，**目前未接线**：
# host_allowed() / origin_allowed() 都只放行回环地址，绑定也写死 127.0.0.1。
# 保留仅为占位；若真要启用，必须同步改这两处校验与绑定地址，
# 并清楚这是把高权限能力开放给同局域网（属安全降级）。
ALLOW_LAN = ("--lan" in sys.argv) or (os.environ.get("TM_LAN") == "1")
LAN_PORT = None      # 预留：内网模式下实际使用的端口（当前未使用）


def local_ipv4s():
    """列出本机所有对内可用的 IPv4 地址（用于内网模式的 Host/Origin 白名单）。"""
    ips = set()
    try:
        # 主出口 IP（连一下公网地址，看系统选了哪块网卡）
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            ips.add(s.getsockname()[0])
    except OSError:
        pass
    try:
        import subprocess
        if IS_WIN:
            out = subprocess.run(["ipconfig"], capture_output=True, text=True,
                                 timeout=5, errors="ignore").stdout
            for m in re.finditer(r"IPv4[^:]*:\s*([0-9.]+)", out):
                ips.add(m.group(1))
        else:
            for name in os.listdir("/dev"):
                pass  # 占位：macOS 用下面的 ifconfig 取
            out = subprocess.run(["ifconfig"], capture_output=True, text=True,
                                 timeout=5, errors="ignore").stdout
            ips.update(re.findall(r"inet (\d+\.\d+\.\d+\.\d+)", out))
    except Exception:  # noqa: BLE001
        pass
    return {ip for ip in ips if not ip.startswith("127.")}


# 状态文件：必须放在**当前用户可写**的位置。
# 早期版本放在 /var/run（root 属主，普通用户写不进去）→ apply 加完路由后
# 写状态失败、又是静默吞异常，导致 undo 拿不到记录、按钮置灰，路由永久残留。
STATE_FILE = os.path.join(CONFIG_DIR, "state.json")
# 兼容旧版本写下的位置（只读，用于迁移）
LEGACY_STATE_FILE = "/var/run/tunnel-manager.state" if IS_MAC else None

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
# 物理网卡命名规律
PHYS_IFACE_RE = re.compile(
    r"^(en\d|eth\d|wlan|wi-fi|以太网|本地连接|wlp\d|wl\d|enp\d|Ethernet)", re.I)
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


# ======================================================================
# 二、通用工具
# ======================================================================

_sudo_pw = None
_lock = threading.Lock()
_csrf_token = secrets.token_hex(16)  # 进程级 CSRF token，前端必须回传


def run(cmd, timeout=30):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout, errors="replace")
        return p.returncode, p.stdout.strip(), p.stderr.strip()
    except (OSError, subprocess.SubprocessError) as e:
        return -1, "", str(e)


def run_ps(script, timeout=60):
    try:
        p = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive",
             "-Command", script],
            capture_output=True, text=True, timeout=timeout, errors="replace")
        return p.returncode, p.stdout.strip(), p.stderr.strip()
    except (OSError, subprocess.SubprocessError) as e:
        return -1, "", str(e)


def run_root(cmd_str, pw=None):
    if IS_WIN:
        return run_elevated_win(cmd_str)
    if os.geteuid() == 0:
        return run(["bash", "-c", cmd_str])
    password = pw if pw is not None else _sudo_pw
    if password is None:
        return 403, "", "NEED_SUDO"
    try:
        p = subprocess.run(["sudo", "-S", "-k", "bash", "-c", cmd_str],
                           input=password + "\n", capture_output=True,
                           text=True, timeout=120)
        if "Sorry, try again" in p.stderr:
            return 403, "", "BAD_PASSWORD"
        return p.returncode, p.stdout.strip(), p.stderr.strip()
    except (OSError, subprocess.SubprocessError) as e:
        return -1, "", str(e)


def run_elevated_win(cmd_str):
    import ctypes
    out_tmp = os.path.join(tempfile.gettempdir(),
                           f"tunmgr_out_{os.getpid()}.txt")
    if os.path.exists(out_tmp):
        os.remove(out_tmp)
    ps_script = (
        f"$ErrorActionPreference='Continue'\n"
        f"{cmd_str} *>&1 | Out-File -FilePath '{out_tmp}' -Encoding UTF8\n"
        f"\"RC:$LASTEXITCODE\" | Out-File -FilePath '{out_tmp}' "
        f"-Append -Encoding UTF8\n"
    )
    ps_file = os.path.join(tempfile.gettempdir(),
                           f"tunmgr_{os.getpid()}.ps1")
    with open(ps_file, "w", encoding="utf-8-sig") as f:
        f.write(ps_script)
    params = f'-NoProfile -ExecutionPolicy Bypass -File "{ps_file}"'
    try:
        rc = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", "powershell.exe", params, None, 0)
    except OSError as e:
        return -1, "", f"UAC 启动失败: {e}"
    if rc <= 32:
        return -1, "", "UAC 被取消或被拒绝"
    deadline = time.time() + 90
    content = ""
    while time.time() < deadline:
        time.sleep(0.4)
        try:
            with open(out_tmp, encoding="utf-8", errors="replace") as f:
                content = f.read()
        except OSError:
            continue
        m = re.search(r"RC:(-?\d+)\s*$", content)
        if m:
            body = content[:m.start()].rstrip()
            try:
                os.remove(ps_file)
                os.remove(out_tmp)
            except OSError:
                pass
            return int(m.group(1)), body, ""
    return -1, content, "UAC 执行超时"


def verify_sudo(password):
    global _sudo_pw
    if not password:
        return False, "空密码"
    try:
        p = subprocess.run(["sudo", "-S", "-v"], input=password + "\n",
                           capture_output=True, text=True, timeout=10)
        if p.returncode == 0 and "Sorry" not in p.stderr:
            with _lock:
                _sudo_pw = password
            return True, "ok"
        return False, "密码错误或被拒绝"
    except (OSError, subprocess.SubprocessError) as e:
        return False, str(e)


# ======================================================================
# 三、进程证据：谁在运行
# ======================================================================

def list_processes():
    """返回一个可搜索的进程名/命令行文本（全小写）。"""
    if IS_MAC:
        # ps 可能被沙箱拒，退路 pgrep -fl
        rc, out, _ = run(["ps", "axww", "-o", "command"])
        if rc != 0:
            rc2, out2, _ = run(["ps", "axco", "pid,comm"])
            out = out2 if rc2 == 0 else ""
        return out.lower()
    if IS_WIN:
        rc, out, _ = run_ps(
            "[Console]::OutputEncoding=[Text.Encoding]::UTF8;"
            "Get-Process | Select-Object -ExpandProperty Name"
        )
        return out.lower()
    rc, out, _ = run(["ps", "auxww"])
    return out.lower()


def detect_software(procs_blob):
    """在进程列表里搜已知隧道软件，返回命中的软件信息列表。"""
    seen = {}
    for sw in TUNNEL_KNOWLEDGE:
        for kw in sw["proc"]:
            if kw.lower() in procs_blob:
                seen.setdefault(sw["name"], sw)
                break
    return list(seen.values())


# ======================================================================
# 四、接口证据：扫网卡（v2：收集 IPv4/IPv6-ULA/MTU 三项特征）
# ======================================================================

def is_tunnel_iface(name, desc=""):
    blob = (name + " " + desc).lower()
    if TUNNEL_IFACE_RE.match(name):
        return True
    return any(k in blob for k in ("tap-", "tun-", "virtual adapter",
                                   "virtual ethernet", "虚拟网卡"))


def is_phys_iface(name, desc=""):
    return bool(PHYS_IFACE_RE.match(name))


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


# ======================================================================
# 五、路由证据（v2：加聚合路由多点抽查）
# ======================================================================

# 公网多点探测目标 —— 覆盖各聚合路由段（1/8…240/4），
# 用来抓「默认路由正常但聚合路由隐性接管」的隧道
PROBE_TARGETS = [
    "0.1.1.1", "1.1.1.1", "8.8.8.8", "20.20.20.20", "48.48.48.48",
    "96.96.96.96", "128.0.0.1", "160.0.0.1", "176.0.0.1",
    "200.0.0.1", "208.0.0.1", "240.0.0.1",
]


def default_route_mac():
    rc, out, _ = run(["route", "-n", "get", "default"])
    iface = gw = ""
    if rc == 0:
        m = re.search(r"interface:\s*(\S+)", out)
        if m:
            iface = m.group(1)
        m = re.search(r"gateway:\s*(\S+)", out)
        if m:
            gw = m.group(1)
    return iface, gw


def iface_of_mac(ip):
    rc, out, _ = run(["route", "-n", "get", ip])
    if rc != 0:
        return ""
    m = re.search(r"interface:\s*(\S+)", out)
    return m.group(1) if m else ""


def phys_gateway_mac(phys_iface):
    rc, out, _ = run(["ipconfig", "getoption", phys_iface, "router"])
    if rc == 0 and re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", out.strip()):
        return out.strip()
    _, _, gw = default_route_mac()
    return gw


def probe_egress_mac():
    """多点抽查公网出口，返回 {接口: 命中点数}。"""
    counts = {}
    for t in PROBE_TARGETS:
        i = iface_of_mac(t)
        if i:
            counts[i] = counts.get(i, 0) + 1
    return counts


def win_snapshot():
    rc, out, _ = run_ps(
        "[Console]::OutputEncoding=[Text.Encoding]::UTF8;"
        "try { [PSCustomObject]@{"
        "routes = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | "
        "Select InterfaceAlias,NextHop,InterfaceMetric) } | "
        "ConvertTo-Json -Depth 4 } catch {}"
    )
    if rc != 0 or not out:
        return {}
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return {}


def default_route_win(snap):
    for r in snap.get("routes", []):
        alias = r.get("InterfaceAlias", "")
        if not is_tunnel_iface(alias, ""):
            return alias, r.get("NextHop", "")
    routes = snap.get("routes", [])
    if routes:
        return routes[0].get("InterfaceAlias", ""), routes[0].get("NextHop", "")
    return "", ""


def iface_of_win_batch(ips):
    if not ips:
        return {}
    ip_list = ",".join(f"'{i}'" for i in ips)
    rc, out, _ = run_ps(
        "[Console]::OutputEncoding=[Text.Encoding]::UTF8;"
        f"$ips = @({ip_list});"
        "foreach ($i in $ips) {"
        "  $r = Find-NetRoute -DestinationIPAddress $i "
        "-ErrorAction SilentlyContinue | Select-Object -First 1;"
        "  [PSCustomObject]@{ ip = $i; iface = $r.InterfaceAlias }"
        "} | ConvertTo-Json"
    )
    result = {}
    if rc != 0 or not out:
        return result
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return result
    if isinstance(data, dict):
        data = [data]
    for row in data:
        result[row.get("ip", "")] = row.get("iface", "") or ""
    return result


# ======================================================================
# 六、配置
# ======================================================================

# 默认目标域名：几个通用示例站点。
# 用途：页面「目标域名的路由走向」表里默认展示这些站走直连还是走隧道。
# 可在页面上自由增删，配置存 ~/.tunnel-manager/config.json。
# 请把它换成你自己常访问、且希望「走物理直连」的站点（学校/单位的门户、教务、图书馆等）。
DEFAULT_DOMAINS = [
    # 常见网站
    "www.baidu.com", "www.bing.com", "github.com", "www.zhihu.com",
    # 注意：**不要把 VPN 客户端「自身服务器」的域名放进来** —— 例如某些校内 VPN 的
    # vpn.<学校域名> 解析到的正是客户端自己的外层传输服务器，让本工具去托管它的
    # 保活通路既无意义也有风险（见 EXCLUDED 机制）。
]


def load_config():
    try:
        with open(CONFIG_FILE, encoding="utf-8") as f:
            cfg = json.load(f)
        domains = cfg.get("domains") or []
        if domains:
            return domains
    except (OSError, json.JSONDecodeError):
        pass
    return list(DEFAULT_DOMAINS)


def save_config(domains):
    os.makedirs(CONFIG_DIR, exist_ok=True)
    cleaned = []
    for d in domains:
        d = (d or "").strip().lower()
        if d and d not in cleaned:
            cleaned.append(d)
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump({"domains": cleaned}, f, ensure_ascii=False, indent=2)
    return cleaned


_dns_cache = {}          # domain -> (expire_ts, [ips])
DNS_TTL = 60             # 秒。扫描一次会用到两遍解析结果，加缓存避免重复查 DNS


def resolve_a(domain):
    """解析 A 记录，只返回公网 IP（私网/保留地址一律剔除，防 DNS 投毒）。"""
    now = time.time()
    hit = _dns_cache.get(domain)
    if hit and hit[0] > now:
        return hit[1]
    try:
        _, _, ips = socket.gethostbyname_ex(domain)
    except (socket.gaierror, OSError):
        _dns_cache[domain] = (now + DNS_TTL, [])
        return []
    out = []
    for ip in ips:
        if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", ip) and is_public_ip(ip):
            out.append(ip)
    _dns_cache[domain] = (now + DNS_TTL, out)
    return out


# ======================================================================
# 六.5 自动追踪：浏览器新开的网站
# ======================================================================
# 原理：每 30 秒扫一次各浏览器的历史记录库（只读，SQLite），
#   · 最近 AUTO_WINDOW 秒内访问过的新域名 → 自动加入「目标域名」
#   · 超过 AUTO_EXPIRE 秒没再访问的自动域名 → 自动移除
#   实测 Chrome / Edge / Firefox / Safari 的历史库都能读到，Safari 需要完全磁盘访问权限。

AUTO_WINDOW = 180    # 最近 3 分钟内访问过 = 「正在看」
AUTO_EXPIRE = 600    # 10 分钟没再看 = 「关了」，移除
AUTO_INTERVAL = 30   # 扫描周期

_auto_domains = {}          # {domain: last_seen_timestamp}
_auto_lock = threading.Lock()
_auto_thread = None
_auto_enabled = True        # 前端可开关


def _chrome_history_paths():
    """Chrome / Edge / Brave 的 History 库路径（含所有 Profile）。"""
    home = os.path.expanduser("~")
    bases = [
        os.path.join(home, "Library/Application Support/Google/Chrome"),
        os.path.join(home, "Library/Application Support/Microsoft Edge"),
        os.path.join(home, "Library/Application Support/BraveSoftware/Brave-Browser"),
        os.path.join(home, ".config/google-chrome"),
        os.path.join(home, ".config/microsoft-edge"),
        os.path.join(os.environ.get("LOCALAPPDATA", ""), "Google/Chrome/User Data"),
        os.path.join(os.environ.get("LOCALAPPDATA", ""), "Microsoft/Edge/User Data"),
    ]
    paths = []
    for b in bases:
        try:
            if not os.path.isdir(b):
                continue
            for prof in os.listdir(b):
                if prof.startswith("Profile") or prof == "Default":
                    p = os.path.join(b, prof, "History")
                    if os.path.isfile(p):
                        paths.append(p)
        except OSError:
            continue
    return paths


def _firefox_history_paths():
    home = os.path.expanduser("~")
    base = os.path.join(home, "Library/Application Support/Firefox/Profiles")
    if not os.path.isdir(base):
        base = os.path.join(home, ".mozilla/firefox")
    paths = []
    if os.path.isdir(base):
        for prof in os.listdir(base):
            p = os.path.join(base, prof, "places.sqlite")
            if os.path.isfile(p):
                paths.append(p)
    return paths


def _safari_history_path():
    p = os.path.expanduser("~/Library/Safari/History.db")
    return p if os.path.isfile(p) else None


def _extract_domain(url):
    """从 URL 提取主域名：去 scheme/path，去掉 www. 前缀。"""
    if not url:
        return None
    m = re.match(r"^[a-zA-Z]+://", url)
    rest = url[m.end():] if m else url
    host = rest.split("/")[0].split("?")[0].split(":")[0]
    host = host.lower().strip(".")
    if not host or not "." in host:
        return None
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):  # 裸 IP 不要
        return None
    if host.endswith((".local", ".internal", ".localhost")):
        return None
    if host.startswith("www."):
        host = host[4:]
    return host


def _scan_history_once():
    """扫一遍所有浏览器历史库，返回 {domain: last_visit_timestamp}。"""
    import sqlite3
    now = time.time()
    found = {}

    def merge(dom, ts):
        if dom and ts:
            prev = found.get(dom, 0)
            if ts > prev:
                found[dom] = ts

    # Chrome / Edge / Brave：last_visit_time 是 1601 起的微秒
    EPOCH_1601 = 11644473600
    for p in _chrome_history_paths():
        try:
            tmp = None
            # Chrome 运行时库被锁，复制一份再读
            import tempfile as _tf
            tmp = _tf.NamedTemporaryFile(suffix=".db", delete=False)
            tmp.close()
            shutil_copy = None
            import shutil as _sh
            _sh.copyfile(p, tmp.name)
            con = sqlite3.connect(f"file:{tmp.name}?mode=ro", uri=True)
            try:
                for url, t in con.execute(
                        "SELECT url, last_visit_time FROM urls "
                        "ORDER BY last_visit_time DESC LIMIT 200"):
                    ts = t / 1_000_000 - EPOCH_1601 if t else 0
                    merge(_extract_domain(url), ts)
            finally:
                con.close()
                os.unlink(tmp.name)
        except (OSError, sqlite3.Error):
            pass

    # Firefox：visit_date 是 1970 起的微秒
    for p in _firefox_history_paths():
        try:
            con = sqlite3.connect(f"file:{p}?mode=ro", uri=True)
            try:
                for url, t in con.execute(
                        "SELECT url, visit_date FROM moz_places, moz_historyvisits "
                        "WHERE moz_places.id = moz_historyvisits.place_id "
                        "ORDER BY visit_date DESC LIMIT 200"):
                    merge(_extract_domain(url), (t or 0) / 1_000_000)
            finally:
                con.close()
        except (OSError, sqlite3.Error):
            pass

    # Safari：visit_time 是 2001 起的秒（Cocoa epoch）
    p = _safari_history_path()
    if p:
        try:
            con = sqlite3.connect(f"file:{p}?mode=ro", uri=True)
            try:
                for url, t in con.execute(
                        "SELECT url, visit_time FROM history_items, history_visits "
                        "WHERE history_items.id = history_visits.history_item "
                        "ORDER BY visit_time DESC LIMIT 200"):
                    merge(_extract_domain(url), (t or 0) + 978307200)
            finally:
                con.close()
        except (OSError, sqlite3.Error):
            pass

    return {d: t for d, t in found.items() if t > 0}


def auto_domains_loop():
    """后台循环：把最近访问的新域名纳入追踪，过期的移除。"""
    while True:
        try:
            if _auto_enabled:
                now = time.time()
                fresh = _scan_history_once()
                with _auto_lock:
                    # 新访问的：在窗口期内
                    for dom, ts in fresh.items():
                        if now - ts <= AUTO_WINDOW:
                            _auto_domains[dom] = ts
                    # 过期清理：超过 AUTO_EXPIRE 没再访问的移除
                    expired = [d for d, ts in _auto_domains.items()
                               if now - ts > AUTO_EXPIRE]
                    for d in expired:
                        _auto_domains.pop(d, None)
        except Exception:  # noqa: BLE001
            pass
        time.sleep(AUTO_INTERVAL)


def start_auto_tracker():
    """在 HTTP 服务启动时一起拉起后台追踪线程。"""
    global _auto_thread
    if _auto_thread and _auto_thread.is_alive():
        return
    _auto_thread = threading.Thread(target=auto_domains_loop, daemon=True)
    _auto_thread.start()


def get_auto_domains():
    """返回当前自动追踪到的域名（按最近访问排序）。"""
    with _auto_lock:
        return [d for d, _ in sorted(_auto_domains.items(),
                                     key=lambda kv: -kv[1])]


def toggle_auto_tracker(enabled):
    global _auto_enabled
    _auto_enabled = bool(enabled)


def auto_tracker_enabled():
    return _auto_enabled


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


# ======================================================================
# 八·五、情景判定（游戏模式 / 校内模式 / 直连）
# ======================================================================

SCENES = {
    "game":    {"name": "游戏模式", "desc": "加速器独占出口（Steam 等游戏走专线）"},
    "campus":  {"name": "校内模式", "desc": "aTrust 独占出口（校园资源、文献、数据库）"},
    "direct":  {"name": "直连模式", "desc": "无隧道接管，全部走物理宽带"},
    "tunnel":  {"name": "隧道接管", "desc": "有隧道接口在承载公网（归属未识别）"},
    "mixed":   {"name": "多出口冲突", "desc": "多个隧道客户端同时接管公网，可能互相踩死"},
    "unknown": {"name": "未知", "desc": ""},
}

# 能当「出口」用的类别（覆盖网络、虚拟网卡不是出口，只做识别不参与切换）
OUTLET_CATS = ("企业VPN", "开源VPN", "系统VPN", "代理", "加速器")

KNOWN_OWNER_NAMES = {k["name"] for k in TUNNEL_KNOWLEDGE}


def _owner_scene(owner):
    """把隧道归属映射到情景。不认识的一律 'other'（不参与情景判定）。"""
    o = owner or ""
    low = o.lower()
    if "atrust" in low or "深信服" in o or "sangfor" in low:
        return "campus"
    if "雷神" in o or "leigod" in low:
        return "game"
    if "网易uu" in o or "uubooster" in low or "uu加速" in o:
        return "game"
    return "other"


def _iface_owners(res):
    """算出每个隧道接口的归属：{iface: {"owner": str, "guessed": bool}}。

    为什么需要「猜」：实测在 macOS 上**拿不到 TUN 接口的厂商信息**——
    `lsof | grep utun` 看不到、`ifconfig` 没有 description、
    `system_profiler SPNetworkDataType` 也不列 utun。
    而 Clash / sing-box / 雷神这类客户端建的接口**全都叫 utunN**，名字毫无特征。
    所以只能退而求其次：用「谁在跑」反推，并且**只在证据唯一时才认领**，
    认不出来就如实标成未识别 —— 宁可显示「未识别」也不要瞎指一个。
    """
    ifaces = res.get("interfaces") or []
    software = [s["name"] for s in (res.get("running_software") or [])]

    owners, claimed, ghosts = {}, set(), []

    # ① 最高优先级：已确认过的指纹。
    #    **按「路由特征」匹配，而不是按接口名** —— 这点很关键：
    #    接口名 utunN 每次重连/重启都可能换号（雷神这次是 utun6，下次可能就是 utun8），
    #    但客户端加的那组路由（雷神固定是 1/2/4/8/16/32/64/128 那八条拆分，
    #    aTrust 是 198.18.0.0/24 + 198.18.255.0/24 + 128.0/3…）才是它的"签名"。
    #    按签名认，换多少次接口号都认得出来。
    fps = load_fingerprints()
    cur_routes = _routes_snapshot()
    for key, fp in fps.items():
        want = set(fp.get("routes") or [])
        if want:
            hit_ifaces = {i for (d, i) in cur_routes if d in want}
            if len(hit_ifaces) == 1:
                owners[hit_ifaces.pop()] = {"owner": key, "guessed": False,
                                            "from": "fingerprint-route"}
                claimed.add(key)
                continue
        for name in fp.get("ifaces") or []:
            if name not in owners:
                owners[name] = {"owner": key, "guessed": False,
                                "from": "fingerprint-iface"}
                claimed.add(key)

    for i in ifaces:
        if i.get("kind") != "隧道":
            continue
        name = i["name"]
        if name in owners:
            continue                       # 指纹已经认领
        own = i.get("owner") or ""
        if own in KNOWN_OWNER_NAMES:
            owners[name] = {"owner": own, "guessed": False}
            claimed.add(own)
        elif i.get("ipv4"):
            ghosts.append(name)          # 有 IPv4 但认不出厂商的隧道接口

    outlet_names = {k["name"] for k in TUNNEL_KNOWLEDGE if k.get("cat") in OUTLET_CATS}
    loose = [s for s in software if s in outlet_names and s not in claimed]

    if len(ghosts) == 1 and len(loose) == 1:
        owners[ghosts[0]] = {"owner": loose[0], "guessed": True}
    else:
        for g in ghosts:
            owners[g] = {"owner": "", "guessed": True}
    return owners


def detect_scene(res):
    """判定当前出口情景。

    「谁在承载公网」= 多点抽查（egress_counts）里命中公网探测点的**隧道**接口。
    只有隧道接口才算——物理网卡命中是正常现象；系统隧道 / ZeroTier 之类不承载公网，
    用 _owner_scene 归为 other 后排除。

    返回 {key, name, desc, directors, egress, main_egress}
    """
    if not isinstance(res, dict) or res.get("error"):
        return {"key": "unknown", "name": SCENES["unknown"]["name"],
                "desc": "", "directors": [], "egress": {}, "main_egress": ""}

    egress = res.get("egress_counts") or {}
    owners = _iface_owners(res)

    carriers = {}   # iface -> (scene, hits, owner)
    for name, hits in egress.items():
        try:
            hits = int(hits)
        except (TypeError, ValueError):
            continue
        if hits <= 0:
            continue
        info = owners.get(name)
        if info is None:
            continue                       # 物理网卡 / 回环 / 系统隧道
        own = info["owner"]
        sc = _owner_scene(own) if own else "tunnel"
        if sc == "other":
            continue                       # 系统隧道等，不参与
        carriers[name] = (sc, hits, own)

    if not carriers:
        key, directors = "direct", []
    else:
        scenes = {v[0] for v in carriers.values()}
        if len(scenes) == 1:
            key = scenes.pop()
        elif scenes - {"tunnel"}:
            key = "mixed"
        else:
            key = "tunnel"
        directors = sorted(
            ({"iface": k, "owner": v[2] or "（归属未识别）", "hits": v[1],
              "scene": v[0], "guessed": (owners.get(k) or {}).get("guessed", False)}
             for k, v in carriers.items()),
            key=lambda x: -x["hits"])

    info = SCENES.get(key, SCENES["unknown"])
    return {
        "key": key, "name": info["name"], "desc": info["desc"],
        "directors": directors, "egress": egress,
        "main_egress": res.get("main_egress") or "",
    }


# ======================================================================
# 八·六、情景切换（游戏模式 ⇄ 校内模式）
# ======================================================================
#
# 为什么是「半自动」：实测雷神与 aTrust 都是「拆分整段公网」的全量接管，
# 同时开必然在同一张路由表里争夺最长前缀 → 只能二选一（PLAN 路线 E）。
# 但两件事脚本做不到：
#   1) 雷神的「开始/停止加速」只在它自己的 GUI 里（helper 的 127.0.0.1:10908
#      WebSocket 控制口协议尚未还原）；
#   2) aTrust 重新拉起后需要用户登录。
# 所以工具负责「可自动的那半」：停对家、清残留、校验；GUI 那半交给用户。

ATRUST_JOBS = [
    "system/com.sangfor.aTrustTunnelWatchDog",   # 必须先停守卫：KeepAlive 会把隧道拉回来
    "system/com.sangfor.aTrustTunnel",
    "system/com.sangfor.aTrustDaemon",
]
ATRUST_PLISTS = [
    "/Library/LaunchDaemons/com.sangfor.aTrustDaemon.plist",
    "/Library/LaunchDaemons/com.sangfor.aTrustTunnel.plist",
    "/Library/LaunchDaemons/com.sangfor.aTrustTunnelWatchDog.plist",
]


def _sh(cmd, timeout=20):
    """跑一条只读命令，返回 stdout。"""
    try:
        p = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True,
                           errors="replace", timeout=timeout)
        return p.stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def active_ifaces():
    return set(_sh("ifconfig -l").split())


def atrust_up():
    """aTrust 是否还在承载隧道（接口存在，或路由表里还有指向 utun7 的条目）。"""
    ifs = active_ifaces()
    if "utun7" in ifs:
        return True
    nets = _sh("netstat -rn -f inet | awk '{print $4}' | sort -u")
    return "utun7" in nets.split()


def scene_steps(target):
    """从任意当前态切到 target 的步骤清单（mode: auto 工具做 / manual 用户做）。"""
    if target == "game":
        return [
            {"key": "stop_atrust", "desc": "完全退出 aTrust", "mode": "auto",
             "detail": "按 WatchDog → Tunnel → Daemon 顺序 bootout 三个守护作业"},
            {"key": "clean_routes", "desc": "清理残留路由", "mode": "auto",
             "detail": "删掉指向已消失接口的条目，避免流量被黑洞"},
            {"key": "start_leigod", "desc": "在雷神加速器里点「开始加速」", "mode": "manual",
             "detail": "加速开关只在它的 GUI 里（本地控制口协议尚未还原）"},
            {"key": "verify", "desc": "校验出口是否已切到加速器", "mode": "verify",
             "detail": "切完后重新扫描，看情景是否变成「游戏模式」"},
        ]
    if target == "campus":
        return [
            {"key": "stop_leigod", "desc": "在雷神加速器里点「停止加速」", "mode": "manual",
             "detail": "同上，需要在其 GUI 操作"},
            {"key": "clean_routes", "desc": "清理残留路由", "mode": "auto",
             "detail": "删掉指向已消失接口的条目"},
            {"key": "start_atrust", "desc": "拉起 aTrust", "mode": "auto",
             "detail": "bootstrap 回三个守护作业并打开 App"},
            {"key": "login_atrust", "desc": "在 aTrust 里完成登录", "mode": "manual",
             "detail": "重新拉起后通常需要重新登录，约 10~30 秒"},
            {"key": "verify", "desc": "校验出口是否已切到 aTrust", "mode": "verify",
             "detail": "切完后重新扫描，看情景是否变成「校内模式」"},
        ]
    return []


def _del_route_cmd(dest):
    if "/" in dest:
        net, _slash, bits = dest.partition("/")
        if bits == "32":
            return f"route -n delete -host {net}"
        return f"route -n delete -net {dest}"
    return f"route -n delete -host {dest}"


def clean_residual_routes(pw=None):
    """删掉指向「已不存在的接口」的路由。返回 (条数, 说明)。"""
    if not IS_MAC:
        return 0, "仅 macOS 支持"
    valid = active_ifaces()
    stale = []
    for line in _sh("netstat -rn -f inet").splitlines():
        p = line.split()
        if len(p) < 4:
            continue
        dest, netif = p[0], p[3]
        if netif.startswith(("utun", "feth", "tun", "tap", "ppp")) and netif not in valid:
            stale.append(dest)
    stale = sorted(set(stale), key=lambda d: -len(d))
    if not stale:
        return 0, "无残留路由"
    cmd = " ; ".join(_del_route_cmd(d) for d in stale)
    rc, _out, _err = run_root(cmd, pw)
    if rc == 403:
        return 0, "NEED_SUDO"
    return len(stale), f"已清理 {len(stale)} 条（{', '.join(stale[:6])}）"


def do_scene(target, pw=None):
    """执行情景切换里「可自动」的部分。
    返回 {ok, target, done, manual, message}；不需要的步骤不会出现。
    """
    if not IS_MAC:
        return {"ok": False, "target": target, "done": [], "manual": [],
                "message": "情景切换当前仅支持 macOS"}
    if target not in ("game", "campus"):
        return {"ok": False, "target": target, "done": [], "manual": [],
                "message": f"未知情景：{target}"}

    done, manual, need_sudo = [], [], False

    if target == "game":
        if atrust_up():
            cmds = " ; ".join(f"launchctl bootout {j}" for j in ATRUST_JOBS)
            rc, _o, _e = run_root(cmds, pw)
            if rc == 403:
                need_sudo = True
                done.append({"key": "stop_atrust", "ok": False,
                             "detail": "需要管理员密码才能停 aTrust"})
            else:
                done.append({"key": "stop_atrust", "ok": True,
                             "detail": "已 bootout 3 个守护作业"})
        else:
            done.append({"key": "stop_atrust", "ok": True,
                         "detail": "aTrust 本来就没在跑"})
    else:
        cmds = " ; ".join(
            f"launchctl bootstrap system {p} 2>/dev/null || true" for p in ATRUST_PLISTS)
        rc, _o, _e = run_root(cmds, pw)
        if rc == 403:
            need_sudo = True
            done.append({"key": "start_atrust", "ok": False,
                         "detail": "需要管理员密码才能拉起 aTrust"})
        else:
            _sh('open -a "aTrust"')
            done.append({"key": "start_atrust", "ok": True,
                         "detail": "已恢复守护作业并打开 App"})

    if not need_sudo:
        _n, msg = clean_residual_routes(pw)
        if msg == "NEED_SUDO":
            need_sudo = True
            done.append({"key": "clean_routes", "ok": False, "detail": "需要管理员密码"})
        else:
            done.append({"key": "clean_routes", "ok": True, "detail": msg})

    for s in scene_steps(target):
        if s["mode"] in ("manual", "verify"):
            manual.append({"key": s["key"], "desc": s["desc"],
                           "detail": s["detail"], "mode": s["mode"]})

    if need_sudo:
        msg = "需要管理员密码才能完成自动步骤"
    elif manual:
        msg = "自动步骤已完成，请继续完成下面的手动步骤"
    else:
        msg = "切换完成"
    return {"ok": not need_sudo, "target": target, "done": done,
            "manual": manual, "message": msg}


# ======================================================================
# 八·七、通用出口管理（Outlet）—— 不为 35 种客户端手写适配
# ======================================================================
#
# 把「切换」抽象成「选一个出口」：物理直连 / 某个隧道客户端 / 某个系统 VPN。
# 关键设计：**不去为每种客户端写死适配**，而是自动探测三个「可控点」——
#   1) 装没装 .app         → 能 `open -a` 启动
#   2) 有没有 launchd 作业  → 能 `bootout` 停 / `bootstrap` 启
#   3) 有没有系统 VPN 配置  → `scutil --nc start/stop`（不需要 root）
# 三个都没有就退化为「引导用户手点」（manual）。
#
# 实测归属：aTrust → launchd(2)；ZeroTier → app+launchd(1,2)；
# 雷神 / 网易UU → 只有 app(1)，但加速开关在 App 内部 ⇒ 实际是 manual。

DIRECT_OUTLET = "__direct__"

# 「关闭方式」显式表 —— 只给少数需要特判的客户端配，其余走自动探测。
#
# 为什么雷神 / UU 必须是 manual：它们的 `com.leigod.helper` / `com.netease.uumac.helper`
# 是**引擎本体**、KeepAlive 常驻 —— 停掉它等于把整个加速器搞坏，而不是「停止加速」；
# 而真正的加速开关只在 App 内部（PLAN §2.5.3 也记了这条）。
# aTrust 则相反：它有三个**专门承载隧道**的守护作业，bootout 掉才是正确的「完全退出」。
OUTLET_RULES = {
    "aTrust (深信服零信任)": {
        "stop_jobs": [
            "system/com.sangfor.aTrustTunnelWatchDog",   # 必须先停：它是 KeepAlive，会立刻把隧道拉回来
            "system/com.sangfor.aTrustTunnel",
            "system/com.sangfor.aTrustDaemon",
        ],
        "start_plists": [
            "/Library/LaunchDaemons/com.sangfor.aTrustDaemon.plist",
            "/Library/LaunchDaemons/com.sangfor.aTrustTunnel.plist",
            "/Library/LaunchDaemons/com.sangfor.aTrustTunnelWatchDog.plist",
        ],
    },
    "雷神加速器": {"mode": "manual",
                 "reason": "helper 是引擎本体、常驻，不能停；加速开关只在它 App 内"},
    "网易UU加速器": {"mode": "manual",
                    "reason": "helper 是常驻服务；加速开关只在它 App 内"},
    "迅游加速器": {"mode": "manual", "reason": "加速开关只在它 App 内"},
    "奇游加速器": {"mode": "manual", "reason": "加速开关只在它 App 内"},
    "biubiu 加速器": {"mode": "manual", "reason": "加速开关只在它 App 内"},
}

# 这些作业名一看就是「看护 / 资源 / 卸载」类，不是承载隧道的服务 —— 自动模式下不动它们
_JOB_NOISE = re.compile(
    r"helper|uninstall|monitor|limit|maxfiles|crashpad|update|telemetry", re.I)


def _stoppable(jobs):
    """从自动探测到的作业里，挑出真能用来关闭出口的那些。"""
    return [j for j in jobs if not _JOB_NOISE.search(j["label"])]


# 「上次切到哪个出口」的记忆。
# 为什么需要：TUN 接口认不出归属（见 _iface_owners 的说明），纯靠系统探测
# 无法回答「我现在用的到底是哪个」。所以在用户点过切换之后记下来，
# 界面就能显示得准 —— 并且明确标注这是「你上次切的」，不是我们猜出来的。
ACTIVE_FILE = os.path.join(CONFIG_DIR, "active_outlet.json")
ACTIVE_TTL = 3600


def remember_outlet(key):
    try:
        os.makedirs(CONFIG_DIR, exist_ok=True)
        with open(ACTIVE_FILE, "w", encoding="utf-8") as f:
            json.dump({"key": key, "ts": time.time()}, f)
    except OSError:
        pass


def remembered_outlet():
    try:
        with open(ACTIVE_FILE, encoding="utf-8") as f:
            d = json.load(f)
        if time.time() - float(d.get("ts") or 0) < ACTIVE_TTL:
            return d.get("key")
    except (OSError, ValueError, TypeError):
        pass
    return None


def forget_active_outlet():
    """抹掉「上次切到哪个出口」这笔记录（界面上的「取消这次切换」用它）。"""
    try:
        os.remove(ACTIVE_FILE)
        return True
    except OSError:
        return False


def _kb_keywords(entry):
    kws = list(entry.get("proc") or []) + list(entry.get("iface") or [])
    return sorted({k.lower() for k in kws if k})


def _find_apps(keywords):
    """在系统与应用目录里找匹配的 .app。"""
    hits = []
    for base in ("/Applications", os.path.expanduser("~/Applications")):
        try:
            for n in sorted(os.listdir(base)):
                if n.endswith(".app") and any(k in n.lower() for k in keywords):
                    hits.append(os.path.join(base, n))
        except OSError:
            pass
    return hits


def _find_launchd(keywords):
    """找标签匹配的 launchd 作业。返回 (daemons, agents)。"""
    daemons, agents = [], []
    home = os.path.expanduser("~")
    for d, bucket, domain in (
            ("/Library/LaunchDaemons", daemons, "system"),
            ("/Library/LaunchAgents", agents, f"gui/{os.getuid()}"),
            (os.path.join(home, "Library/LaunchAgents"), agents, f"gui/{os.getuid()}")):
        try:
            for n in sorted(os.listdir(d)):
                if n.endswith(".plist") and any(k in n.lower() for k in keywords):
                    bucket.append({"label": n[:-6], "plist": os.path.join(d, n),
                                   "domain": domain})
        except OSError:
            pass
    return daemons, agents


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
        apps = _find_apps(kws)
        daemons, agents = _find_launchd(kws)
        owned, carrying = _outlet_ifaces(entry["name"], ifaces, egress, owners)
        installed = bool(apps or daemons or agents)
        if not installed and not owned:
            continue                       # 本机没装也没跑 → 不进列表

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

        bits = [_app_name(a) for a in apps] + [j["label"] for j in daemons + agents]
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


def outlet_stop(key, pw=None, res=None):
    """停掉一个出口。返回 (ok, message)；message 为 NEED_SUDO 表示缺密码。"""
    o = _outlet_by_key(key, res)
    if not o:
        return False, f"未知出口：{key}"
    ad = o["adapter"]
    if ad["kind"] == "direct":
        return False, "「物理直连」不是一个可停止的客户端"

    jobs = ad.get("stop_jobs") or []
    if not jobs:
        return False, (f"{o['name']} 没有可自动关闭的守护作业"
                       f"（{o.get('hint') or '需要手动操作'}）")
    cmd = " ; ".join(f"launchctl bootout {j} 2>/dev/null || true" for j in jobs)
    rc, _o, _e = run_root(cmd, pw)
    if rc == 403:
        return False, "NEED_SUDO"
    return True, f"已停止 {o['name']}（bootout {len(jobs)} 个作业）"


def outlet_start(key, pw=None, res=None):
    """启动一个出口。"""
    o = _outlet_by_key(key, res)
    if not o:
        return False, f"未知出口：{key}"
    ad = o["adapter"]
    if ad["kind"] == "direct":
        return True, "物理直连无需启动"

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
    if not IS_MAC:
        return {"ok": False, "target": key, "done": [], "manual": [],
                "message": "出口切换当前仅支持 macOS"}

    done, manual, need_sudo = [], [], False

    for o in outlets:
        if o["key"] == key or not o.get("in_use"):
            continue
        ok, msg = outlet_stop(o["key"], pw, res)
        if msg == "NEED_SUDO":
            need_sudo = True
            done.append({"name": o["name"], "action": "stop", "ok": False,
                         "detail": "需要管理员密码"})
            continue
        done.append({"name": o["name"], "action": "stop", "ok": ok, "detail": msg})
        if not ok:
            manual.append(f"手动关闭「{o['name']}」：{msg}")

    if not need_sudo and target["key"] != DIRECT_OUTLET:
        ok, msg = outlet_start(key, pw, res)
        if msg == "NEED_SUDO":
            need_sudo = True
        done.append({"name": target["name"], "action": "start", "ok": ok,
                     "detail": msg})
        if not ok:
            manual.append(f"手动开启「{target['name']}」：{msg}")

    if not need_sudo:
        n, cmsg = clean_residual_routes(pw)
        if cmsg == "NEED_SUDO":
            need_sudo = True
        elif n:
            done.append({"name": "残留路由", "action": "clean", "ok": True,
                         "detail": cmsg})

    if target["key"] == DIRECT_OUTLET:
        manual.append("若仍有加速器在自行接管流量，请在它的界面里关掉加速")

    if need_sudo:
        msg = "需要管理员密码才能完成自动步骤"
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
    if not IS_MAC:
        return {"ok": False, "message": "归属确认当前仅支持 macOS"}
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

    mid_r, mid_i = _routes_snapshot(), _ifaces_snapshot()

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
    rc, out, _ = run(["ipconfig", "getoption", iface, "domain_name_server"])
    if rc != 0 or not out.strip():
        return []
    return [x.strip() for x in re.split(r"[,\s]+", out.strip()) if x.strip()]


def system_dns_servers():
    """当前系统实际生效的 DNS（只看主解析器，避免把 VPN 推送的一堆都算进来）。"""
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
    def_iface, def_gw = default_route_mac()
    phys = def_iface if is_phys_iface(def_iface) else ""
    if not phys:
        for _ip, n in sorted(local_addr_map().items()):
            if is_phys_iface(n):
                phys = n
                break
    return phys, (def_gw if phys == def_iface else (phys_gateway_mac(phys) if phys else def_gw))


def quick_egress(res):
    """轻量版「声明 vs 实测」：只做 UDP 选路（不发包、微秒级），可随每次扫描跑。"""
    if not IS_MAC:
        return []
    am = local_addr_map(res.get("interfaces"))
    rows = []
    for label, ip in TRUTH_TARGETS[:4]:
        decl = iface_of_mac(ip)
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
    if not IS_MAC:
        return {"error": f"暂仅支持 macOS（当前 {PLATFORM}）"}

    t0 = time.time()
    phys, phys_gw = phys_iface_guess()
    def_iface, def_gw = default_route_mac()
    dhcp = dhcp_dns(phys)
    cur_dns = system_dns_servers()
    query_dns = ipv4_dns_servers(cur_dns) or ["223.5.5.5"]   # 直查只用 IPv4

    # ---- 面板 1：路由（声明 vs 实测）----
    # 用固定 IP 而不是域名 —— 这样即使 DNS 已经挂了，这一栏照样能出结论
    am = local_addr_map()
    hops = parallel_map(first_hop, [ip for _l, ip in TRUTH_TARGETS], workers=6)
    routes = []
    for (label, ip), hop in zip(TRUTH_TARGETS, hops):
        hop = hop or ""                          # 实测：TTL=1 逼出来的第一跳
        decl = iface_of_mac(ip)                  # 声明：路由表怎么写的
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
    for line in _sh("netstat -rn -f inet").splitlines():
        p = line.split()
        if len(p) < 4 or "/" not in p[0]:
            continue
        if re.match(r"^(198\.1[89]\.|100\.6[4-9]\.|240\.0\.0\.)", p[0].split("/")[0]):
            found.append(p[0])
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


def do_rescue(pw=None):
    """一键应急恢复：把路由与 DNS 救回「本机直连」的干净状态。

    设计原则：
      · 只做「恢复」不做「优化」—— 目标是让网络回到能用，不是变快
      · 每步都记 before/after 并落 rescue.log，事后能审计、能对照
      · 不做不可逆的事（不删配置、不动 hosts、不卸软件）
    """
    if not IS_MAC:
        return {"ok": False, "message": f"暂仅支持 macOS（当前 {PLATFORM}）"}

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


# ======================================================================
# 八·八、Steam 体检（平台网 / 游戏联机网 / 内容分发网）
# ======================================================================
# Steam 不是一个网络，而是三张互不相干的网，三项需求各对应一张：
#   ① 平台网    登录 / 好友 / 商店   WebSocket 443     → CM 集群（hkg1 / tyo3 / sgp1…）
#   ② 游戏联机网 中继转发            UDP 27015-27060   → SDR 中继（hkg / sgp / tyo…）
#   ③ 内容分发网 商店 / 下载         HTTP 80 / 443     → 由 CellID 决定的 CDN
# 它们**可以分别走不同出口**（有的走物理、有的被加速器拽走），所以必须分开观测。
#
# 设计原则（与「七·五 真实流量体检」一脉相承）：
#   · 只观测「事实」，不读「声明」；全程只读 —— 不改路由、不启停客户端、不写系统配置。
#   · 外部数据源（官方 API / 本地日志）失败一律降级，绝不让服务起不来。
#   · **绝不伪造测速**：Steam 的 depot 文件需要 depot key，CDN 根路径只回 302/403，
#     公开拿不到「确定大小的文件」→ 真速度只能靠 nettop 边下边测；
#     主动探测只做 TCP 握手 RTT，并如实标注口径。
#   · ICMP RTT 只是「网络层参考值」，不得当成游戏内看到的延迟。
#
# ★ 一条决定性的定性结论（本机 2026-10-05 实测）：
#   杀戮尖塔 2（appid 2868840）走的是 Steam Datagram Relay，**不是双方 P2P 直连**。
#   官方 GetSDRConfig 对它返回 36 个 pop（hkg 香港 tier=0 有 10 个 relay、sgp、tyo…）。
#   → 加速器对 SDR 无益甚至有害（SDR 已是 Valve 优化过的骨干，再套一层隧道 = 多一跳 + MTU 变小）。
#   这是整个诊断规则库里最重要的一条。

STEAM_API = "https://api.steampowered.com"
STEAM_CDN_CELL = 46                 # 本机实测 config.vdf 的 CellIDServerOverride
STEAM_APP_FALLBACK = 2868840        # 杀戮尖塔 2（本机已装；认不出在跑的游戏时兜底）
STEAM_LOG_TAIL = 256 * 1024         # 日志只读尾部 256KB（connection_log 会长到几 MB）

# 商店 / 社区 / API —— 「连接方式是直连还是加速器」的观测对象
STEAM_STORE_DOMAINS = ["store.steampowered.com", "api.steampowered.com",
                       "steamcommunity.com", "login.steampowered.com"]

# 中国大陆附近、与国内玩家相关的 SDR pop（探测时优先看这几个）
STEAM_NEAR_POPS = ("hkg", "sgp", "tyo", "seo", "gum", "bom2", "maa2")

# pop key → 中文地名（SDR pop 是 hkg / tyo3 这种简写）
STEAM_POP_NAMES = {
    "hkg": "香港", "sgp": "新加坡", "tyo": "东京", "tyo1": "东京",
    "tyo2": "东京", "tyo3": "东京", "seo": "首尔", "seo1": "首尔",
    "gum": "关岛", "bom2": "孟买", "maa2": "金奈", "hkg1": "香港", "sgp1": "新加坡",
    "lax": "洛杉矶", "lax1": "洛杉矶", "sea": "西雅图", "sea1": "西雅图",
    "dfw": "达拉斯", "dfw2": "达拉斯", "ord": "芝加哥", "iad": "弗吉尼亚",
    "atl": "亚特兰大", "atl3": "亚特兰大", "fra": "法兰克福", "fra1": "法兰克福",
    "fra2": "法兰克福", "dfra": "法兰克福", "ams": "阿姆斯特丹", "par": "巴黎",
    "lhr": "伦敦", "lhr1": "伦敦", "dlhr": "伦敦", "mad": "马德里",
    "sto": "斯德哥尔摩", "sto2": "斯德哥尔摩", "dsto": "斯德哥尔摩",
    "waw": "华沙", "waw1": "华沙", "vie": "维也纳", "dvie": "维也纳",
    "dxb": "迪拜", "syd": "悉尼", "gru": "圣保罗", "eze": "布宜诺斯艾利斯",
    "scl": "圣地亚哥", "lim": "利马", "jnb": "约翰内斯堡", "eat": "韦纳奇",
    "fsn": "法尔肯施泰因", "hel": "赫尔辛基",
}


# ----------------------------------------------------------------------
# Steam 目录与文件定位（跨平台）
# ----------------------------------------------------------------------

def steam_dirs():
    """按平台列出 Steam 根目录候选。用户级安装优先于全局安装。"""
    home = os.path.expanduser("~")
    if IS_MAC:
        return [os.path.join(home, "Library", "Application Support", "Steam")]
    if IS_WIN:
        cands = []
        for env in ("PROGRAMFILES(X86)", "PROGRAMFILES"):
            base = os.environ.get(env)
            if base:
                cands.append(os.path.join(base, "Steam"))
        cands.append(os.path.join(os.environ.get("LOCALAPPDATA") or home, "Steam"))
        return cands
    return [os.path.join(home, ".steam", "steam"),
            os.path.join(home, ".local", "share", "Steam")]


def steam_root():
    for d in steam_dirs():
        if d and os.path.isdir(d):
            return d
    return ""


def steam_path(*parts):
    root = steam_root()
    return os.path.join(root, *parts) if root else ""


def read_tail(path, nbytes=STEAM_LOG_TAIL):
    """只读文件尾部。

    connection_log.txt 会长到几 MB 且持续增长，**绝不能全文读**；
    而且我们只关心「最近一次连接」，尾部足够。任何异常都返回空串，由调用方降级。
    """
    if not path:
        return ""
    try:
        size = os.path.getsize(path)
    except OSError:
        return ""
    try:
        with open(path, "rb") as f:
            if size > nbytes:
                f.seek(-nbytes, os.SEEK_END)
            data = f.read()
    except OSError:
        return ""
    return data.decode("utf-8", errors="replace")


def _vdf_get(text, key):
    """VDF 就是嵌套的 `"键"  "值"` 文本，取第一个匹配即可。"""
    m = re.search(r'"' + re.escape(key) + r'"\s+"([^"]*)"', text or "")
    return m.group(1) if m else ""


# ----------------------------------------------------------------------
# 官方 API（标准库直连，失败一律降级返回 None）
# ----------------------------------------------------------------------

_steam_api_cache = {}       # url -> (expire_ts, data)


def _proxy_for(scheme):
    """标准代理环境变量。

    用户本机通常**没有**这些变量（macOS 系统代理为空就走直连，行为和以前完全一样）；
    但在公司代理后面，或被别的沙箱套住时，它们会存在 —— 这时必须走代理，
    否则所有官方接口都会静默超时。任何失败都只是降级，不影响主功能。
    """
    for k in (f"{scheme}_proxy", f"{scheme.upper()}_PROXY",
              "all_proxy", "ALL_PROXY"):
        v = os.environ.get(k)
        if v:
            return v
    return ""


def _connect_via_proxy(proxy_url, host, port, timeout):
    """给 http 代理发 CONNECT 建隧道，返回裸 socket（失败返回 None）。"""
    try:
        p = urllib.parse.urlsplit(proxy_url if "://" in proxy_url
                                 else "http://" + proxy_url)
        phost, pport = p.hostname, p.port or 80
        if not phost:
            return None
        raw = socket.create_connection((phost, pport), timeout=timeout)
        auth = ""
        if p.username:
            tok = base64.b64encode(
                f"{p.username}:{p.password or ''}".encode()).decode()
            auth = f"Proxy-Authorization: Basic {tok}\r\n"
        raw.sendall((f"CONNECT {host}:{port} HTTP/1.1\r\n"
                     f"Host: {host}:{port}\r\n{auth}\r\n").encode())
        raw.settimeout(timeout)
        head = b""
        while b"\r\n\r\n" not in head and len(head) < 8192:
            chunk = raw.recv(1024)
            if not chunk:
                break
            head += chunk
        if b" 200 " not in head.split(b"\r\n", 1)[0]:
            raw.close()
            return None
        return raw
    except OSError:
        return None


def http_get_json(url, timeout=6):
    """标准库 HTTPS/HTTP GET → JSON。

    三个刻意的设计：

    1. **自己解析地址、逐个 IPv4 尝试**，不用 urllib.request。本机是双栈，
       urllib 会先试 IPv6；到 api.steampowered.com 的 IPv6 路径常不通，
       一次 timeout 就把整个请求吃掉（实测 8 秒后直接失败，而 curl 因为有
       happy-eyeballs 自动回落 IPv4，所以看不出问题）。
    2. **尊重 https_proxy 等标准代理环境变量**（见 _proxy_for）。用户本机通常没有
       这些变量，那就是直连，行为与以前完全一致。
    3. **总时间有预算**：多个地址共享 timeout（而不是每个地址都等一次 timeout），
       否则一个不可达的域名能耗掉几十秒，把体检按钮卡死。

    任何失败都返回 None，由调用方降级并如实报告，绝不冒泡。
    """
    sock = None
    try:
        parts = urllib.parse.urlsplit(url)
        host = parts.hostname
        if not host:
            return None
        https = parts.scheme != "http"
        port = parts.port or (443 if https else 80)
        path = (parts.path or "/") + (("?" + parts.query) if parts.query else "")

        raw = None
        proxy = _proxy_for("https" if https else "http")
        if proxy and https:
            raw = _connect_via_proxy(proxy, host, port, min(timeout, 5))
        if raw is None:
            try:
                infos = socket.getaddrinfo(host, port, socket.AF_INET,
                                           socket.SOCK_STREAM)
            except OSError:
                return None
            if not infos:
                return None
            per = max(1.5, timeout / len(infos))     # 共享预算，不逐个吃满 timeout
            for _f, _t, _p, _c, sa in infos:
                try:
                    raw = socket.create_connection(sa, timeout=per)
                    break
                except OSError:
                    if raw:
                        raw.close()
                    raw = None
        if raw is None:
            return None
        sock = ssl.create_default_context().wrap_socket(raw, server_hostname=host) \
            if https else raw
        sock.settimeout(timeout)
        req = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
               "User-Agent: UniversalTunnelManager\r\n"
               "Accept: application/json\r\nConnection: close\r\n\r\n")
        sock.sendall(req.encode("ascii", errors="replace"))
        buf = b""
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            buf += chunk
            if len(buf) > 4_000_000:
                break
        head, _sep, body = buf.partition(b"\r\n\r\n")
        status_line = head.split(b"\r\n", 1)[0]
        if b" 200 " not in status_line:
            return None
        if b"chunked" in head.lower():
            body = _dechunk(body)
        return json.loads(body.decode("utf-8", errors="replace"))
    except Exception:       # noqa: BLE001 —— 网络问题一律降级，不冒泡
        return None
    finally:
        if sock:
            try:
                sock.close()
            except OSError:
                pass


def _dechunk(body):
    """HTTP/1.1 chunked 解码（Steam 有些接口会用它）。"""
    out, i = b"", 0
    while True:
        j = body.find(b"\r\n", i)
        if j < 0:
            break
        try:
            size = int(body[i:j].split(b";")[0], 16)
        except ValueError:
            break
        if size <= 0:
            break
        out += body[j + 2:j + 2 + size]
        i = j + 2 + size + 2
    return out or body


_api_fail_until = 0.0       # 官方接口失败后的冷却期（熔断）


def steam_api_json(url, ttl=900):
    """带「进程内缓存 + TTL + 失败熔断」的 GET。拿不到就返回 None，调用方如实报告。

    熔断的意义：这条网络一旦暂时到不了 Steam 的服务器，一次失败后 3 分钟内的
    后续请求直接快速返回 None，而不是每个接口都再等一次超时 ——
    否则「体检」按钮会从十几秒变成四十多秒。
    """
    global _api_fail_until
    now = time.time()
    hit = _steam_api_cache.get(url)
    if hit and hit[0] > now:
        return hit[1]
    if now < _api_fail_until:
        return None
    data = http_get_json(url)
    if data is None:
        _api_fail_until = now + 180
    else:
        _steam_api_cache[url] = (now + ttl, data)
        _api_fail_until = 0.0
    return data


# ----------------------------------------------------------------------
# 基本事实：装没装 / 在不在跑 / 日志在哪 / 下载区域
# ----------------------------------------------------------------------

def steam_cell_id():
    """下载区域 ID：优先用户手动设的 CellIDServerOverride，其次 CellID。"""
    txt = read_tail(steam_path("config", "config.vdf"), 512 * 1024)
    for key, src in (("CellIDServerOverride", "override"), ("CellID", "auto")):
        v = _vdf_get(txt, key)
        if v.isdigit() and int(v) > 0:
            return int(v), src
    return STEAM_CDN_CELL, "default"


def steam_installed_apps():
    """steamapps 下的 appmanifest —— 用来把「在跑的游戏目录名」对回 appid。"""
    d = steam_path("steamapps")
    out = []
    if not d or not os.path.isdir(d):
        return out
    try:
        names = os.listdir(d)
    except OSError:
        return out
    for n in names:
        m = re.match(r"appmanifest_(\d+)\.acf$", n)
        if not m:
            continue
        txt = read_tail(os.path.join(d, n), 32768)
        out.append({
            "appid": m.group(1),
            "name": _vdf_get(txt, "name"),
            "size": int(_vdf_get(txt, "SizeOnDisk") or 0),
            "state": int(_vdf_get(txt, "StateFlags") or 0),
        })
    return out


def steam_running_game():
    """「正在跑的游戏」= 命令行里带 `steamapps/common/` 的进程。

    比 console_log.txt 的 `Game process added` 更可靠 —— 后者会记到
    Remote Play 的 streaming_client（appid 202355）上，容易张冠李戴。
    """
    if not IS_MAC:
        return {}
    out = _sh("ps axww -o pid=,command= 2>/dev/null", timeout=15)
    found = {}
    for line in out.splitlines():
        if "steamapps/common/" not in line:
            continue
        m = re.match(r"\s*(\d+)\s+(.*)", line)
        if not m:
            continue
        pid, cmd = m.group(1), m.group(2).strip()
        tail = cmd.split("steamapps/common/", 1)[1]
        app_dir = tail.split("/", 1)[0] if tail else ""
        exe = os.path.basename(cmd.split(" ")[0]) if cmd else ""
        found = {"pid": pid, "app_dir": app_dir, "exe": exe, "cmd": cmd[:240]}
    return found


def pid_alive(pid):
    if not pid or not str(pid).isdigit():
        return False
    rc, out, _err = run(["ps", "-p", str(pid), "-o", "pid="])
    return rc == 0 and out.strip() != ""


def steam_env():
    """Steam 的安装 / 运行 / 日志 / 账号 / 下载区域 —— 拿不到的项如实标空，不猜。"""
    root = steam_root()
    blobs = list_processes()
    if IS_WIN:
        running = "steam.exe" in blobs or "steamwebhelper" in blobs
    else:
        running = ("steam_osx" in blobs) or ("steamwebhelper" in blobs) \
            or ("steam" in blobs.split())
    logs = os.path.join(root, "logs") if root else ""
    files = {}
    for n in ("connection_log.txt", "console_log.txt", "content_log.txt",
              "connection_log_27015.txt"):
        p = os.path.join(logs, n) if logs else ""
        if p and os.path.isfile(p):
            try:
                files[n] = {"path": p, "size": os.path.getsize(p),
                            "mtime": os.path.getmtime(p)}
            except OSError:
                pass

    steamid, persona = "", ""
    lu = steam_path("config", "loginusers.vdf")
    if lu and os.path.isfile(lu):
        txt = read_tail(lu, 65536)
        m = re.search(r'"(7656119\d{10})"', txt)
        if m:
            steamid = m.group(1)
        m2 = re.search(r'"PersonaName"\s+"([^"]*)"', txt)
        if m2:
            persona = m2.group(1)

    cell, cell_src = steam_cell_id()
    game = steam_running_game()
    apps = steam_installed_apps()
    appid, app_name = "", ""
    if game:
        for a in apps:
            if a["name"] and a["name"] == game.get("app_dir"):
                appid, app_name = a["appid"], a["name"]
                break
    return {
        "installed": bool(root),
        "root": root,
        "running": bool(running),
        "logs": files,
        "sdr_cache": steam_path("appcache", "sdr_config.txt"),
        "steamid": steamid,
        "persona": persona,
        "cell_id": cell, "cell_src": cell_src,
        "running_game": game,
        "game_appid": appid,
        "game_name": app_name,
        "installed_apps": apps,
    }


def steam_guess_appid(env=None):
    """优先「正在跑的游戏」，其次 console_log，最后兜底常量。"""
    env = env or steam_env()
    if env.get("game_appid"):
        return env["game_appid"], env.get("game_name") or ""
    cl = parse_steam_console_log()
    if cl.get("appid") and cl.get("appid") != "202355":     # 202355 = Remote Play 客户端
        return cl["appid"], ""
    return str(STEAM_APP_FALLBACK), ""


# ----------------------------------------------------------------------
# 观测原语（复用七·五那套：真解析 / 真连接 / 真看第一跳）
# ----------------------------------------------------------------------

_PING_RTT_RE = re.compile(r"time[=<]\s*([0-9.]+)\s*ms")


def icmp_probe(ip, wait_ms=400, timeout=1):
    """ICMP 探一次，返回 (是否收到回包, RTT ms)。

    ⚠ 这只是**网络层参考值**：SDR 走 UDP 且有自己的握手与加密，
    ICMP 通不通不等于游戏通不通 —— 界面上必须如实标注，不得冒充游戏延迟。
    超时给得很短（1 秒）：批量探十几个中继时，每个都等几秒会把体检拖到一分钟。
    """
    if not ip or not re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", ip):
        return False, None
    if not IS_MAC:
        return False, None
    out = _sh(f"ping -c 1 -W {wait_ms} -t {timeout} {ip} 2>&1", timeout=timeout + 2)
    m = _PING_RTT_RE.search(out)
    if m:
        return True, round(float(m.group(1)), 1)
    return False, None


def steam_path_of(ip, am=None, phys_gw="", want_hop=False):
    """一个目标 IP 的「声明 vs 实际」：路由表怎么写的 / 内核实际选了哪个源地址（/ 第一跳）。

    want_hop 默认关：ping 一次要等超时，批量探测几十个目标时会拖到几十秒。
    只对少数「结论最依赖它」的目标（商店域名）才开。
    """
    am = local_addr_map() if am is None else am
    src = src_addr_for(ip)
    sif = am.get(src, "")
    decl = iface_of_mac(ip)
    hop = first_hop(ip) if (want_hop and IS_MAC) else ""

    tun = bool(sif and is_tunnel_iface(sif)) or bool(decl and is_tunnel_iface(decl))
    phi = bool(hop and phys_gw and hop == phys_gw) or bool(sif and is_phys_iface(sif))
    if phi and tun:
        via = "隧道声明 · 物理实际（不一致）"
    elif tun:
        via = "隧道接管"
    elif phi:
        via = "物理直连"
    else:
        via = sif or "未知"
    return {
        "ip": ip, "declared_iface": decl, "src_ip": src, "src_iface": sif,
        "first_hop": hop, "is_tunnel": tun, "is_phys": phi, "via": via,
        "mismatch": bool(decl and sif and decl != sif),
    }


def probe_host(host, port=443, am=None, phys_gw="", want_hop=False):
    """真解析 + 真连一次（TCP 握手 RTT）+ 看它走哪条路。"""
    row = {"host": host, "port": port, "ips": [], "resolve_ms": None,
           "resolve_error": "", "tcp_ok": False, "tcp_ms": None,
           "src_ip": "", "src_iface": "", "declared_iface": "", "first_hop": "",
           "is_tunnel": False, "is_phys": False, "mismatch": False, "via": ""}
    ips, rms, rerr = sys_resolve(host)
    row["ips"], row["resolve_ms"], row["resolve_error"] = ips, rms, rerr
    if not ips:
        row["via"] = "解析失败"
        return row
    ip = ips[0]
    ok, tcp_ms, src = tcp_probe(ip, port, timeout=3)
    if not ok:
        # 443 不通时退一步试 80 —— 「连不上」本身也是有用的事实，但要尽量拿到 RTT
        ok2, tcp_ms2, src2 = tcp_probe(ip, 80, timeout=2)
        if ok2:
            row["port_fallback"] = 80
            ok, tcp_ms, src = ok2, tcp_ms2, src2
    row["tcp_ok"], row["tcp_ms"], row["src_ip"] = ok, tcp_ms, src
    am = local_addr_map() if am is None else am
    iface = am.get(src, "")
    decl = iface_of_mac(ip)
    hop = first_hop(ip) if (want_hop and IS_MAC) else ""
    row.update({"src_iface": iface, "declared_iface": decl, "first_hop": hop})
    tun = bool(iface and is_tunnel_iface(iface)) or bool(decl and is_tunnel_iface(decl))
    phi = bool(hop and phys_gw and hop == phys_gw) or bool(iface and is_phys_iface(iface))
    row["is_tunnel"], row["is_phys"] = tun, phi
    row["mismatch"] = bool(decl and iface and decl != iface)
    if phi and tun:
        row["via"] = "隧道声明 · 物理实际（不一致）"
    elif tun:
        row["via"] = "隧道接管"
    elif phi:
        row["via"] = "物理直连"
    else:
        row["via"] = iface or "未知"
    return row


# ----------------------------------------------------------------------
# 日志解析：Steam 自己写的「事实」
# ----------------------------------------------------------------------

_STEAM_CM_MS_RE = re.compile(
    r"\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\].*?"
    r"PingWebSocketCM\(\)\s*\(([^\s:()]+):(\d+)\)\s*results:\s*([0-9.]+)ms")
_STEAM_CONN_RE = re.compile(
    r"\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\].*?"
    r"ConnectionCompleted\(\)\s*\((\d+\.\d+\.\d+\.\d+):(\d+),\s*([^)]*)\)\s*"
    r"local address\s*\(([^:()]+):(\d+)\)")
_STEAM_EXT_RE = re.compile(r"external address\s*=\s*'([^']+)'")
_STEAM_CM_HOST_RE = re.compile(r"cmp\d+-([a-z]+\d?)\.steamserver\.net")


def parse_steam_conn_log():
    """解析 connection_log.txt 尾部。

    这里记着「连到哪个 Steam 服务器」和「用了哪个本地地址」——
    **本地地址就是「走没走加速器」的铁证**（172.21.0.2 = 加速器隧道；192.168.x.x = 物理网卡），
    是 Steam 自己写的，不需要抓包。
    """
    p = steam_path("logs", "connection_log.txt")
    row = {"ok": False, "error": "", "path": p, "cm": [], "latest": [],
           "external_ip": "", "at": "", "mtime": None}
    if not p or not os.path.isfile(p):
        row["error"] = "找不到 connection_log.txt（Steam 可能从未运行过）"
        return row
    try:
        row["mtime"] = os.path.getmtime(p)
    except OSError:
        pass
    txt = read_tail(p, STEAM_LOG_TAIL)
    if not txt:
        row["error"] = "日志读不到（权限或文件被占用）"
        return row
    row["ok"] = True

    cm = {}
    latest = []
    for line in txt.splitlines():
        m = _STEAM_CM_MS_RE.search(line)
        if m:
            at, host, port, ms = m.group(1), m.group(2), m.group(3), float(m.group(4))
            mm = _STEAM_CM_HOST_RE.search(host)
            dc = mm.group(1) if mm else host.split(".")[0]
            prev = cm.get(dc)
            if not prev or at >= prev["at"]:
                cm[dc] = {"dc": dc, "dc_cn": STEAM_POP_NAMES.get(dc, ""),
                          "host": host, "port": port,
                          "ms": round(ms, 1), "at": at}
            row["at"] = max(row["at"], at)
            continue
        m = _STEAM_CONN_RE.search(line)
        if m:
            at, ip, port, proto, laddr, lport = m.groups()
            latest.append({"at": at, "server_ip": ip, "server_port": port,
                           "proto": proto.strip(), "local_ip": laddr,
                           "local_port": lport})
            row["at"] = max(row["at"], at)
            continue
        m = _STEAM_EXT_RE.search(line)
        if m:
            row["external_ip"] = m.group(1)

    row["cm"] = sorted(cm.values(), key=lambda x: x["ms"])
    row["latest"] = latest[-8:]
    if not row["cm"] and not row["latest"]:
        row["error"] = "日志尾部没有可解析的连接记录（格式可能与预期不同）"
    return row


_STEAM_GAME_EVT_RE = re.compile(
    r"\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\]\s*Game process (added|removed)")


def _local_ip_verdict(ip, am=None):
    """本地地址 → (接口, 结论)。这是「走没走加速器」的判定核心。

    注意：connection_log 里 UDP 那条记的可能是 `0.0.0.0`（当时还没绑定本地地址），
    这时必须如实说「未知」，不能猜成物理网卡。
    """
    if not ip or ip in ("0.0.0.0", "::", "*"):
        return "", "未知"
    am = local_addr_map() if am is None else am
    iface = am.get(ip, "")
    if iface and is_tunnel_iface(iface):
        return iface, "隧道（加速已生效）"
    if iface and is_phys_iface(iface):
        return iface, "物理网卡（没走加速）"
    if iface:
        return iface, "其他接口"
    return "", "认不出的接口"


def annotate_conn_rows(rows):
    """给「最近连接」逐条标上本地地址属于哪个接口、以及结论。"""
    am = local_addr_map()
    for r in (rows or []):
        iface, verdict = _local_ip_verdict(r.get("local_ip"), am)
        r["local_iface"], r["verdict"] = iface, verdict
    return rows


def parse_steam_console_log():
    """console_log.txt：游戏进程的启停与启动参数（含 `--relay IP:port`）。"""
    p = steam_path("logs", "console_log.txt")
    row = {"ok": False, "error": "", "path": p, "events": [], "restarts": 0,
           "relay": "", "last_at": "", "running": False}
    if not p or not os.path.isfile(p):
        row["error"] = "找不到 console_log.txt"
        return row
    txt = read_tail(p, STEAM_LOG_TAIL)
    if not txt:
        row["error"] = "日志读不到"
        return row
    row["ok"] = True
    evts, relay, last_at = [], "", ""
    for line in txt.splitlines():
        m = _STEAM_GAME_EVT_RE.search(line)
        if m:
            evts.append({"at": m.group(1), "act": m.group(2)})
            last_at = m.group(1)
        mr = re.search(r"--relay\s+(\d+\.\d+\.\d+\.\d+):(\d+)", line)
        if mr:
            relay = f"{mr.group(1)}:{mr.group(2)}"
    row["events"] = evts[-40:]
    row["restarts"] = sum(1 for e in evts if e["act"] == "added")
    # 只看最近 24 小时 —— 不然会把历史累积的启动次数误读成「现在在反复重连」
    cutoff = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time() - 86400))
    row["restarts_24h"] = sum(1 for e in evts
                              if e["act"] == "added" and e["at"] >= cutoff)
    row["relay"] = relay
    row["last_at"] = last_at
    row["running"] = bool(evts and evts[-1]["act"] == "added")
    return row


# ----------------------------------------------------------------------
# SDR 中继：这个游戏实际会用到哪些中继点
# ----------------------------------------------------------------------

def _read_local_sdr():
    """Steam 客户端自己缓存的 appcache/sdr_config.txt —— 离线可用。"""
    p = steam_path("appcache", "sdr_config.txt")
    txt = read_tail(p, 512 * 1024) if p else ""
    if not txt:
        return {}, None
    i = txt.find("{")
    if i < 0:
        return {}, None
    try:
        d = json.loads(txt[i:])
    except ValueError:
        return {}, None
    pops = d.get("pops")
    return (pops if isinstance(pops, dict) else {}), d.get("revision")


def steam_sdr_pops(appid, prefer_online=False):
    """返回 (pops, meta)。

    数据源优先级：本地缓存（快、离线）→ 官方 GetSDRConfig（权威、按 appid）。
    两个都拿不到时如实返回空 + 原因，绝不编造。
    """
    if not prefer_online:
        local, rev = _read_local_sdr()
        if local:
            return local, {"source": "local", "revision": rev, "error": ""}
    d = steam_api_json(
        f"{STEAM_API}/ISteamApps/GetSDRConfig/v1/?appid={appid}&format=json", ttl=1800)
    if isinstance(d, dict) and d.get("pops"):
        return d["pops"], {"source": "online", "revision": d.get("revision"), "error": ""}
    local, rev = _read_local_sdr()          # 在线失败再兜一次本地
    if local:
        return local, {"source": "local", "revision": rev,
                       "error": "官方接口不可达，已降级用本地缓存"}
    return {}, {"source": "", "revision": None,
                "error": "拿不到 SDR 配置（本地缓存缺失，且官方接口不可达）"}


def sdr_relay_targets(pops, limit=24):
    """从 pop 表抽出「优先探测」的中继 IP（近的先来）。"""
    out = []
    order = [k for k in STEAM_NEAR_POPS if k in (pops or {})]
    order += [k for k in sorted(pops or {}) if k not in order]
    for k in order:
        v = pops.get(k) or {}
        for r in (v.get("relays") or []):
            ip = r.get("ipv4")
            if not ip:
                continue
            pr = r.get("port_range") or []
            out.append({
                "pop": k, "pop_cn": STEAM_POP_NAMES.get(k, ""),
                "desc": v.get("desc") or "", "tier": v.get("tier"),
                "ip": ip, "port": (pr[0] if pr else None),
            })
            if len(out) >= limit:
                return out
    return out


def cm_targets(cell_id, limit=10):
    """CM 集群（平台网，登录/好友/商店走的那条）。"""
    url = (f"{STEAM_API}/ISteamDirectory/GetCMListForConnect/v1/"
           f"?cellid={cell_id}&qoslevel=2&format=json")
    d = steam_api_json(url, ttl=900)
    rows = ((d or {}).get("response") or {}).get("serverlist") or []
    best = {}
    for s in rows:
        ep = s.get("endpoint") or ""
        dc = s.get("dc") or ""
        if not ep or not dc:
            continue
        cur = best.get(dc)
        load = s.get("wtd_load") or s.get("load") or 0
        if not cur or load < cur["_load"]:
            host, _, port = ep.partition(":")
            best[dc] = {"dc": dc, "dc_cn": STEAM_POP_NAMES.get(dc, ""),
                        "host": host, "port": port or "443", "_load": load}
    out = sorted(best.values(), key=lambda x: x["_load"])
    for r in out:
        r.pop("_load", None)
    return out[:limit]


# ----------------------------------------------------------------------
# 内容分发网：下载主机 + 连接方式
# ----------------------------------------------------------------------

def steam_cdn_servers(cell_id):
    """官方接口：这个 CellID 下「现在会用」的下载主机。"""
    url = (f"{STEAM_API}/IContentServerDirectoryService/GetServersForSteamPipe/v1/"
           f"?cell_id={cell_id}&max_servers=20&format=json")
    d = steam_api_json(url, ttl=1800)
    out, seen = [], set()
    for s in ((d or {}).get("response") or {}).get("servers") or []:
        h = (s.get("host") or s.get("vhost") or "").strip()
        if h and h not in seen:
            seen.add(h)
            out.append({"host": h, "source": "api", "type": s.get("type") or "",
                        "load": s.get("load"), "wtd_load": s.get("weighted_load"),
                        "client_list": s.get("num_entries_in_client_list")})
    return out


_CDN_HOST_RE = re.compile(r"https?://([a-zA-Z0-9._-]+\.(?:com|net|cn|org))/")


def steam_cdn_history():
    """content_log.txt 里**真的用过**的下载主机 —— 比任何猜测都准。"""
    txt = read_tail(steam_path("logs", "content_log.txt"), 512 * 1024)
    seen = {}
    for m in _CDN_HOST_RE.finditer(txt):
        h = m.group(1).lower()
        seen[h] = seen.get(h, 0) + 1
    return [{"host": h, "hits": n, "source": "history"}
            for h, n in sorted(seen.items(), key=lambda x: -x[1])[:10]]


# ----------------------------------------------------------------------
# 逐进程采样（nettop）—— 真速度只能这么测
# ----------------------------------------------------------------------

_CAP_LOCK = threading.Lock()
_CAP = {
    "running": False, "done": False, "seconds": 0, "elapsed": 0,
    "target": "", "target_kind": "", "pid": "", "samples": [], "frames": 0,
    "peers": [], "error": "", "started_at": 0.0, "finished_at": 0.0,
    "interrupted": False,
}
_CAP_MAX = 300
_CAP_PROC = {"p": None}     # 正在跑的 nettop 进程句柄（capture_stop 用）


def _parse_nettop_line(line):
    """解析 nettop 输出的一行 → (进程名.pid, 四个累计计数)；表头行返回 (None, None)。

    两个实测结论决定了这里的写法：

    1. `nettop` 给的是**累计值**（进程启动以来的总量），所以速率必须靠相邻两帧差分；
    2. `nettop` **单次调用有约 5 秒固定开销**（要重新枚举所有进程）。因此采样绝不能
       「每秒起一个新进程」—— 那样 60 秒的采样会变成五分钟。正确做法是起一个进程，
       用 `-l N -s 1` 让它自己连续采（见 _cap_loop）。

    进程名可能带空格（如 `Steam Helper.1040`），所以从行尾往左取数字，剩下才是名字。
    """
    if not line or line[0] in " \t":
        return None, None           # 表头行 = 新一帧的开始
    parts = line.rstrip().split()
    nums = []
    while parts and re.fullmatch(r"-?\d+", parts[-1]):
        nums.insert(0, int(parts.pop()))
    name = " ".join(parts).strip()
    if not name or not re.search(r"\.\d+$", name):
        return None, None           # 脏行
    return name, {
        "bytes_in": nums[0] if len(nums) > 0 else 0,
        "bytes_out": nums[1] if len(nums) > 1 else 0,
        "rx_ooo": nums[2] if len(nums) > 2 else 0,
        "re_tx": nums[3] if len(nums) > 3 else 0,
    }


def _is_steam_proc(name):
    return "steam" in name.rsplit(".", 1)[0].lower()


def _cap_pick_target(frame, pid):
    """用第一帧的进程名单决定「看谁」：给定 pid → 正在跑的游戏 → 所有 steam* 进程。"""
    if pid and str(pid).isdigit():
        keys = [k for k in frame if k.endswith(f".{pid}")]
        if keys:
            return "game", keys
    gp = (steam_running_game() or {}).get("pid")
    if gp:
        keys = [k for k in frame if k.endswith(f".{gp}")]
        if keys:
            return "game", keys
    keys = [k for k in frame if _is_steam_proc(k)]
    if keys:
        return "steam", keys
    return "", []


def _cap_append(frame, kind, keys, started_at):
    """把一帧汇总成一条样本（累计值原样存下，差分在 _cap_analyze 里做）。"""
    if kind == "steam":
        keys = [k for k in frame if _is_steam_proc(k)]
    got = {k: frame[k] for k in keys if k in frame}
    agg = {"bi": 0, "bo": 0, "ooo": 0, "rtx": 0}
    for v in got.values():
        agg["bi"] += v["bytes_in"]
        agg["bo"] += v["bytes_out"]
        agg["ooo"] += v["rx_ooo"]
        agg["rtx"] += v["re_tx"]
    with _CAP_LOCK:
        _CAP["samples"].append({
            "t": round(time.time() - started_at, 1), "procs": len(got),
            "bytes_in": agg["bi"], "bytes_out": agg["bo"],
            "rx_ooo": agg["ooo"], "re_tx": agg["rtx"],
            "names": sorted(got)[:6],
        })
        _CAP["elapsed"] = round(time.time() - started_at, 1)
        if not _CAP["target"] and got:
            _CAP["target"] = "、".join(sorted(got))
    return bool(got)


def _cap_loop(seconds, pid):
    keys, kind = [], ""
    proc = None
    try:
        n = max(2, min(_CAP_MAX, int(seconds)) + 1)
        cmd = ["nettop", "-P", "-x", "-l", str(n), "-s", "1",
               "-J", "bytes_in,bytes_out,rx_ooo,re-tx"]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL,
                                text=True, errors="replace")
        _CAP_PROC["p"] = proc
        started_at = _CAP["started_at"] or time.time()
        frame, frames = {}, 0
        for line in proc.stdout:
            name, vals = _parse_nettop_line(line)
            if name is None:
                if frame:
                    frames += 1
                    if not kind:
                        kind, keys = _cap_pick_target(frame, pid)
                        with _CAP_LOCK:
                            _CAP["target_kind"] = kind
                            _CAP["pid"] = (pid or (steam_running_game() or {}).get("pid", ""))
                    _cap_append(frame, kind, keys, started_at)
                frame = {}
                continue
            frame[name] = vals
        if frame:                       # 收尾最后一帧
            frames += 1
            if not kind:
                kind, keys = _cap_pick_target(frame, pid)
                with _CAP_LOCK:
                    _CAP["target_kind"] = kind
            _cap_append(frame, kind, keys, started_at)
        try:
            proc.wait(timeout=5)
        except Exception:               # noqa: BLE001 —— 收尾而已
            pass
        with _CAP_LOCK:
            _CAP["running"] = False
            _CAP["done"] = True
            _CAP["frames"] = frames
            _CAP["finished_at"] = time.time()
        if not frames:
            with _CAP_LOCK:
                _CAP["error"] = "nettop 没有输出任何采样帧（可能被系统权限拦住）"
        _CAP["peers"] = steam_peers(pid, keys)
    except Exception as e:      # noqa: BLE001 —— 采样线程绝不能把服务带崩
        with _CAP_LOCK:
            _CAP["running"] = False
            _CAP["done"] = True
            _CAP["error"] = str(e)
    finally:
        _CAP_PROC["p"] = None
        if proc and proc.poll() is None:
            try:
                proc.terminate()
            except OSError:
                pass


def steam_peers(pid=None, keys=None):
    """目标进程当前的**对端 IP** —— 「实际连的是哪个中继 / 哪个 CDN」的直接证据。"""
    if not IS_MAC:
        return []
    pids = []
    if pid and str(pid).isdigit():
        pids.append(str(pid))
    else:
        gp = (steam_running_game() or {}).get("pid")
        if gp:
            pids.append(gp)
    if not pids:
        for k in (keys or []):
            tail = k.rsplit(".", 1)[-1]
            if tail.isdigit():
                pids.append(tail)
    found = {}
    for p in pids[:4]:
        txt = _sh(f"lsof -nP -i -a -p {p} 2>/dev/null", timeout=10)
        for line in txt.splitlines():
            m = re.search(r"->(\d+\.\d+\.\d+\.\d+):(\d+)", line)
            if not m:
                continue
            ip, port = m.group(1), m.group(2)
            if not is_public_ip(ip):
                continue
            k = f"{ip}:{port}"
            found[k] = found.get(k, 0) + 1
    return [{"peer": k, "hits": v}
            for k, v in sorted(found.items(), key=lambda x: -x[1])[:20]]


def _cap_analyze(samples, peers=None, relays=None):
    """把累计值换算成速率与质量增量，并给出「断续率」。"""
    if len(samples) < 2:
        return {}
    secs, total_in, total_out, missing = [], 0, 0, 0
    for a, b in zip(samples, samples[1:]):
        span = max(0.001, b["t"] - a["t"])
        d_in = b["bytes_in"] - a["bytes_in"]
        if d_in < 0:                # 计数器回绕 / 进程重启
            d_in = b["bytes_in"]
        d_out = b["bytes_out"] - a["bytes_out"]
        if d_out < 0:
            d_out = b["bytes_out"]
        d_ooo = max(0, b["rx_ooo"] - a["rx_ooo"])
        d_rtx = max(0, b["re_tx"] - a["re_tx"])
        if b.get("procs") == 0:
            missing += 1
            continue
        secs.append({"t": b["t"], "in": d_in, "out": d_out,
                     "ooo": d_ooo, "rtx": d_rtx, "s": round(span, 2)})
        total_in += d_in
        total_out += d_out
    span = max(1.0, samples[-1]["t"] - samples[0]["t"])
    zero = sum(1 for s in secs if s["in"] == 0 and s["out"] == 0)

    # 对端 IP → 命中哪个中继
    #
    # 先精确匹配；匹配不到再退一步按 /24 同网段推断。
    # 为什么必须退这一步：本地 SDR 缓存（appcache/sdr_config.txt）是 Steam 上次联网时
    # 写下的，中继 IP **会换号** —— 实测本机缓存里 hkg 是 103.28.54.163/.164/…，
    # 而实时抓到的对端却是 103.28.54.102，同网段但不在旧名单里。
    # 少了这一步，最关键的「实际命中哪个中继」就会长期为空。
    # 推断出来的必须标 match="subnet"，界面上如实说明这是推断而非确证。
    hit, unknown = [], []
    rmap = {r["ip"]: r for r in (relays or [])}
    sub = {}
    for r in (relays or []):
        sub.setdefault(r["ip"].rsplit(".", 1)[0], r)
    for p in (peers or []):
        ip = p["peer"].split(":")[0]
        port = p["peer"].split(":")[-1]
        r = rmap.get(ip)
        match = "exact"
        if not r:
            r = sub.get(ip.rsplit(".", 1)[0])
            match = "subnet" if r else ""
        if r:
            hit.append({"ip": ip, "port": port, "pop": r["pop"],
                        "pop_cn": r.get("pop_cn") or "", "hits": p["hits"],
                        "match": match})
        else:
            unknown.append({"ip": ip, "port": port, "hits": p["hits"]})
    return {
        "span": round(span, 1),
        "samples": len(samples),
        "active_seconds": len(secs),
        "missing_seconds": missing,
        "zero_seconds": zero,
        "zero_ratio": round(zero / len(secs), 3) if secs else None,
        "rate_kbps_in": round(total_in / span * 8 / 1000, 1),
        "rate_kbps_out": round(total_out / span * 8 / 1000, 1),
        "total_in": total_in,
        "rx_ooo_delta": sum(s["ooo"] for s in secs),
        "re_tx_delta": sum(s["rtx"] for s in secs),
        "series": secs,
        "peers": peers or [],
        "hit_relays": hit,
        "unknown_peers": unknown,
    }


def capture_state():
    with _CAP_LOCK:
        st = {"running": _CAP["running"], "done": _CAP["done"],
              "seconds": _CAP["seconds"], "elapsed": _CAP["elapsed"],
              "target": _CAP["target"], "target_kind": _CAP["target_kind"],
              "pid": _CAP["pid"], "samples": len(_CAP["samples"]),
              "frames": _CAP["frames"], "interrupted": _CAP["interrupted"],
              "error": _CAP["error"], "started_at": _CAP["started_at"],
              "finished_at": _CAP["finished_at"]}
        st["progress"] = (round(st["elapsed"] / st["seconds"], 2)
                          if st["seconds"] else 0)
        return st


def capture_start(seconds=60, pid=""):
    with _CAP_LOCK:
        if _CAP["running"]:
            return False, "已经有一次采样在进行中，等它结束或先停止。"
        try:
            secs = int(seconds)
        except (TypeError, ValueError):
            secs = 60
        secs = max(10, min(_CAP_MAX, secs))
        _CAP.update({"running": True, "done": False, "seconds": secs,
                     "elapsed": 0, "samples": [], "frames": 0, "peers": [],
                     "error": "", "interrupted": False, "target": "",
                     "target_kind": "", "pid": str(pid or ""),
                     "started_at": time.time(), "finished_at": 0.0})
    threading.Thread(target=_cap_loop, args=(secs, str(pid or "")),
                     daemon=True).start()
    return True, f"已开始采样（{secs} 秒）。采样期间请保持游戏联机状态。"


def capture_stop():
    with _CAP_LOCK:
        if not _CAP["running"]:
            return False, "当前没有正在进行的采样。"
        _CAP["interrupted"] = True
        _CAP["seconds"] = max(1, int(_CAP["elapsed"] or 1))
    p = _CAP_PROC.get("p")
    if p:
        try:
            p.terminate()          # 真结束 nettop，不等它跑满
        except OSError:
            pass
    return True, "已请求提前结束，正在收尾。"


def capture_result(relays=None):
    st = capture_state()
    with _CAP_LOCK:
        samples = list(_CAP["samples"])
        peers = list(_CAP["peers"])
    st["analysis"] = _cap_analyze(samples, peers, relays)
    return st


# ----------------------------------------------------------------------
# 诊断规则库（表驱动，便于扩展）
# ----------------------------------------------------------------------

def steam_diagnose(facts):
    """把观测事实映射成「原因 + 建议」。没有证据就不下结论。"""
    out = []

    def add(level, title, detail, advice=""):
        out.append({"level": level, "title": title, "detail": detail,
                    "advice": advice})

    env = facts.get("env") or {}
    if not env.get("installed"):
        add("info", "没找到 Steam 安装",
            "按该平台的常见路径都没找到 Steam 目录，下面所有检测都没有对象。",
            "先装好 Steam 并至少登录一次。")
        return out
    if not env.get("running"):
        add("info", "Steam 当前没在运行",
            "「连接日志」里的记录是上一次连接时写下的，可能已经过期；"
            "游戏进程相关的判断也会缺数据。",
            "开着 Steam 再做体检更准。")

    # R1 加速器接管了 SDR 中继 ★最重要的一条
    relays = facts.get("relays") or []
    tun_relays = [r for r in relays if r.get("is_tunnel")]
    if tun_relays:
        names = "、".join(f"{r['pop']}({r['ip']})" for r in tun_relays[:4])
        add("high", "加速器正在接管 SDR 中继",
            f"{len(tun_relays)} 个中继点（{names}）的流量走了隧道接口而不是物理网卡。"
            "杀戮尖塔这类游戏联机走的是 Steam Datagram Relay（Valve 自己的骨干中继），"
            "绕经加速器只会多一跳、还把可用 MTU 压小。",
            "在加速器里针对该游戏关闭加速，或整体停掉加速后重测。")

    # R2 隧道 MTU 偏小
    low = facts.get("low_mtu_tunnels") or []
    if low:
        names = "、".join(f"{n}（MTU {m}）" for n, m in low)
        add("high", "隧道 MTU 偏小，UDP 大包会被分片丢弃",
            f"{names} 的 MTU 低于 1400。游戏联机走 UDP，大包一旦分片，"
            "任何一片丢失都要整包重传 —— 表现就是「能进游戏但频繁瞬卡或掉线」。",
            "关掉这些隧道，或在客户端里把 MTU 调大。")

    # R3 实际命中的中继点
    cap = facts.get("capture") or {}
    an = cap.get("analysis") or {}
    hit = an.get("hit_relays") or []
    unknown = an.get("unknown_peers") or []
    if hit:
        pops = sorted({h["pop"] for h in hit})
        txt = "、".join(f"{h['pop']}（{h.get('pop_cn') or '?'}）{h['ip']}:{h['port']}"
                        for h in hit[:4])
        if "hkg" not in pops:
            add("mid", "实际连的中继不是香港",
                f"采样期间对端是 {txt}。国内玩家最近的 SDR 中继在香港（hkg），"
                "命中别的 pop 说明去香港的链路可能异常，或加速器改掉了选点。",
                "对比 hkg 各中继的 RTT 后再决定是否关加速。")
        else:
            add("info", "实际连的中继在香港",
                f"采样期间对端是 {txt} —— 这是国内玩家最理想的中继位置。")
        sub_only = [h for h in hit if h.get("match") == "subnet"]
        if sub_only:
            add("info", "有中继是按同网段推断的归属",
                "、".join(f"{h['ip']}（{h['pop']}）" for h in sub_only[:4])
                + " 不在本地缓存的 SDR 名单里，是按同一个 /24 网段推断出来的。"
                "Steam 的中继 IP 会换号，本地缓存只在上次联网时更新。",
                "点「刷新 SDR 名单」从官方接口重拉一次，归属会更准。")
    elif unknown:
        add("info", "抓到了对端，但认不出是哪个中继",
            "采样期间该进程连过 " + "、".join(f"{u['ip']}:{u['port']}"
                                        for u in unknown[:4])
            + "，这些 IP 不在已知中继名单里。可能是较新的中继（本地 SDR 缓存偏旧），"
            "也可能根本不是 Steam 的中继流量。",
            "点「刷新 SDR 名单」后重测，或进入对局后再采样一次。")
    elif cap.get("done"):
        add("info", "没抓到游戏的对端 IP",
            "采样期间该进程没有出现公网 UDP/TCP 对端。可能当时不在联机中，"
            "也可能游戏走的是别的进程。",
            "进入对局后再采样一次。")

    # R4 断续与乱序
    zr = an.get("zero_ratio")
    if zr is not None and zr > 0.2:
        add("mid", f"联机流量断续：{int(zr * 100)}% 的秒数没有数据",
            f"采样 {an.get('active_seconds')} 个有效秒里有 {an.get('zero_seconds')} 秒"
            "收发都为 0。" + ("期间目标进程还消失了 "
                          f"{an.get('missing_seconds')} 秒（可能已退出对局）。"
                          if an.get("missing_seconds") else ""),
            "配合下面「走哪条路」的判断一起看，先排除加速器与 MTU 问题。")
    if (an.get("rx_ooo_delta") or 0) > 0 or (an.get("re_tx_delta") or 0) > 0:
        add("mid", "出现乱序 / 重传",
            f"采样期间累计乱序 {an.get('rx_ooo_delta')} 字节、"
            f"重传 {an.get('re_tx_delta')} 次。这是「卡一下再跳回来」的直接物证。",
            "如果同时存在隧道接管或 MTU 偏小，优先处理那两项。")

    # R5 Steam 客户端自身反复重连（只算最近 24 小时，避免把历史累积误读成现状）
    cl = facts.get("console") or {}
    r24 = cl.get("restarts_24h") or 0
    if r24 >= 8:
        add("mid", "Steam 客户端反复重连",
            f"最近 24 小时的日志里出现 {r24} 次「Game process added」，"
            "说明客户端层在反复起停游戏进程 —— 这与加速器无关。",
            "先确认 Steam 自身网络正常，再看联机质量。")

    # R6 商店 / 社区
    tun_store = [d for d in (facts.get("store") or []) if d.get("is_tunnel")]
    if tun_store:
        add("mid", "商店 / 社区流量被隧道接管",
            "、".join(f"{d['host']}（{d['via']}）" for d in tun_store[:4])
            + "。商店和社区被绕进隧道后，常见症状是登录转圈、社区打不开。",
            "如果只是要开社区，考虑把这几个域名切到直连再试。")

    # R7 下载 CDN
    tun_cdn = [c for c in (facts.get("cdn") or []) if c.get("is_tunnel")]
    if tun_cdn:
        add("mid", "下载 CDN 被隧道接管",
            "、".join(f"{c['host']}（{c['via']}）" for c in tun_cdn[:4])
            + "。Steam 下载走的是国内 CDN，被加速器绕出去通常只会更慢。",
            "下载时建议关掉加速器。")

    # R8 ICMP 几乎全不可达 —— 如实说明这只是参考值
    if relays:
        dead = [r for r in relays if not r.get("icmp_ok")]
        if len(dead) > len(relays) * 0.6:
            add("info", "多数中继不回 ICMP",
                f"{len(dead)}/{len(relays)} 个中继点 ping 不通。"
                "SDR 走 UDP，中继不回 ICMP 是常见现象，**不代表游戏连不上**，"
                "别据此判断联机质量。",
                "以「实测联机」与「采样」的结论为准。")

    # R9 SDR 配置拿不到
    if (facts.get("sdr_meta") or {}).get("error"):
        add("info", "SDR 中继列表不完整",
            (facts.get("sdr_meta") or {}).get("error") or "",
            "中继探测结果可能不全，等 Steam 客户端跑过一次再试。")

    # R10 还没采样
    if not cap.get("done"):
        add("info", "还没做过联机采样",
            "P2P 稳定性必须在对局中边跑边采样才能判断，单看配置得不出结论。",
            "进游戏开一局，点「开始采样」，样本越长越准（建议 60 秒）。")

    return out


# ----------------------------------------------------------------------
# 对外入口
# ----------------------------------------------------------------------

def steam_summary():
    """给 /api/scan 用的**轻量摘要**：只读进程 + 日志尾部，不跑任何网络探测。

    必须保持在几十毫秒量级 —— 不能把扫描拖慢。
    """
    if not IS_MAC and not IS_WIN:
        return {"supported": False}
    env = steam_env()
    if not env.get("installed"):
        return {"supported": True, "installed": False, "running": False}
    cl = parse_steam_conn_log()
    best = (cl.get("cm") or [None])[0]
    last = (cl.get("latest") or [None])[-1]
    if last:
        last = dict(last)
        _iface, _verdict = _local_ip_verdict(last.get("local_ip"))
        last["local_iface"], last["verdict"] = _iface, _verdict
    return {
        "supported": True,
        "installed": True,
        "running": env.get("running"),
        "cell_id": env.get("cell_id"),
        "game_name": env.get("game_name"),
        "running_game": (env.get("running_game") or {}).get("app_dir", ""),
        "cm_best": ({"dc": best.get("dc"), "dc_cn": best.get("dc_cn"),
                     "ms": best.get("ms")} if best else None),
        "cm_count": len(cl.get("cm") or []),
        "last_conn": ({"at": last.get("at"), "server_ip": last.get("server_ip"),
                       "local_ip": last.get("local_ip"),
                       "local_iface": last.get("local_iface"),
                       "verdict": last.get("verdict")} if last else None),
        "log_at": cl.get("at") or "",
        "log_error": cl.get("error") or "",
        "capture": capture_state(),
    }


def do_steam_overview():
    """快照：安装/运行/账号/下载区域 + 平台网（CM 延迟）+ 游戏进程 + 采样状态。"""
    t0 = time.time()
    env = steam_env()
    cl = parse_steam_conn_log()
    csl = parse_steam_console_log()
    cl["latest"] = annotate_conn_rows(cl.get("latest") or [])
    return {
        "ok": True, "at": time.time(),
        "elapsed_ms": round((time.time() - t0) * 1000),
        "env": env, "cm": cl, "console": csl,
        "store_domains": STEAM_STORE_DOMAINS,
        "capture": capture_state(),
        "sdr_meta": {"source": "local" if env.get("sdr_cache") else "",
                     "error": ""},
    }


def do_steam_probe(appid=None, cell=None, force_online=False):
    """排行：CM 集群 / SDR 中继 / CDN / 商店 —— 真解析、真连、真看第一跳。"""
    if not IS_MAC:
        return {"error": f"实时探测暂仅支持 macOS（当前 {PLATFORM}）"}
    t0 = time.time()
    env = steam_env()
    appid, app_name = (str(appid), "") if appid else steam_guess_appid(env)
    cell_id = int(cell) if cell else env.get("cell_id") or STEAM_CDN_CELL

    pops, sdr_meta = steam_sdr_pops(appid, prefer_online=force_online)
    relays = sdr_relay_targets(pops, limit=12)
    phys, phys_gw = phys_iface_guess()
    am = local_addr_map()

    # 中继：先 ICMP（网络层参考值），再判它走哪条路。
    # 这里**不做第一跳** —— 每个目标 ping 一次要等超时，几十个目标会把体检拖到一分钟。
    # 判定「走没走加速器」靠源地址 + 路由声明就够了（和 quick_egress 同口径）。
    rtts = parallel_map(lambda r: icmp_probe(r["ip"]), relays, workers=12)
    for r, pair in zip(relays, rtts):
        ok, ms = pair or (False, None)
        r["icmp_ok"], r["icmp_ms"] = ok, ms
        p = steam_path_of(r["ip"], am, phys_gw, want_hop=False)
        for k in ("declared_iface", "src_ip", "src_iface", "first_hop",
                  "is_tunnel", "is_phys", "mismatch", "via"):
            r[k] = p[k]

    # CM 集群（平台网）
    cms = cm_targets(cell_id, limit=6)
    crows = parallel_map(
        lambda c: probe_host(c["host"], int(c["port"] or 443), am, phys_gw,
                             want_hop=False), cms, workers=6)
    for c, row in zip(cms, crows):
        c.update(row or {"via": "解析失败"})

    # 商店 / 社区 / API —— 这一组开第一跳：它是「直连还是加速器」证据最强的一栏
    stores = parallel_map(
        lambda d: probe_host(d, 443, am, phys_gw, want_hop=True),
        STEAM_STORE_DOMAINS, workers=4)

    # 内容分发网：官方列表 + 历史真实主机
    cdn = steam_cdn_servers(cell_id)
    for c in steam_cdn_history():
        if c["host"] not in [x["host"] for x in cdn]:
            cdn.append(c)
    cdn = cdn[:10]
    crows2 = parallel_map(
        lambda c: probe_host(c["host"], 80, am, phys_gw, want_hop=False),
        cdn, workers=6)
    for c, row in zip(cdn, crows2):
        c.update(row or {"via": "解析失败"})

    # 隧道 MTU 事实
    low_mtu = []
    try:
        for i in scan_interfaces_mac():
            if (i.get("status") == "active" and is_tunnel_iface(i["name"])
                    and i.get("mtu") and i["mtu"] < 1400):
                low_mtu.append((i["name"], i["mtu"]))
    except Exception:       # noqa: BLE001 —— 拿不到就不报
        pass

    return {
        "ok": True, "at": time.time(),
        "elapsed_ms": round((time.time() - t0) * 1000),
        "appid": appid, "app_name": app_name,
        "cell_id": cell_id,
        "phys_iface": phys, "phys_gw": phys_gw,
        "sdr_meta": sdr_meta, "pop_count": len(pops),
        "relays": relays, "cm": cms, "store": stores, "cdn": cdn,
        "low_mtu_tunnels": low_mtu,
        "capture": capture_result(relays),
    }


def do_steam_diagnose(appid=None, cell=None):
    """体检结论：把三类观测汇到规则库，产出「原因 + 建议」。"""
    if not IS_MAC:
        return {"error": f"暂仅支持 macOS（当前 {PLATFORM}）"}
    ov = do_steam_overview()
    pb = do_steam_probe(appid=appid, cell=cell)
    if pb.get("error"):
        return pb
    facts = {
        "env": ov.get("env") or {},
        "cm": ov.get("cm") or {},
        "console": ov.get("console") or {},
        "relays": pb.get("relays") or [],
        "cms": pb.get("cm") or [],
        "store": pb.get("store") or [],
        "cdn": pb.get("cdn") or [],
        "sdr_meta": pb.get("sdr_meta") or {},
        "low_mtu_tunnels": pb.get("low_mtu_tunnels") or [],
        "capture": pb.get("capture") or {},
    }
    findings = steam_diagnose(facts)
    hi = [f for f in findings if f["level"] == "high"]
    mid = [f for f in findings if f["level"] == "mid"]
    if hi:
        summary = f"发现 {len(hi)} 项高优先级问题：" + hi[0]["title"]
    elif mid:
        summary = f"发现 {len(mid)} 项需要注意的问题：" + mid[0]["title"]
    else:
        summary = "没有发现明显问题（已完成的观测范围内）"
    return {
        "ok": True, "at": time.time(),
        "appid": pb.get("appid"), "app_name": pb.get("app_name"),
        "cell_id": pb.get("cell_id"),
        "elapsed_ms": (ov.get("elapsed_ms") or 0) + (pb.get("elapsed_ms") or 0),
        "summary": summary,
        "counts": {"high": len(hi), "mid": len(mid),
                   "info": len(findings) - len(hi) - len(mid)},
        "findings": findings,
        "relays": pb.get("relays") or [],
        "cm": pb.get("cm") or [],
        "store": pb.get("store") or [],
        "cdn": pb.get("cdn") or [],
        "capture": pb.get("capture") or {},
        "sdr_meta": pb.get("sdr_meta") or {},
        "low_mtu_tunnels": pb.get("low_mtu_tunnels") or [],
        "phys_iface": pb.get("phys_iface"), "phys_gw": pb.get("phys_gw"),
    }


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
        if i.get("type") in (6, 71) and i.get("status") == "active":
            phys_iface = i["name"]
            break
    if not phys_iface:
        for i in raw:
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
        "daemon_installed": IS_MAC and os.path.isfile(
            "/Library/LaunchDaemons/com.local.tunnel-manager.plist"),
        "is_root": (os.geteuid() == 0) if not IS_WIN else False,
        "domains_config": load_config(),
        "csrf_token": _csrf_token,
    }


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
    """本程序管理的域名 = 配置表 + 自动追踪到的。

    扫描展示与撤销操作都用这一份口径，避免「界面显示 3 条、撤销动了 5 条」这类不一致。
    """
    return load_config() + get_auto_domains()


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
    kws = ",".join("'" + k + "'" for k in _proc_keywords())
    ps = (
        f"$kws = @({kws}); "
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
    domains = load_config()

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
    if rc != 0:
        return False, f"执行失败 (rc={rc})：{err or out}"

    vpn_note = (f"，并已跳过 {len(set(skipped_vpn))} 个隧道客户端自身服务器 IP"
                f"（{'、'.join(sorted(set(skipped_vpn)))}）") if skipped_vpn else ""
    saved = write_state(state_ips)
    if not saved:
        # 记录写不进去也必须让用户知道 —— 否则下次 undo 无从下手
        return True, (f"完成：新增 {len(state_ips)} 条直连路由，出口 {phys_iface} ({gw})"
                      f"{vpn_note}。⚠ 但状态文件写入失败（{STATE_FILE}），"
                      f"撤销时将以路由表实测结果为准。")
    return True, (f"完成：新增 {len(state_ips)} 条直连路由，出口 {phys_iface} ({gw})"
                  f"{vpn_note}")


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


# ======================================================================
# 十、HTTP 服务（v2：CSRF / Host 头 / DNS rebinding 防护）
# ======================================================================

# 单文件分发版会把 index.html 的内容内嵌进这个变量（构建时填充）。
# 优先级：同目录 index.html > 内嵌 EMBEDDED_HTML > 兜底提示。
EMBEDDED_HTML = None


def get_html():
    path = os.path.join(BASE_DIR, "index.html")
    if os.path.isfile(path):
        try:
            with open(path, encoding="utf-8") as f:
                return f.read()
        except OSError:
            pass
    if EMBEDDED_HTML:
        return EMBEDDED_HTML
    return "<h3>index.html 丢失</h3><p>请把 index.html 放在 server.py 同目录。</p>"


def host_allowed(host):
    """只允许本机访问（防 DNS rebinding：攻击者用域名指向 127.0.0.1 绕过同源策略）。"""
    if not host:
        return True  # 无 Host 头的极端情况，后面 Origin 校验兜底
    h = host.split(":")[0].lower()
    return h in ("127.0.0.1", "localhost", "[::1]", "::1")


def origin_allowed(origin):
    """CSRF 防护：只接受本机来源的写请求。"""
    if not origin:
        return False
    o = origin.lower()
    for h in ("127.0.0.1", "localhost", "[::1]"):
        if o.startswith(f"http://{h}:") or o == f"http://{h}":
            return True
    return False


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    def _json(self, code, obj):
        body = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self):
        body = get_html().encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _check_read(self):
        """读请求：只校验 Host 头。"""
        if not host_allowed(self.headers.get("Host", "")):
            self._json(403, {"error": "FORBIDDEN_HOST"})
            return False
        return True

    def _check_write(self, payload):
        """写请求：Host + Origin + CSRF token 三重校验。"""
        if not self._check_read():
            return False
        origin = self.headers.get("Origin") or self.headers.get("Referer") or ""
        if not origin_allowed(origin):
            self._json(403, {"error": "FORBIDDEN_ORIGIN",
                             "message": "只允许本机页面发起操作"})
            return False
        token = self.headers.get("X-TM-Token") or (payload or {}).get("token")
        if token != _csrf_token:
            self._json(403, {"error": "BAD_CSRF_TOKEN",
                             "message": "缺少或错误的 CSRF token"})
            return False
        return True

    def do_GET(self):
        if not self._check_read():
            return
        path = self.path.split("?")[0]
        try:
            if path == "/api/scan":
                self._json(200, do_scan())
            elif path == "/api/config":
                self._json(200, {"domains": load_config()})
            elif path == "/api/steam/overview":
                self._json(200, do_steam_overview())
            elif path == "/api/steam/capture/result":
                # 采样结果：中继名单只读本地缓存，避免这个 GET 卡在网络上
                _local_pops, _rev = _read_local_sdr()
                self._json(200, capture_result(
                    sdr_relay_targets(_local_pops, limit=48)))
            elif path == "/" or path == "/index.html":
                self._send_html()
            else:
                self._json(404, {"error": "not found"})
        except Exception as e:  # noqa: BLE001
            self._json(500, {"error": str(e)})

    def do_POST(self):
        path = self.path.split("?")[0]
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            payload = json.loads(raw.decode() or "{}")
        except json.JSONDecodeError:
            self._json(400, {"error": "bad json"})
            return

        try:
            if path == "/api/sudo":
                if not self._check_write(payload):
                    return
                ok, msg = verify_sudo(payload.get("password", ""))
                self._json(200 if ok else 403, {"ok": ok, "message": msg})
                return
            if path == "/api/config":
                if not self._check_write(payload):
                    return
                domains = save_config(payload.get("domains", []))
                self._json(200, {"ok": True, "domains": domains,
                                 "result": do_scan()})
                return
            if path == "/api/auto/enable":
                if not self._check_write(payload):
                    return
                toggle_auto_tracker(True)
                self._json(200, {"ok": True, "result": do_scan()})
                return
            if path == "/api/auto/disable":
                if not self._check_write(payload):
                    return
                toggle_auto_tracker(False)
                with _auto_lock:
                    _auto_domains.clear()
                self._json(200, {"ok": True, "result": do_scan()})
                return
            if path == "/api/auto/pin":
                if not self._check_write(payload):
                    return
                # 手动把一个域名加入自动追踪集合（与浏览器历史发现的域名同等待遇：
                # 出现在自动追踪面板和路由表里，超过 AUTO_EXPIRE 没再访问则自动移除）
                dom = (payload.get("domain") or "").strip().lower()
                if dom:
                    with _auto_lock:
                        _auto_domains[dom] = time.time()
                self._json(200, {"ok": True, "result": do_scan()})
                return
            if path == "/api/outlet/forget":
                if not self._check_write(payload):
                    return
                ok, msg = forget_fingerprint(payload.get("key", ""))
                self._json(200 if ok else 500, {"ok": ok, "message": msg})
                return
            if path == "/api/outlet/identify":
                if not self._check_write(payload):
                    return
                r = identify_outlet(payload.get("key", ""), payload.get("password"))
                if r.get("message") == "NEED_SUDO":
                    self._json(403, {"ok": False, "error": "NEED_SUDO",
                                     "message": "需要管理员密码"})
                else:
                    self._json(200 if r.get("ok") else 500,
                               {"ok": r.get("ok"), "message": r.get("message"),
                                "identify": r})
                return
            if path == "/api/outlet/cancel":
                if not self._check_write(payload):
                    return
                r = cancel_switch(payload.get("password"))
                msg = r.get("message")
                if msg == "NEED_SUDO":
                    self._json(403, {"ok": False, "error": "NEED_SUDO",
                                     "message": "需要管理员密码"})
                else:
                    self._json(200 if r.get("ok") else 500,
                               {"ok": r.get("ok"), "message": msg,
                                "outlet": r, "result": do_scan()})
                return
            if path in ("/api/outlet/stop", "/api/outlet/start", "/api/outlet/switch"):
                if not self._check_write(payload):
                    return
                act = path.rsplit("/", 1)[-1]
                key = payload.get("key", "")
                pw = payload.get("password")
                if act == "switch":
                    r = switch_outlet(key, pw)
                    ok, msg = r.get("ok"), r.get("message")
                else:
                    fn = outlet_stop if act == "stop" else outlet_start
                    ok, msg = fn(key, pw)
                    r = None
                if msg == "NEED_SUDO":
                    self._json(403, {"ok": False, "error": "NEED_SUDO",
                                     "message": "需要管理员密码"})
                else:
                    self._json(200 if ok else 500,
                               {"ok": ok, "message": msg, "outlet": r})
                return
            if path in ("/api/scene/game", "/api/scene/campus"):
                if not self._check_write(payload):
                    return
                res = do_scene(path.rsplit("/", 1)[-1], payload.get("password"))
                if res.get("ok"):
                    self._json(200, {"ok": True, "message": res.get("message"),
                                     "scene_switch": res})
                else:
                    self._json(403, {"ok": False, "error": "NEED_SUDO",
                                     "message": res.get("message"),
                                     "scene_switch": res})
                return
            if path == "/api/trace":
                if not self._check_write(payload):
                    return
                self._json(200, {"ok": True, "trace": do_trace()})
                return
            if path == "/api/steam/probe":
                if not self._check_write(payload):
                    return
                r = do_steam_probe(appid=payload.get("appid"),
                                   cell=payload.get("cell"),
                                   force_online=bool(payload.get("refresh")))
                self._json(500 if r.get("error") else 200, r)
                return
            if path == "/api/steam/diagnose":
                if not self._check_write(payload):
                    return
                r = do_steam_diagnose(appid=payload.get("appid"),
                                      cell=payload.get("cell"))
                self._json(500 if r.get("error") else 200, r)
                return
            if path == "/api/steam/capture/start":
                if not self._check_write(payload):
                    return
                ok, msg = capture_start(payload.get("seconds") or 60,
                                        payload.get("pid") or "")
                self._json(200 if ok else 409,
                           {"ok": ok, "message": msg, "capture": capture_state()})
                return
            if path == "/api/steam/capture/stop":
                if not self._check_write(payload):
                    return
                ok, msg = capture_stop()
                self._json(200 if ok else 409,
                           {"ok": ok, "message": msg, "capture": capture_state()})
                return
            if path == "/api/health/save":
                if not self._check_write(payload):
                    return
                ok, msg = save_health()
                self._json(200 if ok else 500, {"ok": ok, "message": msg,
                                                "result": do_scan() if ok else None})
                return
            if path == "/api/rescue":
                if not self._check_write(payload):
                    return
                r = do_rescue(payload.get("password"))
                if r.get("error") == "NEED_SUDO":
                    self._json(403, {"ok": False, "error": "NEED_SUDO",
                                     "message": r.get("message"),
                                     "rescue": r.get("rescue")})
                else:
                    self._json(200 if r.get("ok") else 500,
                               {"ok": r.get("ok"), "message": r.get("message"),
                                "rescue": r.get("rescue"),
                                "result": do_scan() if r.get("ok") else None})
                return
            if path == "/api/apply":
                if not self._check_write(payload):
                    return
                ok, msg = do_apply(payload.get("password"))
            elif path == "/api/undo":
                if not self._check_write(payload):
                    return
                ok, msg = do_undo(payload.get("password"))
            elif path in ("/api/daemon/install", "/api/daemon/remove"):
                if not self._check_write(payload):
                    return
                ok, msg = do_daemon(
                    "install" if path.endswith("install") else "remove",
                    payload.get("password"))
            else:
                self._json(404, {"error": "not found"})
                return

            if ok is None and msg in ("NEED_SUDO", "BAD_PASSWORD"):
                self._json(403, {"error": msg,
                                 "message": "需要管理员密码" if msg == "NEED_SUDO" else "密码错误"})
            elif ok:
                self._json(200, {"ok": True, "message": msg, "result": do_scan()})
            else:
                self._json(500, {"ok": False, "message": msg})
        except Exception as e:  # noqa: BLE001
            self._json(500, {"error": str(e)})


def pick_port():
    for port in PORT_PREFERENCE:
        if port == 0:
            break
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            # 关键：必须设 SO_REUSEADDR。
            # 否则刚重启时端口处于 TIME_WAIT，会被**误判成"被占用"**，
            # 服务就顺延到 7532/7533 —— 用户保存的书签/快捷方式立刻失效。
            # （真正的监听端也要能复用，那边由 HTTPServer.allow_reuse_address 负责。）
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.bind(("127.0.0.1", port))
                return port
            except OSError:
                continue
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def main():
    port = pick_port()
    start_auto_tracker()   # 拉起浏览器历史自动追踪线程
    try:
        server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    except OSError as e:
        print(f"无法绑定端口：{e}", file=sys.stderr)
        sys.exit(1)
    url = f"http://127.0.0.1:{port}"
    print(f"Universal Tunnel Manager 已启动（{PLATFORM}）：{url}")
    print("只绑 127.0.0.1，仅本机可访问。Ctrl-C 退出。")
    threading.Thread(target=lambda: (time.sleep(1.2), webbrowser.open(url)),
                     daemon=True).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n再见。")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
