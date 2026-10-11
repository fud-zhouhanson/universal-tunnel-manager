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

