# -*- coding: utf-8 -*-
"""tunnel_manager.win/probe — Windows 探测基座（ps 可用性 / 缓存 / IP 掩码工具）

由 P2 从 win/native.py 的第 1–113 行**原样拆出**，正文逐字未改（与 P1 一样，只搬不改）。

【切片规则 —— 这不是漏写 import】
本项目按设计保持**单一扁平命名空间**：
  · 开发期入口 `python -m tunnel_manager.main` → 把所有切片拼进一个命名空间再执行；
  · 构建期 `bundle.py` → 同样顺序拼接成单文件 `dist/tunnel-manager.py`（纯源码，不含 exec）。
所以本文件里可以直接引用其它切片定义的函数与常量，无需 import。跨切片调用是既有事实。
本模块对外提供：ps_available
本模块依赖其它切片：_base、util
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


