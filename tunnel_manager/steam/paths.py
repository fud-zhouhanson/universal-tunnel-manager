# -*- coding: utf-8 -*-
"""tunnel_manager.steam/paths — Steam 目录 / 代理 / HTTP 取数

由 P2 从 steam/diagnose.py 的第 1–248 行**原样拆出**，正文逐字未改（与 P1 一样，只搬不改）。

【切片规则 —— 这不是漏写 import】
本项目按设计保持**单一扁平命名空间**：
  · 开发期入口 `python -m tunnel_manager.main` → 把所有切片拼进一个命名空间再执行；
  · 构建期 `bundle.py` → 同样顺序拼接成单文件 `dist/tunnel-manager.py`（纯源码，不含 exec）。
所以本文件里可以直接引用其它切片定义的函数与常量，无需 import。跨切片调用是既有事实。
本模块对外提供：STEAM_API、STEAM_APP_FALLBACK、STEAM_CDN_CELL、STEAM_LOG_TAIL、STEAM_NEAR_POPS、STEAM_POP_NAMES 等 12 个
本模块依赖其它切片：_base、steam/api
"""
>>>SLICE_BODY<<<
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

def _win_steam_from_registry():
    """从注册表读 Steam 安装路径 —— 官方安装器**必然**写这几处，是权威来源。

    只扫 Program Files / LOCALAPPDATA 是不够的：Steam 允许装到任意目录
    （真机反馈：把软件装 D 盘的习惯很常见，`D:\\Steam` 这类会全漏掉）。
    """
    out = []
    try:
        import winreg
    except ImportError:                      # 非 Windows 上直接空手而归
        return out

    def _get(hive, sub, val, flag=0):
        try:
            with winreg.OpenKey(hive, sub, 0, winreg.KEY_READ | flag) as k:
                p, _ = winreg.QueryValueEx(k, val)
                if p:
                    out.append(str(p))
        except OSError:
            pass

    _get(winreg.HKEY_CURRENT_USER, r"SOFTWARE\Valve\Steam", "SteamPath")
    _get(winreg.HKEY_CURRENT_USER, r"SOFTWARE\Valve\Steam", "SteamExe")
    _get(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Valve\Steam", "InstallPath")
    _get(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Valve\Steam", "InstallPath",
         winreg.KEY_WOW64_32KEY)
    res = []
    for p in out:
        p = os.path.normpath(p)              # 注册表里常是正斜杠 c:/program files/steam
        if p.lower().endswith(".exe"):       # SteamExe 给的是 steam.exe 的完整路径
            p = os.path.dirname(p)
        res.append(p)
    return res


def _win_steam_from_drives():
    """扫各**本地固定盘**的常见位置 —— 兜底注册表缺失 / 绿色安装。

    只认 DRIVE_FIXED（本地磁盘，类型 3），跳过 U 盘与网络盘：
    对网络盘做 isdir() 可能长时间卡住，而 Steam 装在网络盘上没有意义。
    """
    out = []
    try:
        import ctypes
        bitmask = ctypes.windll.kernel32.GetLogicalDrives()
    except Exception:                        # noqa: BLE001
        return out
    subs = ("Steam", "SteamLibrary", "Games\\Steam",
            "Program Files (x86)\\Steam", "Program Files\\Steam")
    for i in range(26):
        if not bitmask & (1 << i):
            continue
        letter = chr(ord("A") + i)
        try:
            if ctypes.windll.kernel32.GetDriveTypeW(letter + ":\\") != 3:
                continue
        except Exception:                    # noqa: BLE001
            continue
        out.extend(letter + ":\\" + s for s in subs)
    return out


def steam_dirs():
    """按平台列出 Steam 根目录候选。用户级安装优先于全局安装。"""
    home = os.path.expanduser("~")
    if IS_MAC:
        return [os.path.join(home, "Library", "Application Support", "Steam")]
    if IS_WIN:
        cands = _win_steam_from_registry()   # 权威：官方安装器写注册表
        cands.append(os.path.join(os.environ.get("LOCALAPPDATA") or home, "Steam"))
        for env in ("PROGRAMFILES(X86)", "PROGRAMFILES"):
            base = os.environ.get(env)
            if base:
                cands.append(os.path.join(base, "Steam"))
        cands.extend(_win_steam_from_drives())
        seen, out = set(), []                # 去重保序（注册表大概率命中前几个）
        for d in cands:
            d = (d or "").rstrip("\\/")
            k = d.lower()
            if d and k not in seen:
                seen.add(k)
                out.append(d)
        return out
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


