# -*- coding: utf-8 -*-
"""tunnel_manager.steam/diagnose — Steam 三网体检（平台 / 联机 / 内容分发）

由 P1 从 server.py 的第 4148–5241 行**整块搬迁**而来，正文逐字未改。

【切片规则 —— 这不是漏写 import】
本项目按设计保持**单一扁平命名空间**：
  · 开发期入口 `python -m tunnel_manager.main` → 把所有切片拼进一个命名空间再执行；
  · 构建期 `bundle.py` → 同样顺序拼接成单文件 `dist/tunnel-manager.py`（纯源码，不含 exec）。
所以本文件里可以直接引用其它切片定义的函数与常量，无需 import。跨切片调用是既有事实。
本模块对外提供：STEAM_API、STEAM_APP_FALLBACK、STEAM_CDN_CELL、STEAM_LOG_TAIL、STEAM_NEAR_POPS、STEAM_POP_NAMES 等 35 个
本模块依赖其它切片：_base、consts、detect/iface、detect/process、detect/route、health/flow、outlet/scene、util
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


