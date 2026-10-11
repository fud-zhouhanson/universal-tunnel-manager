# -*- coding: utf-8 -*-
"""tunnel_manager.steam/api — Steam API 数据与运行态

由 P2 从 steam/diagnose.py 的第 249–483 行**原样拆出**，正文逐字未改（与 P1 一样，只搬不改）。

【切片规则 —— 这不是漏写 import】
本项目按设计保持**单一扁平命名空间**：
  · 开发期入口 `python -m tunnel_manager.main` → 把所有切片拼进一个命名空间再执行；
  · 构建期 `bundle.py` → 同样顺序拼接成单文件 `dist/tunnel-manager.py`（纯源码，不含 exec）。
所以本文件里可以直接引用其它切片定义的函数与常量，无需 import。跨切片调用是既有事实。
本模块对外提供：icmp_probe、pid_alive、steam_api_json、steam_cell_id、steam_env、steam_guess_appid 等 9 个
本模块依赖其它切片：_base、detect/iface、detect/process、detect/route、health/probe、outlet/scene_ops、steam/paths、steam/trace、util
"""
>>>SLICE_BODY<<<
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


