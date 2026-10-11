# -*- coding: utf-8 -*-
"""tunnel_manager.config — 配置 + 自动追踪（浏览器历史）

由 P1 从 server.py 的第 759–1163 行**整块搬迁**而来，正文逐字未改。

【切片规则 —— 这不是漏写 import】
本项目按设计保持**单一扁平命名空间**：
  · 开发期入口 `python -m tunnel_manager.main` → 把所有切片拼进一个命名空间再执行；
  · 构建期 `bundle.py` → 同样顺序拼接成单文件 `dist/tunnel-manager.py`（纯源码，不含 exec）。
所以本文件里可以直接引用其它切片定义的函数与常量，无需 import。跨切片调用是既有事实。
本模块对外提供：AUTO_EXPIRE、AUTO_INTERVAL、AUTO_MAX、AUTO_WINDOW、DEFAULT_DOMAINS、DNS_TTL 等 15 个
本模块依赖其它切片：_base、consts
"""
>>>SLICE_BODY<<<
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
#
# ⚠️ 三条踩过的坑，别改回去：
#
#  1) **不要剥掉 `www.`**（曾这么干过，是错的）。
#     实测国内站的 apex 与 www 解析出来的公网 IP **零交集**：
#       www.baidu.com → 180.101.51.73      baidu.com → 111.63.65.103
#       www.zhihu.com → 43.242.197.211     zhihu.com → 182.61.194.9
#       www.bilibili.com → 114.230.222.139 bilibili.com → 119.3.70.188  …共 6 个站全部 0 交集
#     只有 github.com 这种本来就无 www 的才对得上。
#     浏览器连的是 **www 的 IP**；存成 apex 就会给一批用不上的 IP 加直连路由，
#     「追踪 → 应用」整条链路看着成功、实际一条都没生效。原样保留 host 最准。
#
#  2) **读取失败绝不能吞**。macOS 上 Safari 的历史库受 TCC（完全磁盘访问）保护，
#     直读报 `unable to open database file`、先复制再读报 `EPERM`。
#     以前是 `except: pass`，界面于是永远显示「追踪中 · 0 个」，
#     用户分不清「没开浏览器」/「没授权」/「刚开过但都超了 3 分钟」。
#     现在每次扫描都留一份 _auto_status，经 /api/scan 送到前端展示。
#
#  3) **临时文件要放在 finally 里删**。Chrome 的库要先复制再读（运行时被锁），
#     复制失败时如果 unlink 不在 finally，副本会永远留下 —— 每 30 秒一轮、失败一次留一个。

AUTO_WINDOW = 180    # 最近 3 分钟内访问过 = 「正在看」
AUTO_EXPIRE = 600    # 10 分钟没再看 = 「关了」，移除
AUTO_INTERVAL = 30   # 扫描周期
AUTO_MAX = 60        # 追踪集合的上限（防「浏览一天 → 上百条路由」失控），超出丢最旧的。
                     # 为什么不是 100：追踪到的域名现在**真的会变成直连路由**，
                     # 每个域名解析出 2~4 个 IP，而 Windows 上每条 IP 要起两次 route.exe
                     # （先 delete 再 -p add），100 个域名 ≈ 800 次进程创建，
                     # 逼近 run_elevated_win 的 90 秒超时。60 个留足余量。

_auto_domains = {}          # {domain: last_seen_timestamp}
_auto_lock = threading.Lock()
_auto_thread = None
_auto_enabled = True        # 前端可开关
# 最近一次扫描的实况：给界面回答「为什么这里是空的」
_auto_status = {"at": 0.0, "found": 0, "tracked": 0, "sources": [], "error": ""}



def _chrome_history_paths():
    """Chrome / Edge / Brave 的 History 库路径（含所有 Profile）。"""
    home = os.path.expanduser("~")
    bases = [
        os.path.join(home, "Library/Application Support/Google/Chrome"),
        os.path.join(home, "Library/Application Support/Microsoft Edge"),
        os.path.join(home, "Library/Application Support/BraveSoftware/Brave-Browser"),
        os.path.join(home, ".config/google-chrome"),
        os.path.join(home, ".config/microsoft-edge"),
    ]
    # ⚠️ 必须先判空再拼。os.path.join("", "Google/Chrome/User Data") 得到的是
    #    **相对路径** `Google/Chrome/User Data` —— 在 macOS / Linux 上 LOCALAPPDATA
    #    必然为空，这条相对路径会跟着进程 cwd 跑，属于「碰巧才可能命中」的隐患。
    la = os.environ.get("LOCALAPPDATA") or ""
    if la:
        bases += [
            os.path.join(la, "Google", "Chrome", "User Data"),
            os.path.join(la, "Microsoft", "Edge", "User Data"),
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


def _short_path(path):
    """把家目录缩成 ~，免得状态提示里塞一条又长又私的绝对路径。"""
    try:
        home = os.path.expanduser("~")
        if path.startswith(home):
            return "~" + path[len(home):]
    except Exception:  # noqa: BLE001
        pass
    return path


def _browser_of(path):
    """从历史库路径反推浏览器名 —— 只用于给人看的状态提示。"""
    low = path.lower()
    for key, name in (("microsoft/edge", "Edge"), ("microsoft\\edge", "Edge"),
                      ("chrome", "Chrome"), ("brave", "Brave"),
                      ("firefox", "Firefox"), ("mozilla", "Firefox"),
                      ("safari", "Safari")):
        if key in low:
            return name
    return "浏览器"



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
    """从 URL 提取主机名：去 scheme / userinfo / path / query / port，**保留子域**。

    ⚠️ 特意**不剥 `www.`**（曾经剥过，是错的，见本节的坑 1）：
    国内站的 apex 与 www 解析出来的 IP 零交集，剥掉就会给错的 IP 加路由。
    我们要的就是「浏览器实际连的那个主机名」。
    """
    if not url:
        return None
    m = re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", url)
    rest = url[m.end():] if m else url
    host = rest.split("/")[0].split("?")[0].split("#")[0]
    host = host.split("@")[-1]          # 去掉 user:pass@
    host = re.sub(r":\d+$", "", host)   # 去掉端口
    host = host.lower().strip(".")
    if not host or "." not in host:
        return None
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):  # 裸 IP 不要
        return None
    if host.endswith((".local", ".internal", ".localhost", ".in-addr.arpa")):
        return None
    return host


def _classify_read_error(exc):
    """把「读历史库失败」归类成人能看懂的原因。

    macOS 的 TCC（完全磁盘访问）保护有两种脸色：
      · 直接 open → sqlite3.OperationalError: unable to open database file
      · 先复制再读 → PermissionError / OSError EPERM
    两种都归到 denied，前端据此提示去开权限。
    """
    import errno as _errno
    if isinstance(exc, PermissionError):
        return "denied"
    if getattr(exc, "errno", None) in (_errno.EACCES, _errno.EPERM):
        return "denied"
    if isinstance(exc, sqlite3.Error) and "unable to open" in str(exc).lower():
        return "denied"
    return "error"



def _scan_history_once():
    """扫一遍所有浏览器历史库。

    返回 (found, sources)：
      found   = {domain: last_visit_timestamp}
      sources = [{"kind", "path", "state", "n", "msg"}]，state ∈ ok / denied / error

    sources 是给界面用的 —— 「为什么追踪列表是空的」必须能回答出来。
    """
    now = time.time()
    found = {}
    sources = []

    def merge(dom, ts):
        if dom and ts:
            prev = found.get(dom, 0)
            if ts > prev:
                found[dom] = ts

    def note(kind, path, state, n=0, msg=""):
        sources.append({"kind": kind,
                        "path": _short_path(path),
                        "state": state, "n": n, "msg": str(msg)[:160]})

    # ---- Chrome / Edge / Brave：last_visit_time 是 1601 起的微秒 ----
    EPOCH_1601 = 11644473600
    for p in _chrome_history_paths():
        kind = _browser_of(p)
        tmp = None
        try:
            # Chrome 运行时库被锁，先复制一份再读
            tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
            tmp.close()
            shutil.copyfile(p, tmp.name)
            n = 0
            con = sqlite3.connect(f"file:{tmp.name}?mode=ro", uri=True)
            try:
                for url, t in con.execute(
                        "SELECT url, last_visit_time FROM urls "
                        "ORDER BY last_visit_time DESC LIMIT 200"):
                    merge(_extract_domain(url),
                          t / 1_000_000 - EPOCH_1601 if t else 0)
                    n += 1
            finally:
                con.close()
            note(kind, p, "ok", n)
        except (OSError, sqlite3.Error) as e:
            note(kind, p, _classify_read_error(e), 0, e)
        finally:
            # ⚠️ 必须在 finally 里删。以前 unlink 写在 con.close() 之后，
            #    copyfile 一失败就直接跳走 → 副本永远留下（每 30 秒一个）。
            if tmp is not None:
                try:
                    os.unlink(tmp.name)
                except OSError:
                    pass

    # ---- Firefox：visit_date 是 1970 起的微秒 ----
    for p in _firefox_history_paths():
        try:
            n = 0
            con = sqlite3.connect(f"file:{p}?mode=ro", uri=True)
            try:
                for url, t in con.execute(
                        "SELECT url, visit_date FROM moz_places, moz_historyvisits "
                        "WHERE moz_places.id = moz_historyvisits.place_id "
                        "ORDER BY visit_date DESC LIMIT 200"):
                    merge(_extract_domain(url), (t or 0) / 1_000_000)
                    n += 1
            finally:
                con.close()
            note("Firefox", p, "ok", n)
        except (OSError, sqlite3.Error) as e:
            note("Firefox", p, _classify_read_error(e), 0, e)

    # ---- Safari：visit_time 是 2001 起的秒（Cocoa epoch）----
    p = _safari_history_path()
    if p:
        try:
            n = 0
            con = sqlite3.connect(f"file:{p}?mode=ro", uri=True)
            try:
                for url, t in con.execute(
                        "SELECT url, visit_time FROM history_items, history_visits "
                        "WHERE history_items.id = history_visits.history_item "
                        "ORDER BY visit_time DESC LIMIT 200"):
                    merge(_extract_domain(url), (t or 0) + 978307200)
                    n += 1
            finally:
                con.close()
            note("Safari", p, "ok", n)
        except (OSError, sqlite3.Error) as e:
            note("Safari", p, _classify_read_error(e), 0, e)

    return {d: t for d, t in found.items() if t > 0}, sources


def auto_domains_loop():
    """后台循环：把最近访问的新域名纳入追踪，过期的移除。"""
    global _auto_status
    while True:
        try:
            if _auto_enabled:
                now = time.time()
                fresh, sources = _scan_history_once()
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
                    # 上限保护：浏览一整天会攒出上百个域名，
                    # 它们最终都会变成直连路由 —— 丢最旧的，留住「最近在看的」。
                    if len(_auto_domains) > AUTO_MAX:
                        drop = sorted(_auto_domains.items(),
                                      key=lambda kv: kv[1])[
                                          :len(_auto_domains) - AUTO_MAX]
                        for d, _ in drop:
                            _auto_domains.pop(d, None)
                    _auto_status = {
                        "at": now,
                        "found": len(fresh),
                        "tracked": len(_auto_domains),
                        "sources": sources,
                        "error": "",
                    }
        except Exception as e:  # noqa: BLE001
            # 循环本身崩了也要让界面知道，否则又会回到「静默为空」
            with _auto_lock:
                _auto_status = {"at": time.time(), "found": 0,
                                "tracked": len(_auto_domains),
                                "sources": [],
                                "error": "%s: %s" % (type(e).__name__, e)}
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


def get_auto_status():
    """返回最近一次扫描的实况 —— 界面靠它回答「为什么追踪列表是空的」。"""
    with _auto_lock:
        return dict(_auto_status)


def toggle_auto_tracker(enabled):
    global _auto_enabled, _auto_status
    _auto_enabled = bool(enabled)
    if not _auto_enabled:
        with _auto_lock:
            _auto_status = {"at": time.time(), "found": 0, "tracked": 0,
                            "sources": [], "error": ""}


def auto_tracker_enabled():
    return _auto_enabled


