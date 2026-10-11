# -*- coding: utf-8 -*-
"""tunnel_manager.autotrack — 自动追踪：浏览器历史里的新域名

由 P2 从 config.py 的第 111–405 行**原样拆出**，正文逐字未改（与 P1 一样，只搬不改）。

【切片规则 —— 这不是漏写 import】
本项目按设计保持**单一扁平命名空间**：
  · 开发期入口 `python -m tunnel_manager.main` → 把所有切片拼进一个命名空间再执行；
  · 构建期 `bundle.py` → 同样顺序拼接成单文件 `dist/tunnel-manager.py`（纯源码，不含 exec）。
所以本文件里可以直接引用其它切片定义的函数与常量，无需 import。跨切片调用是既有事实。
本模块对外提供：auto_domains_loop、auto_tracker_enabled、get_auto_domains、get_auto_status、start_auto_tracker、toggle_auto_tracker
本模块依赖其它切片：config
"""
>>>SLICE_BODY<<<
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


