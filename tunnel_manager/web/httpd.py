# -*- coding: utf-8 -*-
"""tunnel_manager.web/httpd — HTTP 服务（CSRF / Host 头 / DNS rebinding 防护）

由 P1 从 server.py 的第 6492–6859 行**整块搬迁**而来，正文逐字未改。

【切片规则 —— 这不是漏写 import】
本项目按设计保持**单一扁平命名空间**：
  · 开发期入口 `python -m tunnel_manager.main` → 把所有切片拼进一个命名空间再执行；
  · 构建期 `bundle.py` → 同样顺序拼接成单文件 `dist/tunnel-manager.py`（纯源码，不含 exec）。
所以本文件里可以直接引用其它切片定义的函数与常量，无需 import。跨切片调用是既有事实。
本模块对外提供：EMBEDDED_HTML、Handler、get_html、host_allowed、origin_allowed、pick_port
本模块依赖其它切片：_base、config、detect/scan、health/flow、health/flowrate、outlet/manager、outlet/routes、outlet/scene、steam/diagnose、util、win/native
"""
>>>SLICE_BODY<<<
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
            elif path == "/api/flow":
                # 只读采样，不改任何系统配置 → 走"读请求"校验即可，不需要 CSRF
                self._json(200, flow_get())
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
                raw = (payload.get("domain") or "").strip().lower()
                if not raw:
                    self._json(400, {"ok": False, "message": "域名不能为空"})
                    return
                # 用户可能粘整条 URL（https://www.a.com/path?x=1）→ 先规范化成主机名。
                # ⚠️ 只剥 scheme / 路径 / 端口，**不剥 www.**（理由见本节坑 1）。
                dom = _extract_domain(raw)
                if not dom:
                    self._json(400, {"ok": False,
                                     "message": f"看不出这是域名：{raw[:60]}"})
                    return
                with _auto_lock:
                    _auto_domains[dom] = time.time()
                self._json(200, {"ok": True, "domain": dom,
                                 "message": f"已加入追踪：{dom}"
                                            f"（{AUTO_EXPIRE // 60} 分钟内没再访问会自动移除；"
                                            f"要长期生效请用上面的域名列表）",
                                 "result": do_scan()})
                return
            if path == "/api/auto/promote":
                if not self._check_write(payload):
                    return
                # 把追踪中的临时域名「转正」：写进配置表 → 长期生效、不再 10 分钟过期。
                # 解决的是「追踪列表里看到某个网站一直被隧道接管，却无处一键处理」。
                dom = _extract_domain((payload.get("domain") or "").strip().lower())
                if not dom:
                    self._json(400, {"ok": False, "message": "域名不合法"})
                    return
                cfg = load_config()
                if any((x or "").strip().lower() == dom for x in cfg):
                    msg = f"{dom} 已经在「需要直连的域名列表」里了"
                else:
                    cfg.append(dom)
                    save_config(cfg)
                    msg = f"已加入「需要直连的域名列表」：{dom}（长期生效，不会再自动移除）"
                with _auto_lock:
                    _auto_domains.pop(dom, None)   # 已转正，不必再占临时名额
                self._json(200, {"ok": True, "domain": dom, "message": msg,
                                 "result": do_scan()})
                return
            if path == "/api/auto/unpin":
                if not self._check_write(payload):
                    return
                dom = (payload.get("domain") or "").strip().lower()
                with _auto_lock:
                    _auto_domains.pop(dom, None)
                self._json(200, {"ok": True, "domain": dom,
                                 "message": f"已停止追踪 {dom}",
                                 "result": do_scan()})
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
                if r.get("message") in PRIV_MSGS:
                    self._json(403, priv_error())
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
                if msg in PRIV_MSGS:
                    self._json(403, priv_error())
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
                if msg in PRIV_MSGS:
                    self._json(403, priv_error())
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
                    self._json(403, dict(priv_error(res.get("message")),
                                         scene_switch=res))
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
                    self._json(403, dict(priv_error(r.get("message")),
                                         rescue=r.get("rescue")))
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

            if ok is None and msg in ("NEED_SUDO", "NEED_ADMIN", "BAD_PASSWORD"):
                if msg == "BAD_PASSWORD":
                    self._json(403, {"error": msg, "message": "密码错误"})
                else:
                    self._json(403, priv_error())
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


