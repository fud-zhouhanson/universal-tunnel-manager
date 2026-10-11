# -*- coding: utf-8 -*-
"""tunnel_manager.web/httpd — HTTP 服务（CSRF / Host 头 / DNS rebinding 防护）

由 P1 从 server.py 的第 6492–6859 行**整块搬迁**而来。
P4 把原来一条 200 行的 if/elif 链改成「路由表 + 小方法」，并把 30 个端点
统一挂上 `/api/v1/` 前缀（旧路径 `/api/...` 继续可用）——
**除结构外没有改任何业务逻辑**，用重构前后的逐端点差分测试做过核对。

【切片规则 —— 这不是漏写 import】
本项目按设计保持**单一扁平命名空间**：
  · 开发期入口 `python -m tunnel_manager.main` → 把所有切片拼进一个命名空间再执行；
  · 构建期 `bundle.py` → 同样顺序拼接成单文件 `dist/tunnel-manager.py`（纯源码，不含 exec）。
所以本文件里可以直接引用其它切片定义的函数与常量，无需 import。跨切片调用是既有事实。
本模块对外提供：API_V1、EMBEDDED_HTML、Handler、api_path、get_html、host_allowed、origin_allowed、pick_port
本模块依赖其它切片：_base、config、detect/scan、health/flow、health/flowrate、outlet/manager、outlet/routes、outlet/scene、steam/diagnose、util、win/native
"""
>>>SLICE_BODY<<<
# ======================================================================
# 十、HTTP 服务（v2：CSRF / Host 头 / DNS rebinding 防护）
# ======================================================================
#
# 路由为什么写成「表 + 小方法」而不是一条长链：
#   端点有 30 多个，if/elif 链既数不清有几个、也不好确认某个路径到底归谁。
#   表里一眼看全；加一个端点＝表里加一行 + 写一个小方法。
#   ⚠️ 表里的路径必须与前端 index.html 里 fetch 的路径一致 ——
#      改路径时两边一起改（selftest 会核对数量与关键路径）。

# 单文件分发版会把 index.html 的内容内嵌进这个变量（构建时填充）。
# 优先级：同目录 index.html > 内嵌 EMBEDDED_HTML > 兜底提示。
EMBEDDED_HTML = None

# `/api/v1/` 是**别名**，不是新命名空间：/api/v1/scan 与 /api/scan 等价。
# 之所以保留旧路径：用户可能存了书签，或在别处写了脚本调这套接口，
# 加版本号那天不该把他们的东西弄坏。
API_V1 = "/api/v1"


def api_path(path):
    """/api/v1/xxx → /api/xxx；其它路径原样返回（含 / 与 /index.html）。"""
    if path == API_V1:
        return "/api"
    if path.startswith(API_V1 + "/"):
        return "/api" + path[len(API_V1):]
    return path


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
    # ---- 路由表：路径 → 处理方法 ----
    # 读端点只校验 Host 头（GET 不改系统状态）
    GET_ROUTES = {
        "/api/scan": "_h_scan",
        "/api/config": "_h_get_config",
        "/api/flow": "_h_flow",
        "/api/steam/overview": "_h_steam_overview",
        "/api/steam/capture/result": "_h_capture_result",
    }
    # 写端点走 Host + Origin + CSRF 三重校验（在各自的 _h_* 里调 _check_write）
    POST_ROUTES = {
        "/api/sudo": "_h_sudo",
        "/api/config": "_h_post_config",
        "/api/auto/enable": "_h_auto_toggle",
        "/api/auto/disable": "_h_auto_toggle",
        "/api/auto/pin": "_h_auto_pin",
        "/api/auto/promote": "_h_auto_promote",
        "/api/auto/unpin": "_h_auto_unpin",
        "/api/outlet/forget": "_h_outlet_forget",
        "/api/outlet/identify": "_h_outlet_identify",
        "/api/outlet/cancel": "_h_outlet_cancel",
        "/api/outlet/stop": "_h_outlet_ctl",
        "/api/outlet/start": "_h_outlet_ctl",
        "/api/outlet/switch": "_h_outlet_ctl",
        "/api/scene/game": "_h_scene",
        "/api/scene/campus": "_h_scene",
        "/api/trace": "_h_trace",
        "/api/steam/probe": "_h_steam_probe",
        "/api/steam/diagnose": "_h_steam_diagnose",
        "/api/steam/capture/start": "_h_capture_start",
        "/api/steam/capture/stop": "_h_capture_stop",
        "/api/health/save": "_h_health_save",
        "/api/rescue": "_h_rescue",
        "/api/apply": "_h_apply",
        "/api/undo": "_h_undo",
        "/api/daemon/install": "_h_daemon",
        "/api/daemon/remove": "_h_daemon",
    }

    def log_message(self, fmt, *args):
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    # ---- 基础响应 ----
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

    def _dispatch(self, table, path, payload):
        name = table.get(path)
        if name is None:
            self._json(404, {"error": "not found"})
            return
        getattr(self, name)(path, payload)

    def do_GET(self):
        if not self._check_read():
            return
        path = api_path(self.path.split("?")[0])
        try:
            if path in ("/", "/index.html"):
                self._send_html()
                return
            self._dispatch(self.GET_ROUTES, path, None)
        except Exception as e:  # noqa: BLE001
            self._json(500, {"error": str(e)})

    def do_POST(self):
        # 注意顺序：**先解析 JSON 再查路由** —— 保持与改造前一致
        # （对未知路径发一段坏 JSON，得到的是 400 而不是 404）。
        path = api_path(self.path.split("?")[0])
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            payload = json.loads(raw.decode() or "{}")
        except json.JSONDecodeError:
            self._json(400, {"error": "bad json"})
            return
        try:
            self._dispatch(self.POST_ROUTES, path, payload)
        except Exception as e:  # noqa: BLE001
            self._json(500, {"error": str(e)})

    # ---- 读端点 ----
    def _h_scan(self, path, payload):
        self._json(200, do_scan())

    def _h_get_config(self, path, payload):
        self._json(200, {"domains": load_config()})

    def _h_flow(self, path, payload):
        # 只读采样，不改任何系统配置 → 走"读请求"校验即可，不需要 CSRF
        self._json(200, flow_get())

    def _h_steam_overview(self, path, payload):
        self._json(200, do_steam_overview())

    def _h_capture_result(self, path, payload):
        # 采样结果：中继名单只读本地缓存，避免这个 GET 卡在网络上
        _local_pops, _rev = _read_local_sdr()
        self._json(200, capture_result(sdr_relay_targets(_local_pops, limit=48)))

    # ---- 写端点：权限 / 配置 ----
    def _h_sudo(self, path, payload):
        if not self._check_write(payload):
            return
        ok, msg = verify_sudo(payload.get("password", ""))
        self._json(200 if ok else 403, {"ok": ok, "message": msg})

    def _h_post_config(self, path, payload):
        if not self._check_write(payload):
            return
        domains = save_config(payload.get("domains", []))
        self._json(200, {"ok": True, "domains": domains, "result": do_scan()})

    # ---- 写端点：自动追踪 ----
    def _h_auto_toggle(self, path, payload):
        if not self._check_write(payload):
            return
        on = path.endswith("/enable")
        toggle_auto_tracker(on)
        if not on:
            with _auto_lock:
                _auto_domains.clear()
        self._json(200, {"ok": True, "result": do_scan()})

    def _h_auto_pin(self, path, payload):
        if not self._check_write(payload):
            return
        # 手动把一个域名加入自动追踪集合（与浏览器历史发现的域名同等待遇：
        # 出现在自动追踪面板和路由表里，超过 AUTO_EXPIRE 没再访问则自动移除）
        raw = (payload.get("domain") or "").strip().lower()
        if not raw:
            self._json(400, {"ok": False, "message": "域名不能为空"})
            return
        # 用户可能粘整条 URL（https://www.a.com/path?x=1）→ 先规范化成主机名。
        # ⚠️ 只剥 scheme / 路径 / 端口，**不剥 www.**（理由见 config.py 的坑 1）。
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

    def _h_auto_promote(self, path, payload):
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

    def _h_auto_unpin(self, path, payload):
        if not self._check_write(payload):
            return
        dom = (payload.get("domain") or "").strip().lower()
        with _auto_lock:
            _auto_domains.pop(dom, None)
        self._json(200, {"ok": True, "domain": dom,
                         "message": f"已停止追踪 {dom}",
                         "result": do_scan()})

    # ---- 写端点：出口 ----
    def _h_outlet_forget(self, path, payload):
        if not self._check_write(payload):
            return
        ok, msg = forget_fingerprint(payload.get("key", ""))
        self._json(200 if ok else 500, {"ok": ok, "message": msg})

    def _h_outlet_identify(self, path, payload):
        if not self._check_write(payload):
            return
        r = identify_outlet(payload.get("key", ""), payload.get("password"))
        if r.get("message") in PRIV_MSGS:
            self._json(403, priv_error())
        else:
            self._json(200 if r.get("ok") else 500,
                       {"ok": r.get("ok"), "message": r.get("message"),
                        "identify": r})

    def _h_outlet_cancel(self, path, payload):
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

    def _h_outlet_ctl(self, path, payload):
        """停 / 启 / 切 —— 三个端点共用，动作从路径尾段取。"""
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

    def _h_scene(self, path, payload):
        if not self._check_write(payload):
            return
        res = do_scene(path.rsplit("/", 1)[-1], payload.get("password"))
        if res.get("ok"):
            self._json(200, {"ok": True, "message": res.get("message"),
                             "scene_switch": res})
        else:
            # 失败一律按「缺权限」回，前端据此弹密码框 / 提示 UAC。
            # 情景切换是半自动的，返回体里带完整步骤清单，前端直接渲染。
            self._json(403, dict(priv_error(res.get("message")),
                                 scene_switch=res))

    # ---- 写端点：体检 ----
    def _h_trace(self, path, payload):
        if not self._check_write(payload):
            return
        self._json(200, {"ok": True, "trace": do_trace()})

    def _h_health_save(self, path, payload):
        if not self._check_write(payload):
            return
        ok, msg = save_health()
        self._json(200 if ok else 500, {"ok": ok, "message": msg,
                                        "result": do_scan() if ok else None})

    def _h_rescue(self, path, payload):
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

    # ---- 写端点：Steam ----
    def _h_steam_probe(self, path, payload):
        if not self._check_write(payload):
            return
        r = do_steam_probe(appid=payload.get("appid"),
                           cell=payload.get("cell"),
                           force_online=bool(payload.get("refresh")))
        self._json(500 if r.get("error") else 200, r)

    def _h_steam_diagnose(self, path, payload):
        if not self._check_write(payload):
            return
        r = do_steam_diagnose(appid=payload.get("appid"),
                              cell=payload.get("cell"))
        self._json(500 if r.get("error") else 200, r)

    def _h_capture_start(self, path, payload):
        if not self._check_write(payload):
            return
        ok, msg = capture_start(payload.get("seconds") or 60,
                                payload.get("pid") or "")
        self._json(200 if ok else 409,
                   {"ok": ok, "message": msg, "capture": capture_state()})

    def _h_capture_stop(self, path, payload):
        if not self._check_write(payload):
            return
        ok, msg = capture_stop()
        self._json(200 if ok else 409,
                   {"ok": ok, "message": msg, "capture": capture_state()})

    # ---- 写端点：路由操作（三个端点共用同一套「成败 + 哨兵」收尾）----
    def _finish_action(self, ok, msg):
        if ok is None and msg in ("NEED_SUDO", "NEED_ADMIN", "BAD_PASSWORD"):
            if msg == "BAD_PASSWORD":
                self._json(403, {"error": msg, "message": "密码错误"})
            else:
                self._json(403, priv_error())
        elif ok:
            self._json(200, {"ok": True, "message": msg, "result": do_scan()})
        else:
            self._json(500, {"ok": False, "message": msg})

    def _h_apply(self, path, payload):
        if not self._check_write(payload):
            return
        self._finish_action(*do_apply(payload.get("password")))

    def _h_undo(self, path, payload):
        if not self._check_write(payload):
            return
        self._finish_action(*do_undo(payload.get("password")))

    def _h_daemon(self, path, payload):
        if not self._check_write(payload):
            return
        self._finish_action(
            *do_daemon("install" if path.endswith("install") else "remove",
                       payload.get("password")))


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
