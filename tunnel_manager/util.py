# -*- coding: utf-8 -*-
"""tunnel_manager.util — 通用工具（命令执行 / 编码 / 解析）

由 P1 从 server.py 的第 322–434 行**整块搬迁**而来，正文逐字未改。

【切片规则 —— 这不是漏写 import】
本项目按设计保持**单一扁平命名空间**：
  · 开发期入口 `python -m tunnel_manager.main` → 把所有切片拼进一个命名空间再执行；
  · 构建期 `bundle.py` → 同样顺序拼接成单文件 `dist/tunnel-manager.py`（纯源码，不含 exec）。
所以本文件里可以直接引用其它切片定义的函数与常量，无需 import。跨切片调用是既有事实。
本模块对外提供：T_CMD、T_PROBE、T_PS、T_READ、T_ROOT、is_elevated_win、priv_capability 等 15 个
本模块依赖其它切片：_base
"""
>>>SLICE_BODY<<<
# ======================================================================
# 二、通用工具
# ======================================================================

# ---- 统一超时（秒）--------------------------------------------------
# 以前这些数字散落在各切片里（30 / 60 / 120 / 20 / 10…），改一处得满仓库找。
#   T_READ  只读系统命令：route / ifconfig / netstat / arp / netsh，正常 <100ms
#   T_CMD   一般外部命令
#   T_PS    PowerShell —— 冷启动本身就要 1~2 秒，别跟普通命令用一个值
#   T_ROOT  提权批处理：sudo / UAC，里面可能是一整套脚本动作
#   T_PROBE sudo 免密探测 —— 必须短，探测不能把界面拖住
T_READ, T_CMD, T_PS, T_ROOT, T_PROBE = 20, 30, 60, 120, 10
# T_UAC_WAIT：等 UAC 弹窗被点掉 + 被提升的脚本自己跑完。
# 这个值是**对外承诺**的一部分 —— AUTO_MAX（追踪域名上限）就是按它倒推的
# （见 config.py：Windows 每条 IP 要起两次 route.exe，60 个域名 ≈ 800 次进程创建）。
# 改这里必须同步复核 AUTO_MAX。
T_UAC_WAIT = 90

_sudo_pw = None
_lock = threading.Lock()
_csrf_token = secrets.token_hex(16)  # 进程级 CSRF token，前端必须回传


def _exec(cmd, timeout, retries=0, backoff=0.25, strip=True):
    """所有外部命令的**唯一出口**：统一超时、统一重试、统一异常兜底。

    重试只针对「命令根本没跑起来 / 超时」这类**过程性失败**；
    命令跑起来了但返回非 0，一律原样交回 —— 那是业务结果，不该重试。
    """
    err = "未执行"
    for attempt in range(max(1, retries + 1)):
        try:
            p = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=timeout, errors="replace")
            out = p.stdout.strip() if strip else p.stdout
            return p.returncode, out, p.stderr.strip()
        except (OSError, subprocess.SubprocessError) as e:
            err = str(e)
        if attempt < retries:
            time.sleep(backoff * (attempt + 1))
    return -1, "", err


def run(cmd, timeout=T_CMD, retries=0, backoff=0.25):
    """跑一条外部命令 → (returncode, stdout, stderr)。

    默认 **不重试**。要重试只应该给确定偶发的调用点传 retries=1；
    **提权命令（run_root）永远不重试** —— 重试等于再弹一次 UAC / 再要一次密码，
    用户只会以为程序卡死了。
    """
    return _exec(cmd, timeout, retries, backoff, strip=True)


def run_ps(script, timeout=T_PS, retries=0):
    """跑一段 PowerShell。Windows 上也可能整段不可用（企业策略禁 powershell.exe），
    那种情况返回 rc=-1 是**预期**，调用方要按「通道不可用」处理而不是当崩溃。"""
    return _exec(["powershell.exe", "-NoProfile", "-NonInteractive",
                  "-Command", script],
                 timeout, retries, 0.25, strip=True)


def _sh(cmd, timeout=T_READ, retries=0):
    """跑一条只读 shell 命令，返回 stdout（**不 strip**，保留原排版）。

    为什么不 strip：`ifconfig` 靠「行首是不是空白」区分接口名行与选项行，
    strip 掉会把解析带偏。也正因如此它不能直接复用 run()。

    ⚠️ 只在 macOS / Linux 上有意义（Windows 没有 bash）。定义放在这里而不是
    各切片里，是为了让「超时 / 重试」永远只有一处实现。
    """
    return _exec(["bash", "-c", cmd], timeout, retries, 0.25,
                 strip=False)[1]


# ---- 提权能力「前置探测」------------------------------------------------
#
# 为什么需要：改路由 / 启停守护作业都要管理员权限。以前是**做到一半才发现没权限** ——
# 典型事故：情景切换先 bootout 掉 aTrust（成功），再去清残留路由（403），
# 用户就停在「aTrust 已退出、残留路由还挂着」的半残状态，比什么都不做更糟。
# 现在把「能不能提权」变成开工前先问一句，答不上来就整段降级成只读提示。

_sudo_probe = {"at": 0.0, "ok": False}
_SUDO_PROBE_TTL = 15      # 秒。界面会轮询 /api/scan，别每轮都 fork 一个 sudo


def is_elevated_win():
    """Windows 当前进程是否已提权。只查状态，不弹任何界面。"""
    if not IS_WIN:
        return False
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (OSError, AttributeError):
        return False


def sudo_available():
    """sudo 凭据是否仍在有效期内（**不需要密码**）。只探测，不执行任何特权动作。

    用 `sudo -n -v`：`-n` 表示「要密码就直接失败」，绝不会弹交互提示。
    """
    if IS_WIN:
        return is_elevated_win()
    if not hasattr(os, "geteuid"):       # 理论上不会走到，兜底防 AttributeError
        return False
    if os.geteuid() == 0:
        return True
    now = time.time()
    if _sudo_probe["ok"] and now - _sudo_probe["at"] < _SUDO_PROBE_TTL:
        return True
    rc = _exec(["sudo", "-n", "-v"], T_PROBE)[0]
    _sudo_probe.update(at=now, ok=(rc == 0))
    return _sudo_probe["ok"]


def priv_capability(pw=None):
    """开工前问一句「现在到底能不能提权」。

    返回 (ok, code, text)：
      ok=True            → 可以，放心往下做
      ok=False, code=…   → "NEED_SUDO" / "NEED_ADMIN"；调用方必须**立刻停手**，
                           降级为只读提示，绝不能把系统留在半完成状态
    """
    if IS_WIN:
        if is_elevated_win():
            return True, "", "当前已是管理员权限"
        return False, "NEED_ADMIN", "需要管理员授权（会弹出 UAC 确认框）"
    try:
        if os.geteuid() == 0:
            return True, "", "当前已是 root"
    except AttributeError:
        pass
    if pw or _sudo_pw is not None:
        return True, "", "已有管理员密码"
    if sudo_available():
        return True, "", "管理员凭据仍在有效期内"
    return False, "NEED_SUDO", "需要管理员密码"


def priv_status():
    """给界面看的「现在是只读、还是有权限」。只探测，不改任何东西。"""
    ok, code, text = priv_capability()
    return {"can_elevate": ok, "code": code, "text": text}


def run_root(cmd_str, pw=None):
    """以管理员身份跑一串命令。

    ⚠️ 这里是**所有提权动作的唯一闸门**，前置探测也做在这一层：
    没权限就直接返回哨兵，绝不 fork 出半个命令再失败。
    """
    if IS_WIN:
        return run_elevated_win(cmd_str)
    if os.geteuid() == 0:
        return run(["bash", "-c", cmd_str], timeout=T_ROOT)
    password = pw if pw is not None else _sudo_pw
    if password is None:
        # 没有密码可用。先问 sudo「你现在还要不要密码」——
        # 要 → 交回前端弹密码框；不要（凭据还在有效期内）→ 直接用 -n 跑。
        # 以前这里一律 403，于是用户在终端里刚 sudo 过、凭据明明有效，
        # 界面还是固执地要密码。
        if not sudo_available():
            return 403, "", "NEED_SUDO"
        return run(["sudo", "-n", "bash", "-c", cmd_str], timeout=T_ROOT)
    try:
        # 有密码时带 `-k`：先作废已有凭据再输密码，确保**验证的就是这一串**密码，
        # 而不是「旧凭据还有效所以通过了」。
        p = subprocess.run(["sudo", "-S", "-k", "bash", "-c", cmd_str],
                           input=password + "\n", capture_output=True,
                           text=True, timeout=T_ROOT)
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
        "$ErrorActionPreference='Continue'\n"
        f"{cmd_str} *>&1 | Out-File -FilePath '{out_tmp}' -Encoding UTF8\n"
        # PowerShell 的 cmdlet **不设置** $LASTEXITCODE（只有外部 exe 才会），
        # 所以直接写 \"RC:$LASTEXITCODE\" 可能变成光秃秃的 \"RC:\"，下面那句正则
        # 永远匹配不上 → 一直等到 90 秒超时。给个确定的数值兜底。
        "$__rc = if ($null -eq $LASTEXITCODE) { -1 } else { $LASTEXITCODE }\n"
        f"\"RC:$__rc\" | Out-File -FilePath '{out_tmp}' "
        f"-Append -Encoding UTF8\n"
    )
    ps_file = os.path.join(tempfile.gettempdir(),
                           f"tunmgr_{os.getpid()}.ps1")
    with open(ps_file, "w", encoding="utf-8-sig") as f:
        f.write(ps_script)
    params = f'-NoProfile -ExecutionPolicy Bypass -File "{ps_file}"'
    # 临时文件一律走 finally 清掉。以前只在「读到了 RC:」那条路径上删，
    # UAC 被取消 / 超时 / 异常退出都会把 .ps1 和输出文件留在 %TEMP% 里，
    # 每失败一次漏一对 —— 和「Chrome 库副本漏删」是同一类坑。
    try:
        try:
            rc = ctypes.windll.shell32.ShellExecuteW(
                None, "runas", "powershell.exe", params, None, 0)
        except OSError as e:
            return -1, "", f"UAC 启动失败: {e}"
        if rc <= 32:
            return -1, "", "UAC 被取消或被拒绝"
        deadline = time.time() + T_UAC_WAIT
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
                return int(m.group(1)), content[:m.start()].rstrip(), ""
        return -1, content, "UAC 执行超时"
    finally:
        for p in (ps_file, out_tmp):
            try:
                os.remove(p)
            except OSError:
                pass


def verify_sudo(password):
    global _sudo_pw
    if not password:
        return False, "空密码"
    try:
        p = subprocess.run(["sudo", "-S", "-v"], input=password + "\n",
                           capture_output=True, text=True, timeout=T_PROBE)
        if p.returncode == 0 and "Sorry" not in p.stderr:
            with _lock:
                _sudo_pw = password
            return True, "ok"
        return False, "密码错误或被拒绝"
    except (OSError, subprocess.SubprocessError) as e:
        return False, str(e)


