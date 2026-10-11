# -*- coding: utf-8 -*-
"""tunnel_manager.util — 通用工具（命令执行 / 编码 / 解析）

由 P1 从 server.py 的第 322–434 行**整块搬迁**而来，正文逐字未改。

【切片规则 —— 这不是漏写 import】
本项目按设计保持**单一扁平命名空间**：
  · 开发期入口 `python -m tunnel_manager.main` → 把所有切片拼进一个命名空间再执行；
  · 构建期 `bundle.py` → 同样顺序拼接成单文件 `dist/tunnel-manager.py`（纯源码，不含 exec）。
所以本文件里可以直接引用其它切片定义的函数与常量，无需 import。跨切片调用是既有事实。
本模块对外提供：run、run_elevated_win、run_ps、run_root、verify_sudo
本模块依赖其它切片：_base
"""
>>>SLICE_BODY<<<
# ======================================================================
# 二、通用工具
# ======================================================================

_sudo_pw = None
_lock = threading.Lock()
_csrf_token = secrets.token_hex(16)  # 进程级 CSRF token，前端必须回传


def run(cmd, timeout=30):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout, errors="replace")
        return p.returncode, p.stdout.strip(), p.stderr.strip()
    except (OSError, subprocess.SubprocessError) as e:
        return -1, "", str(e)


def run_ps(script, timeout=60):
    try:
        p = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive",
             "-Command", script],
            capture_output=True, text=True, timeout=timeout, errors="replace")
        return p.returncode, p.stdout.strip(), p.stderr.strip()
    except (OSError, subprocess.SubprocessError) as e:
        return -1, "", str(e)


def run_root(cmd_str, pw=None):
    if IS_WIN:
        return run_elevated_win(cmd_str)
    if os.geteuid() == 0:
        return run(["bash", "-c", cmd_str])
    password = pw if pw is not None else _sudo_pw
    if password is None:
        return 403, "", "NEED_SUDO"
    try:
        p = subprocess.run(["sudo", "-S", "-k", "bash", "-c", cmd_str],
                           input=password + "\n", capture_output=True,
                           text=True, timeout=120)
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
    try:
        rc = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", "powershell.exe", params, None, 0)
    except OSError as e:
        return -1, "", f"UAC 启动失败: {e}"
    if rc <= 32:
        return -1, "", "UAC 被取消或被拒绝"
    deadline = time.time() + 90
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
            body = content[:m.start()].rstrip()
            try:
                os.remove(ps_file)
                os.remove(out_tmp)
            except OSError:
                pass
            return int(m.group(1)), body, ""
    return -1, content, "UAC 执行超时"


def verify_sudo(password):
    global _sudo_pw
    if not password:
        return False, "空密码"
    try:
        p = subprocess.run(["sudo", "-S", "-v"], input=password + "\n",
                           capture_output=True, text=True, timeout=10)
        if p.returncode == 0 and "Sorry" not in p.stderr:
            with _lock:
                _sudo_pw = password
            return True, "ok"
        return False, "密码错误或被拒绝"
    except (OSError, subprocess.SubprocessError) as e:
        return False, str(e)


