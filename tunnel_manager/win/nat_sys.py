# -*- coding: utf-8 -*-
"""tunnel_manager.win/nat_sys — Windows 原生读取 · 应用 / 服务 / VPN / 进程 / 提权

由 P2 从 win/native.py 的第 392–644 行**原样拆出**，正文逐字未改（与 P1 一样，只搬不改）。

【切片规则 —— 这不是漏写 import】
本项目按设计保持**单一扁平命名空间**：
  · 开发期入口 `python -m tunnel_manager.main` → 把所有切片拼进一个命名空间再执行；
  · 构建期 `bundle.py` → 同样顺序拼接成单文件 `dist/tunnel-manager.py`（纯源码，不含 exec）。
所以本文件里可以直接引用其它切片定义的函数与常量，无需 import。跨切片调用是既有事实。
本模块对外提供：run_elevated_win_cmd、win_env_status
本模块依赖其它切片：_base、consts、util、win/nat_net、win/probe
"""
>>>SLICE_BODY<<<
def _nat_registry_apps():
    """直接读注册表三个「卸载」键 —— 标准库 winreg，不需要 PowerShell。"""
    try:
        import winreg
    except ImportError:
        return []
    out, seen = [], set()
    sub = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
    roots = [(winreg.HKEY_LOCAL_MACHINE, winreg.KEY_WOW64_64KEY),
             (winreg.HKEY_LOCAL_MACHINE, winreg.KEY_WOW64_32KEY),
             (winreg.HKEY_CURRENT_USER, 0)]
    for hive, flag in roots:
        try:
            key = winreg.OpenKey(hive, sub, 0, winreg.KEY_READ | flag)
        except OSError:
            continue
        try:
            count = winreg.QueryInfoKey(key)[0]
            for i in range(count):
                try:
                    child = winreg.EnumKey(key, i)
                    with winreg.OpenKey(key, child) as sk:
                        def _gv(v):
                            try:
                                return winreg.QueryValueEx(sk, v)[0]
                            except OSError:
                                return ""
                        dn = str(_gv("DisplayName") or "")
                        if not dn or dn.lower() in seen:
                            continue
                        seen.add(dn.lower())
                        out.append({"name": dn,
                                    "loc": str(_gv("InstallLocation") or ""),
                                    "icon": str(_gv("DisplayIcon") or "")})
                except OSError:
                    continue
        finally:
            try:
                winreg.CloseKey(key)
            except OSError:
                pass
    return out


def _nat_service_list():
    """`sc query type= service state= all` —— 字段名恒为英文，不受语言影响。

    retries=1：只读、正常 <1s，真机上有安全软件时偶发被拦一次是常态。
    """
    rc, out, _ = run(["sc.exe", "query", "type=", "service", "state=", "all"],
                     timeout=45, retries=1)
    if rc != 0 or not out:
        return []
    res, cur = [], None
    for line in out.splitlines():
        s = line.strip()
        if s.startswith("SERVICE_NAME:"):
            if cur and cur.get("name"):
                res.append(cur)
            cur = {"name": s.split(":", 1)[1].strip(),
                   "display": "", "running": False}
        elif cur is not None and s.startswith("DISPLAY_NAME:"):
            cur["display"] = s.split(":", 1)[1].strip()
        elif cur is not None and s.startswith("STATE"):
            v = s.split(":", 1)[1].strip().upper()
            cur["running"] = v.startswith("4") or "RUNNING" in v
    if cur and cur.get("name"):
        res.append(cur)
    return res


def _nat_vpn_list():
    """系统 VPN = rasphone.pbk（INI 文件）。读文件，不需要 PowerShell。"""
    bases = [os.environ.get("APPDATA") or "",
             os.environ.get("PROGRAMDATA") or ""]
    out, seen = [], set()
    for base in bases:
        if not base:
            continue
        path = os.path.join(base, "Microsoft", "Network", "Connections",
                            "Pbk", "rasphone.pbk")
        try:
            with open(path, "rb") as f:
                raw = f.read()
        except OSError:
            continue
        txt = ""
        for enc in ("utf-8-sig", "gbk", "utf-16", "latin-1"):
            try:
                txt = raw.decode(enc)
                if "[" in txt:
                    break
            except (UnicodeDecodeError, LookupError):
                continue
        if not txt:
            continue
        for blk in re.split(r"^\[", txt, flags=re.M)[1:]:
            lines = blk.splitlines()
            if not lines:
                continue
            name = lines[0].strip().rstrip("]").strip()
            if not name or name in seen:
                continue
            body = "\n".join(lines[1:])
            srv = ""
            for pat in (r"^\s*PhoneNumber\s*=\s*(\S+)",
                        r"^\s*ServerAddress\s*=\s*(\S+)",
                        r"^\s*Address\s*=\s*(\S+)"):
                m = re.search(pat, body, re.M | re.I)
                if m:
                    srv = m.group(1)
                    break
            seen.add(name)
            out.append({"name": name, "server": srv, "status": ""})
    return out


def _nat_processes():
    """`tasklist /fo csv /nh` → 进程名（ASCII），比 Get-Process 更便宜。"""
    rc, out, _ = run(["tasklist", "/fo", "csv", "/nh"], timeout=40)
    if rc != 0 or not out:
        return ""
    names = []
    for line in out.splitlines():
        m = re.match(r'\s*"([^"]+)"', line)
        if m:
            names.append(m.group(1).lower())
    return " ".join(names)


def _nat_tunnel_server_ips(keywords):
    """`netstat -ano` + `tasklist` 代替 Get-NetTCPConnection。"""
    rc, out, _ = run(["netstat", "-ano"], timeout=30)
    if rc != 0 or not out:
        return set()
    pid2name = {}
    rc2, tbl, _ = run(["tasklist", "/fo", "csv", "/nh"], timeout=40)
    if rc2 == 0:
        for line in tbl.splitlines():
            m = re.match(r'\s*"([^"]+)","(\d+)"', line)
            if m:
                pid2name[m.group(2)] = m.group(1).lower()
    found = set()
    for line in out.splitlines():
        p = line.split()
        if len(p) < 5 or p[0].upper() != "TCP" or p[3].upper() != "ESTABLISHED":
            continue
        host = p[2].rsplit(":", 1)[0].strip("[]")
        if not re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host):
            continue
        if not is_public_ip(host):
            continue
        name = pid2name.get(p[4], "")
        if name and any(k in name for k in keywords):
            found.add(host)
    return found


def run_elevated_win_cmd(commands):
    """PowerShell 不可用时的提权通道：`cmd.exe /c <临时 bat>`。

    与 PowerShell 版一样靠「脚本自己写结果文件 + 末尾哨兵」回读，
    不看退出码（cmd 的 errorlevel 会被中间命令带偏）。
    bat 一律写 **GBK**（本项目的既定约定：Windows 上不能指望 chcp）。
    """
    import ctypes
    out_tmp = os.path.join(tempfile.gettempdir(),
                           "tunmgr_out_%d.txt" % os.getpid())
    try:
        os.remove(out_tmp)
    except OSError:
        pass
    lines = ["@echo off",
             'set "TM_OUT=%s"' % out_tmp,
             '>>"%TM_OUT%" echo __TM_BEGIN__']
    lines.extend(commands)
    lines.append('>>"%TM_OUT%" echo __TM_DONE__')
    bat = os.path.join(tempfile.gettempdir(), "tunmgr_%d.bat" % os.getpid())
    text = "\r\n".join(lines) + "\r\n"
    try:
        data = text.encode("gbk")
    except UnicodeEncodeError:
        data = text.encode("gbk", "replace")
    try:
        with open(bat, "wb") as f:
            f.write(data)
    except OSError as e:
        return False, "临时脚本写不进去：%s" % e, False
    params = '/c "%s"' % bat if " " not in bat else '/c ""%s""' % bat
    try:
        rc = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", "cmd.exe", params, None, 0)
    except OSError as e:
        return False, "UAC 启动失败: %s" % e, False
    if rc <= 32:
        return False, "UAC 被取消或被拒绝", True
    deadline = time.time() + 90
    content = ""
    finished = False
    while time.time() < deadline:
        time.sleep(0.4)
        try:
            with open(out_tmp, "rb") as f:
                raw = f.read()
        except OSError:
            continue
        for enc in ("utf-8", "gbk", "utf-16"):
            try:
                content = raw.decode(enc)
                break
            except UnicodeDecodeError:
                continue
        else:
            content = raw.decode("utf-8", "replace")
        if "__TM_DONE__" in content:
            finished = True
            break
    for p in (bat, out_tmp):
        try:
            os.remove(p)
        except OSError:
            pass
    if not finished:
        return False, "提权命令执行超时（90 秒）", False
    body = content.replace("__TM_BEGIN__", "").replace("__TM_DONE__", "")
    body = "\n".join(l for l in body.splitlines() if l.strip())
    ok = "__TM_FAIL__" not in body
    return ok, body.strip(), False


def win_env_status():
    """Windows 上「读取通道到底通不通」—— 让界面能解释「为什么一片空白」。

    非 Windows 返回空 dict（前端据此不显示这块）。
    """
    if not IS_WIN:
        return {}
    ok, err = ps_available()
    if ok:
        return {"powershell": True, "powershell_error": "",
                "native_fallback": False, "native_ifaces": 0,
                "note": ""}
    try:
        n = len(_nat_interfaces())
    except Exception:                    # noqa: BLE001 —— 诊断信息本身不该炸
        n = 0
    if n:
        note = "PowerShell 被系统策略禁用，已改用原生命令读取（当前读到 %d 个网卡）" % n
    else:
        note = ("PowerShell 被系统策略禁用，原生命令也没读上网卡信息 —— "
                "本机可能装了企业安全管理软件。程序仍能启动，但「网卡 / 隧道 / "
                "出口」这些依赖系统查询的功能会不全。")
    return {"powershell": False, "powershell_error": err[:300],
            "native_fallback": n > 0, "native_ifaces": n, "note": note}


