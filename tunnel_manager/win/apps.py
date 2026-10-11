# -*- coding: utf-8 -*-
"""tunnel_manager.win/apps — Windows 出口条目装配

由 P2 从 win/native.py 的第 645–849 行**原样拆出**，正文逐字未改（与 P1 一样，只搬不改）。

【切片规则 —— 这不是漏写 import】
本项目按设计保持**单一扁平命名空间**：
  · 开发期入口 `python -m tunnel_manager.main` → 把所有切片拼进一个命名空间再执行；
  · 构建期 `bundle.py` → 同样顺序拼接成单文件 `dist/tunnel-manager.py`（纯源码，不含 exec）。
所以本文件里可以直接引用其它切片定义的函数与常量，无需 import。跨切片调用是既有事实。
本模块对外提供：system_vpns
本模块依赖其它切片：outlet/manager、outlet/scene_ops、util、win/nat_sys、win/probe
"""
>>>SLICE_BODY<<<
def _win_registry_apps():
    """从注册表三个「卸载」键读出已安装程序（名称 / 安装位置 / 图标）。"""
    if not ps_available()[0]:
        return _nat_registry_apps()          # winreg 直读，不依赖 PowerShell
    rc, out, _ = run_ps(
        "[Console]::OutputEncoding=[Text.Encoding]::UTF8;"
        "$k=@('HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',"
        "'HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',"
        "'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*');"
        "Get-ItemProperty $k -ErrorAction SilentlyContinue | "
        "Where-Object { $_.DisplayName } | "
        "Select-Object DisplayName,InstallLocation,DisplayIcon | "
        "ConvertTo-Json -Depth 3"
    )
    if rc != 0 or not out:
        return []
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return []
    if isinstance(data, dict):
        data = [data]
    return [{"name": str(d.get("DisplayName") or ""),
             "loc": str(d.get("InstallLocation") or ""),
             "icon": str(d.get("DisplayIcon") or "")}
            for d in data if d.get("DisplayName")]


def _win_service_list():
    """Windows 服务清单（Name / DisplayName / 是否在跑）。"""
    if not ps_available()[0]:
        return _nat_service_list()           # sc query，字段名恒英文
    rc, out, _ = run_ps(
        "[Console]::OutputEncoding=[Text.Encoding]::UTF8;"
        "Get-Service | Select-Object Name,DisplayName,Status | ConvertTo-Json -Depth 3"
    )
    if rc != 0 or not out:
        return []
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return []
    if isinstance(data, dict):
        data = [data]
    res = []
    for d in data:
        try:
            running = int(d.get("Status")) == 4     # ServiceControllerStatus.Running
        except (TypeError, ValueError):
            running = False
        res.append({"name": str(d.get("Name") or ""),
                    "display": str(d.get("DisplayName") or ""),
                    "running": running})
    return res


def _win_installed_apps():
    return _win_cached("apps", 120, _win_registry_apps)


def _win_services():
    return _win_cached("svcs", 30, _win_service_list)


def _win_exe_of(app, keywords, max_scan=400):
    """在安装目录里挑一个最像「主程序」的 exe。"""
    icon = (app.get("icon") or "").strip().strip('"')
    if icon.lower().endswith(".exe") and os.path.isfile(icon):
        return icon
    loc = (app.get("loc") or "").strip().strip('"')
    if not loc or not os.path.isdir(loc):
        return ""
    try:
        names = sorted(os.listdir(loc))[:max_scan]
    except OSError:
        return ""
    first = ""
    for n in names:
        low = n.lower()
        if not low.endswith(".exe"):
            continue
        if any(k in low for k in keywords):
            return os.path.join(loc, n)
        if not first and "unins" not in low:
            first = os.path.join(loc, n)
    return first


def _find_apps_win(keywords):
    """按关键词找已安装客户端的主程序（对应 macOS 的 _find_apps）。"""
    hits = []
    for a in _win_installed_apps():
        blob = (a["name"] + " " + a["loc"]).lower()
        if not any(k in blob for k in keywords):
            continue
        exe = _win_exe_of(a, keywords)
        if exe:
            hits.append(exe)
    return hits


def _find_services_win(keywords):
    """按关键词找 Windows 服务（对应 macOS 的 _find_launchd）。

    短于 4 个字符的关键词一律不参与服务匹配 —— 否则 `wg` / `ssr` 这类
    会和系统自带服务撞名，把不相干的 SCM 条目认成隧道客户端。
    """
    kw = [k for k in keywords if len(k) >= 4]
    if not kw:
        return []
    hits = []
    for s in _win_services():
        blob = (s["name"] + " " + s["display"]).lower()
        if any(k in blob for k in kw):
            hits.append(s)
    return hits


def _win_vpn_list():
    """Windows 自带 VPN 连接（可脱离客户端 App，直接用 rasdial 启停）。"""
    if not ps_available()[0]:
        return _nat_vpn_list()               # 读 rasphone.pbk
    rc, out, _ = run_ps(
        "[Console]::OutputEncoding=[Text.Encoding]::UTF8;"
        "Get-VpnConnection -ErrorAction SilentlyContinue | "
        "Select-Object Name,ServerAddress,ConnectionStatus | ConvertTo-Json -Depth 3"
    )
    if rc != 0 or not out:
        return []
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return []
    if isinstance(data, dict):
        data = [data]
    res = []
    for d in data:
        name = str(d.get("Name") or "")
        if name:
            res.append({"name": name,
                        "server": str(d.get("ServerAddress") or ""),
                        "status": str(d.get("ConnectionStatus") or "")})
    return res


def _win_outlet_parts(entry, keywords):
    """Windows 上一个出口的「应用 / 服务 / 提示」。

    返回 (apps, services, kind, hint)；services 是服务字典列表。
    停与启用的是同一批服务 —— Windows 上没有 launchd 那种「域/标签」的区分。

    ⚠️ `OUTLET_RULES` 里给 aTrust 写死的 stop_jobs 是 **macOS 的 launchd 标签**，
    在 Windows 上根本不存在。所以这里**不读那张表**，一律以实测枚举到的
    SCM 服务为准（只有 `mode: manual` 的意思在 Windows 上依然成立）。
    """
    rule = OUTLET_RULES.get(entry["name"]) or {}
    apps = _find_apps_win(keywords)
    manual = rule.get("mode") == "manual"
    services = [] if manual else _find_services_win(keywords)
    if manual:
        hint = rule.get("reason") or "需要在它自己的界面里手动开关"
    elif services:
        hint = f"停止 Windows 服务（{len(services)} 个）"
    elif apps:
        hint = "打开它的 App，再在里面手动开启"
    else:
        hint = "需要手动操作"
    kind = "service" if services else ("app" if apps else "manual")
    return apps, services, kind, hint


def system_vpns():
    """macOS 原生 VPN 列表（scutil --nc）—— 启停不需要 root。"""
    out = []
    for line in _sh("scutil --nc list").splitlines():
        m = re.match(r'\s*(\*)?\s*\(([^)]*)\)\s+([0-9A-Fa-f-]{8,})\s+"([^"]+)"', line)
        if m:
            out.append({"name": m.group(4), "id": m.group(3),
                        "status": m.group(2), "selected": bool(m.group(1))})
    return out


def _outlet_ifaces(entry_name, ifaces, egress, owners=None):
    """该客户端当前拥有的隧道接口，以及其中在承载公网的。"""
    owned, carrying = [], []
    for i in ifaces:
        if i.get("kind") != "隧道":
            continue
        name = i["name"]
        own = ((owners or {}).get(name) or {}).get("owner") or i.get("owner") or ""
        if own != entry_name:
            continue
        owned.append(name)
        try:
            if int(egress.get(name, 0) or 0) > 0:
                carrying.append(name)
        except (TypeError, ValueError):
            pass
    return owned, carrying


def _app_name(path):
    return os.path.basename(path)[:-4] if path.endswith(".app") else os.path.basename(path)


