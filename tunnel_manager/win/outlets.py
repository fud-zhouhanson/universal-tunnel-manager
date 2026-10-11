# -*- coding: utf-8 -*-
"""tunnel_manager.win/outlets — Windows 可管理出口发现

由 P2 从 win/native.py 的第 850–1080 行**原样拆出**，正文逐字未改（与 P1 一样，只搬不改）。

【切片规则 —— 这不是漏写 import】
本项目按设计保持**单一扁平命名空间**：
  · 开发期入口 `python -m tunnel_manager.main` → 把所有切片拼进一个命名空间再执行；
  · 构建期 `bundle.py` → 同样顺序拼接成单文件 `dist/tunnel-manager.py`（纯源码，不含 exec）。
所以本文件里可以直接引用其它切片定义的函数与常量，无需 import。跨切片调用是既有事实。
本模块对外提供：discover_outlets
本模块依赖其它切片：_base、consts、detect/scan、outlet/manager、outlet/scene、util、win/apps、win/identify、win/nat_sys、win/probe
"""
>>>SLICE_BODY<<<
def discover_outlets(res=None):
    """列出本机所有可用出口（含自动探测到的启停方式）。"""
    if not isinstance(res, dict) or res.get("error"):
        res = do_scan()
    running = {s["name"] for s in (res.get("running_software") or [])}
    ifaces = res.get("interfaces") or []
    egress = res.get("egress_counts") or {}
    scene_key = (res.get("scene") or {}).get("key") or ""
    owners = _iface_owners(res)
    fingerprints = load_fingerprints()

    outlets = [{
        "key": DIRECT_OUTLET, "name": "物理直连", "cat": "直连",
        "desc": "不走任何隧道，全部经物理网卡出去",
        "running": True, "in_use": scene_key == "direct", "installed": True,
        "owned": [], "carrying": [],
        "adapter": {"kind": "direct", "apps": [],
                    "stop_jobs": [], "start_plists": []},
        "can_stop": True, "can_start": True,
        "hint": "停掉所有隧道客户端",
    }]

    for entry in TUNNEL_KNOWLEDGE:
        if entry.get("cat") not in OUTLET_CATS:
            continue                       # 覆盖网络 / 虚拟网卡不是「出口」
        kws = _kb_keywords(entry)
        owned, carrying = _outlet_ifaces(entry["name"], ifaces, egress, owners)

        if IS_WIN:
            # Windows：三个可控点只剩「注册表里的应用」与「SCM 服务」。
            apps, services, kind, hint = _win_outlet_parts(entry, kws)
            daemons, agents = [], []
            stop_jobs = start_plists = [s["name"] for s in services]
            can_stop = bool(services)
            can_start = bool(services or apps)
            installed = bool(apps or services)
            bits = ([_app_name(a) for a in apps]
                    + [s["display"] or s["name"] for s in services])
        else:
            apps = _find_apps(kws)
            daemons, agents = _find_launchd(kws)
            installed = bool(apps or daemons or agents)

            rule = OUTLET_RULES.get(entry["name"]) or {}
            if rule.get("mode") == "manual":
                stop_jobs, start_plists = [], []
                kind, can_stop, can_start = "manual", False, False
                hint = rule.get("reason") or "需要在它自己的界面里手动开关"
            else:
                cand = _stoppable(daemons + agents)
                stop_jobs = rule.get("stop_jobs") or [
                    f"{j['domain']}/{j['label']}" for j in cand]
                start_plists = rule.get("start_plists") or [j["plist"] for j in cand]
                can_stop = bool(stop_jobs)
                can_start = bool(start_plists or apps)
                kind = ("launchd" if (stop_jobs or start_plists)
                        else "app" if apps else "manual")
                hint = ("bootout 守护作业" if stop_jobs
                        else "打开它的 App，再在里面手动开启" if apps else "需要手动操作")

            bits = ([_app_name(a) for a in apps]
                    + [j["label"] for j in daemons + agents])

        if not installed and not owned:
            continue                       # 本机没装也没跑 → 不进列表
        outlets.append({
            "key": entry["name"], "name": entry["name"], "cat": entry["cat"],
            "desc": " / ".join(bits[:3]) or "仅检测到接口残留",
            "confirmed": entry["name"] in fingerprints,
            "fp_routes": len((fingerprints.get(entry["name"]) or {}).get("routes") or []),
            # 区分两件事：进程在跑 ≠ 它正在当出口。
            # 只有「它的接口在承载公网」才算真的在用。
            "running": bool(entry["name"] in running),
            "in_use": bool(carrying),
            "installed": installed,
            "owned": owned, "carrying": carrying,
            "adapter": {"kind": kind, "apps": apps,
                        "stop_jobs": stop_jobs, "start_plists": start_plists},
            "can_stop": can_stop, "can_start": can_start,
            "hint": hint,
        })

    # Windows 自带 VPN：连接名是用户自己起的，没法用关键词匹配，
    # 所以在 TUNNEL_KNOWLEDGE 之外单独枚举，一个连接一个出口。
    # 这类出口的好处是**不依赖任何客户端 App** —— rasdial 就能开关。
    if IS_WIN:
        for v in _win_vpn_list():
            key = VPN_PREFIX + v["name"]
            if any(o["key"] == key for o in outlets):
                continue
            conn = (v.get("status") or "").lower() == "connected"
            outlets.append({
                "key": key, "name": v["name"] + "（系统 VPN）", "cat": "系统VPN",
                "desc": v.get("server") or "Windows 自带的 VPN 连接",
                "confirmed": key in fingerprints,
                "fp_routes": len((fingerprints.get(key) or {}).get("routes") or []),
                "running": conn, "in_use": conn,
                "installed": True, "owned": [], "carrying": [],
                "adapter": {"kind": "vpn", "apps": [],
                            "stop_jobs": [], "start_plists": [],
                            "vpn": v["name"]},
                "can_stop": conn, "can_start": not conn,
                "hint": "用 rasdial 连接 / 断开，不必打开任何客户端",
            })
    return outlets


def _outlet_by_key(key, res=None):
    for o in discover_outlets(res):
        if o["key"] == key:
            return o
    return None


def _bootstrap_target(plist):
    """launchctl bootstrap 需要「域 + plist」两个参数。"""
    if "/Library/LaunchDaemons/" in plist:
        return f"system {plist}"
    return f"gui/{os.getuid()} {plist}"


def _ps_try_lines(verb, names):
    """生成「逐个 try/catch + 末尾报成败」的 PowerShell 片段。

    末尾必须输出 `__TM_OK__` / `__TM_FAIL__` —— 调用方靠这个标记判定，
    而不是靠返回码（见 `_win_elevated` 的说明）。
    """
    lines = ["$ok=$true"]
    for n in names:
        s = str(n).replace("'", "''")
        lines.append("try { %s -Name '%s' -ErrorAction Stop } catch { $ok=$false; "
                     "Write-Output ('ERR %s: ' + $_.Exception.Message) }"
                     % (verb, s, s))
    lines.append("if ($ok) { Write-Output '__TM_OK__' } "
                 "else { Write-Output '__TM_FAIL__' }")
    return lines


def _cmd_try(cmds):
    """给 cmd 命令行补上「失败就写 __TM_FAIL__」的尾巴。

    与 `_ps_try_lines` 同一个约定：成败由脚本自己喊出来，不看退出码
    （cmd 的 errorlevel 会被中间命令带偏，跟 PowerShell 的
    `$LASTEXITCODE` 一样不可信）。
    命令里可以用 `%TM_OUT%` 引用结果文件 —— 那由 run_elevated_win_cmd 设好。
    """
    out = []
    for c in cmds:
        out.append('%s >nul 2>&1 && >>"%%TM_OUT%%" echo __TM_OK__ '
                   '|| >>"%%TM_OUT%%" echo __TM_FAIL__ "%s"'
                   % (c, _cmd_safe(c)))
    return out


def _cmd_safe(s, n=70):
    """把一段命令名塞进 echo 里的安全形式（去掉 cmd 的元字符）。"""
    return re.sub(r'[&|<>^"\r\n]', " ", str(s))[:n]


def _cmd_start_stop(verb, names):
    """sc start / sc stop 的 cmd 行（对应 PowerShell 的 Start/Stop-Service）。"""
    lines = []
    for n in names:
        s = str(n).strip()
        lines.append('sc.exe %s "%s"' % (verb, s.replace('"', "")))
    return _cmd_try(lines)


def _cmd_set_dns(alias, servers):
    """netsh 版 DNS 设置（对应 Set-DnsClientServerAddress）。"""
    a = str(alias).replace('"', "")
    cmds = []
    if servers:
        cmds.append('netsh interface ipv4 set dns name="%s" static %s primary'
                    % (a, servers[0]))
        if len(servers) > 1:
            cmds.append('netsh interface ipv4 add dns name="%s" %s index=2'
                        % (a, servers[1]))
    else:
        cmds.append('netsh interface ipv4 set dns name="%s" source=dhcp' % a)
    return _cmd_try(cmds)


def _cmd_remove_routes(dests):
    """route delete 的 cmd 行（对应 Remove-NetRoute）。

    `route delete` 不吃 CIDR，得拆成「网络 + mask」，所以这里先转换；
    转不了的（比如 macOS netstat 那种「192.168.1」裸网络）就原样交给 route。
    """
    cmds = []
    for d in dests:
        s = str(d).strip()
        if "/" in s:
            net, _, plen = s.partition("/")
            mask = _mask_from_len(int(plen)) if plen.isdigit() else None
            if mask:
                cmds.append("route.exe delete %s mask %s" % (net, mask))
                continue
        cmds.append("route.exe delete %s" % s)
    return _cmd_try(cmds)


def _win_elevated(ps_lines, native_cmds=None):
    """跑一段提权操作。返回 (ok, 文本, 是否被取消了授权)。

    ⚠️ 为什么不能看返回码：`run_elevated_win` **从不返回 403**（403 是 sudo 的约定），
    它用 `rc=-1` 表示「UAC 被取消 / 执行超时」，而其余返回码的语义并不可靠
    （PowerShell 的 cmdlet 根本不设置 `$LASTEXITCODE`）。
    所以这里改用「脚本自己喊一句 `__TM_OK__`」的约定来判定成败。
    另外把整段包进 `& { … }`，这样 `*>&1 | Out-File` 才能把**每一行**输出都收进文件
    （否则只有最后一条语句的输出会被重定向，出错信息会丢）。

    PowerShell 被策略拦死时（真机实测有这种机器），改走 `cmd + 原生命令`。
    ⚠️ 刻意**不做「PS 失败后再补一次原生」的兜底** —— 那会让用户连着吃两个 UAC 弹窗。
    走哪条路只看 `ps_available()` 的探测结论。
    """
    if not ps_available()[0]:
        if native_cmds is None:
            return False, "PowerShell 被策略禁止，且该操作没有 cmd 等价写法", False
        return run_elevated_win_cmd(native_cmds)
    script = "& {\n" + "\n".join(ps_lines) + "\n}\n"
    rc, out, err = run_root(script, None)
    body = (out or "").strip()
    if rc == -1 and err:
        return False, err, True
    if "__TM_OK__" in body:
        return True, body.replace("__TM_OK__", "").strip(), False
    return False, (body.replace("__TM_FAIL__", "").strip()
                   or err or "执行失败"), False


