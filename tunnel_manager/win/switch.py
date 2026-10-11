# -*- coding: utf-8 -*-
"""tunnel_manager.win/switch — Windows 出口启动 / 停止 / 切换

由 P2 从 win/native.py 的第 1081–1309 行**原样拆出**，正文逐字未改（与 P1 一样，只搬不改）。

【切片规则 —— 这不是漏写 import】
本项目按设计保持**单一扁平命名空间**：
  · 开发期入口 `python -m tunnel_manager.main` → 把所有切片拼进一个命名空间再执行；
  · 构建期 `bundle.py` → 同样顺序拼接成单文件 `dist/tunnel-manager.py`（纯源码，不含 exec）。
所以本文件里可以直接引用其它切片定义的函数与常量，无需 import。跨切片调用是既有事实。
本模块对外提供：FP_FILE、cancel_switch、outlet_start、outlet_stop、switch_outlet
本模块依赖其它切片：_base、detect/scan、outlet/apply、outlet/manager、outlet/scene_ops、util、win/apps、win/outlets
"""
>>>SLICE_BODY<<<
# ---- launchd 作业标签 / plist 路径：拼进 root shell 之前先过白名单 ----
#
# ⚠️ 这不是多此一举：标签有一部分是**扫磁盘目录得到的 plist 文件名**
# （见 outlet/manager.py 的 _find_launchd），plist 路径同理。
# 它们会被拼进 `launchctl bootout <标签>` 交给 root shell 执行 ——
# 一个带空格或分号的 plist 文件名就能在提权上下文里注入命令。
# 校验失败一律**整段作废**，宁可报「无法自动操作」也不拼一条可疑的命令。
_SAFE_LAUNCHD_RE = re.compile(r"^[A-Za-z0-9._/@+-]+$")


def _safe_launchd_tokens(tokens):
    """逐段白名单校验；任何一段不合格就返回 []（调用方当「不可用」处理）。

    白名单里**不含空格**：这些 token 是直接拼进 shell 的，不做引号包裹；
    允许空格等于允许「一个名字变成多个参数」，拼出来的命令就不是我们想跑的那条。
    名字里真有空格的 plist（macOS 允许）→ 判定为「无法自动操作」，如实告诉用户，
    也好过去跑一条语义已经变了的命令。
    """
    out = []
    for t in tokens:
        s = str(t or "").strip()
        if not s or s.startswith("-") or not _SAFE_LAUNCHD_RE.match(s):
            return []
        out.append(s)
    return out


_JOB_MISSING_HINTS = (
    "could not find service", "no such process", "service not found",
    "could not find specified service", "not loaded",
)
_JOB_ALREADY_HINTS = (
    "already loaded", "already bootstrapped", "operation already in progress",
)


def _job_missing(err):
    """bootout 失败是不是因为「这个作业本来就没加载」。

    这类「失败」等价于已经达成目标，**不能算错** —— 否则当 aTrust 只加载了
    WatchDog 时，去停不存在的 Tunnel 会被判失败，进而触发一次毫无必要的回滚。
    """
    e = (err or "").lower()
    return any(h in e for h in _JOB_MISSING_HINTS)


def _job_already(err):
    """bootstrap 失败是不是因为「这个作业已经在跑」—— 那正是回滚想要的结果。"""
    e = (err or "").lower()
    return any(h in e for h in _JOB_ALREADY_HINTS)


def _plist_for_job(job, plists):
    """由守护作业标签找回它的 plist 路径（回滚时要用它 bootstrap 回去）。"""
    want = str(job).rsplit("/", 1)[-1]
    for p in plists or []:
        if os.path.basename(str(p))[:-len(".plist")] == want:
            return str(p)
    return ""


def _restore_jobs(jobs, plists, pw):
    """把刚 bootout 掉的守护作业 bootstrap 回原状 —— 失败时自动回滚用。

    返回 (ok, 说明)。这里**必须逐条看返回码**：回滚要是也吞掉失败，
    「已自动恢复」就成了空话，用户反而更不敢信这个提示。
    """
    targets = []
    for j in jobs:
        p = _plist_for_job(j, plists)
        if p:
            t = _safe_launchd_tokens(_bootstrap_target(p).split())
            if t:
                targets.append(" ".join(t))
    if not targets:
        return False, "找不到对应的 plist，无法自动回滚"
    failed = []
    for t in targets:
        rc, _o, e = run_root(f"launchctl bootstrap {t}", pw)
        if rc != 0 and not _job_already(e):
            failed.append((t, (e or "").strip()[:100]))
    if failed:
        return False, "；".join(f"{t} → {e}" for t, e in failed)[:200]
    return True, f"已恢复 {len(targets)} 个守护作业"


def stop_launchd_jobs(jobs, plists, pw=None, name=""):
    """bootout 一组守护作业，**带失败自动回滚**。返回 (ok, 说明)。

    抽出来共用：出口切换（outlet_stop）与情景切换（do_scene）都要这套逻辑。
    以前两边各自把命令用 `; ` 拼成一条、有的还带 `|| true` —— 于是
    「WatchDog 卸了、Tunnel 没卸」这种**停一半**会被报成完全成功，
    用户以为已经退出、其实隧道还在。这是本函数存在的唯一理由。
    """
    label = name or "守护作业"
    safe = []
    for j in jobs or []:
        t = _safe_launchd_tokens([j])
        if t:
            safe.append(t[0])
    if not safe:
        return False, "没有可安全操作的守护作业（标签未通过校验）"

    can, code, _txt = priv_capability(pw)
    if not can:
        return False, code

    unloaded, failed = [], []
    for j in safe:
        rc, _o, e = run_root(f"launchctl bootout {j}", pw)
        if rc == 0:
            unloaded.append(j)
        elif rc == 403:
            # 权限中途失效（凭据过期等）→ 把已经卸掉的捞回来，别把系统留在半残状态
            if unloaded:
                _restore_jobs(unloaded, plists, pw)
            return False, "NEED_SUDO"
        elif _job_missing(e):
            continue          # 本来就没加载 = 已经是目标状态，不算失败
        else:
            failed.append((j, (e or "").strip()[:120]))

    if failed:
        # 「停一半」是最危险的状态 → 整单回滚，把系统退回原样，让用户重试或手动处理
        back_ok, bmsg = _restore_jobs(unloaded, plists, pw)
        hint = ("已自动把刚卸掉的守护作业恢复回原状，系统状态没有变。" if back_ok
                else f"⚠ 自动恢复也没成功（{bmsg}）—— 请用它自己的界面退出，或重启电脑。")
        return False, (f"{'、'.join(f[0] for f in failed)} 卸不掉"
                       f"（{failed[0][1]}）。{hint}")
    if not unloaded:
        return True, f"{label} 本来就没在跑"
    return True, f"已停止 {label}（bootout {len(unloaded)} 个作业）"


def outlet_stop(key, pw=None, res=None):
    """停掉一个出口。返回 (ok, message)；message 为 NEED_SUDO 表示缺密码。"""
    o = _outlet_by_key(key, res)
    if not o:
        return False, f"未知出口：{key}"
    ad = o["adapter"]
    kind = ad.get("kind")
    if kind == "direct":
        return False, "「物理直连」不是一个可停止的客户端"

    if IS_WIN:
        if kind == "vpn":
            rc, out, err = run(["rasdial", ad.get("vpn") or "", "/disconnect"],
                               timeout=60)
            if rc != 0:
                return False, ("断开「%s」失败（rc=%s）：%s"
                               % (ad.get("vpn"), rc,
                                  (err or out or "").strip()[:160]))
            return True, "已断开系统 VPN「%s」" % ad.get("vpn")
        names = ad.get("stop_jobs") or []
        if not names:
            return False, ("%s 没有可自动停止的服务（%s）"
                           % (o["name"], o.get("hint") or "需要手动操作"))
        ok, text, cancelled = _win_elevated(
            _ps_try_lines("Stop-Service -Force", names),
            _cmd_start_stop("stop", names))
        if cancelled:
            return False, "NEED_ADMIN"
        if not ok:
            return False, ("停止「%s」未成功：%s"
                           % (o["name"], text[:200] or "未知原因"))
        return True, "已停止 %s（%d 个服务）" % (o["name"], len(names))

    jobs = []
    for j in (ad.get("stop_jobs") or []):
        t = _safe_launchd_tokens([j])
        if t:
            jobs.append(t[0])
    if not jobs:
        return False, (f"{o['name']} 没有可自动关闭的守护作业"
                       f"（{o.get('hint') or '需要手动操作'}）")

    ok, msg = stop_launchd_jobs(jobs, ad.get("start_plists") or [], pw, o["name"])
    if msg == "NEED_SUDO":
        return False, "NEED_SUDO"
    if not ok:
        return False, f"停止「{o['name']}」未成功：{msg}"
    return True, msg


def outlet_start(key, pw=None, res=None):
    """启动一个出口。"""
    o = _outlet_by_key(key, res)
    if not o:
        return False, f"未知出口：{key}"
    ad = o["adapter"]
    kind = ad.get("kind")
    if kind == "direct":
        return True, "物理直连无需启动"

    if IS_WIN:
        if kind == "vpn":
            rc, out, err = run(["rasdial", ad.get("vpn") or ""], timeout=90)
            if rc != 0:
                return False, ("连接「%s」失败（rc=%s）：%s"
                               % (ad.get("vpn"), rc,
                                  (err or out or "").strip()[:160]))
            return True, "已连接系统 VPN「%s」" % ad.get("vpn")

        msgs = []
        names = ad.get("start_plists") or []
        if names:
            ok, text, cancelled = _win_elevated(
                _ps_try_lines("Start-Service", names),
                _cmd_start_stop("start", names))
            if cancelled:
                return False, "NEED_ADMIN"
            if not ok:
                return False, ("启动「%s」的服务未成功：%s"
                               % (o["name"], text[:200] or "未知原因"))
            msgs.append("已启动 %d 个服务" % len(names))
        for app in ad.get("apps") or []:
            opener = getattr(os, "startfile", None)
            if opener is None:
                msgs.append("无法自动打开 %s" % _app_name(app))
                continue
            try:
                opener(app)
                msgs.append("已打开 " + _app_name(app))
            except OSError as e:
                msgs.append("打开 %s 失败：%s" % (_app_name(app), e))
        if not msgs:
            return False, f"{o['name']} 需要你在它的界面里手动开启"
        return True, "；".join(msgs)

    msgs = []
    plists = []
    for p in (ad.get("start_plists") or []):
        t = _safe_launchd_tokens(_bootstrap_target(p).split())
        if t:
            plists.append(" ".join(t))
    if plists:
        cmd = " ; ".join(f"launchctl bootstrap {t} 2>/dev/null || true"
                         for t in plists)
        rc, _o, _e = run_root(cmd, pw)
        if rc == 403:
            return False, "NEED_SUDO"
        msgs.append(f"已恢复 {len(plists)} 个守护作业")
    for app in ad.get("apps") or []:
        _sh(f'open -a "{app}"')
    if ad.get("apps"):
        msgs.append("已打开 " + "、".join(_app_name(a) for a in ad["apps"]))
    if not msgs:
        return False, f"{o['name']} 需要你在它的界面里手动开启"
    return True, "；".join(msgs)


def switch_outlet(key, pw=None, res=None):
    """切到某个出口 = 停掉其它在跑的出口 + 启动目标 + 清残留路由。"""
    if not isinstance(res, dict) or res.get("error"):
        res = do_scan()
    outlets = discover_outlets(res)
    target = next((o for o in outlets if o["key"] == key), None)
    if not target:
        return {"ok": False, "target": key, "done": [], "manual": [],
                "message": f"未知出口：{key}"}

    done, manual, need_sudo = [], [], False

    # 缺权限时提示语分平台：Windows 是 UAC 弹窗，没有密码可输。
    priv_hint = "UAC 授权" if IS_WIN else "管理员密码"

    for o in outlets:
        if o["key"] == key or not o.get("in_use"):
            continue
        ok, msg = outlet_stop(o["key"], pw, res)
        if msg in PRIV_MSGS:
            need_sudo = True
            done.append({"name": o["name"], "action": "stop", "ok": False,
                         "detail": f"需要{priv_hint}"})
            continue
        done.append({"name": o["name"], "action": "stop", "ok": ok, "detail": msg})
        if not ok:
            manual.append(f"手动关闭「{o['name']}」：{msg}")

    if not need_sudo and target["key"] != DIRECT_OUTLET:
        ok, msg = outlet_start(key, pw, res)
        if msg in PRIV_MSGS:
            need_sudo = True
        done.append({"name": target["name"], "action": "start", "ok": ok,
                     "detail": msg})
        if not ok:
            manual.append(f"手动开启「{target['name']}」：{msg}")

    if not need_sudo:
        n, cmsg = clean_residual_routes(pw)
        if cmsg in PRIV_MSGS:
            need_sudo = True
        elif n:
            done.append({"name": "残留路由", "action": "clean", "ok": True,
                         "detail": cmsg})

    if target["key"] == DIRECT_OUTLET:
        manual.append("若仍有加速器在自行接管流量，请在它的界面里关掉加速")

    if need_sudo:
        msg = f"需要{priv_hint}才能完成自动步骤"
    elif manual:
        msg = "自动步骤已完成，请继续完成下面的手动步骤"
    else:
        msg = "切换完成"
    if not need_sudo:
        remember_outlet(key)
    return {"ok": not need_sudo, "target": key, "target_name": target["name"],
            "done": done, "manual": manual, "message": msg}


def cancel_switch(pw=None):
    """取消上一次「切到这里」。

    「已切换（待确认）」是**我们记的一笔账**，不是系统事实 —— 所以它是可以反悔的。
    取消做两件事：

      1) 若上次切到的是「本机直连」，那笔账伴随的是**真的加了 /32 直连路由**，
         所以要把它们交还隧道（`do_undo`，只删本程序加过的主机路由，不误伤别人）。
      2) 抹掉这笔记录 → 界面那一行从黄色「待确认」回到中性状态。

    切到**隧道客户端**的情况不回滚启停：用户很可能正靠它上网，
    自动把它停掉会直接断网。只清记录，并提示怎么彻底退出。
    """
    key = remembered_outlet()
    done, manual = [], []

    if key is None:
        forget_active_outlet()
        return {"ok": True, "cancelled": None, "done": [], "manual": [],
                "message": "没有待取消的切换记录"}

    ok = True
    if key == DIRECT_OUTLET:
        u_ok, umsg = do_undo(pw)
        if umsg == "NEED_SUDO":
            return {"ok": False, "cancelled": key, "done": [], "manual": [],
                    "message": "NEED_SUDO"}
        done.append({"name": "直连路由交还隧道", "action": "undo",
                     "ok": bool(u_ok), "detail": umsg})
        if not u_ok:
            ok = False

    forget_active_outlet()

    if key == DIRECT_OUTLET:
        msg = ("已取消：「本机直连」的记录已抹掉，直连路由已交还隧道" if ok
               else "记录已抹掉，但直连路由没能全部交还")
    else:
        msg = f"已取消「{key}」的切换记录（客户端启停未回滚）"
        manual.append(f"如需彻底退出「{key}」，请用它自己的界面关掉，或点该行的「停止」")
    return {"ok": ok, "cancelled": key, "done": done, "manual": manual,
            "message": msg}


# ----------------------------------------------------------------------
# 出口指纹：把「某个客户端独有哪几条路由 / 哪个接口」记下来
# ----------------------------------------------------------------------
#
# 为什么需要：TUN 接口认不出厂商（见 _iface_owners）。而**唯一可靠**的通用办法是
# 「停掉它，看哪些路由跟着消失」—— 我们把这个结果存成"指纹"，
# 之后就能一眼认出同样的接口是谁的，不用每次都重启客户端。
#
# 注：另一条路「拔掉某条路由看谁补回来」只对**有守护进程**的客户端有效
# （aTrust 有 aTrustTunnelWatchDog），实测**雷神不补路由**，所以不能作为通用方案。
FP_FILE = os.path.join(CONFIG_DIR, "outlet_fingerprints.json")


