# -*- coding: utf-8 -*-
"""tunnel_manager.win/identify — Windows 出口识别与指纹

由 P2 从 win/native.py 的第 1310–1496 行**原样拆出**，正文逐字未改（与 P1 一样，只搬不改）。

【切片规则 —— 这不是漏写 import】
本项目按设计保持**单一扁平命名空间**：
  · 开发期入口 `python -m tunnel_manager.main` → 把所有切片拼进一个命名空间再执行；
  · 构建期 `bundle.py` → 同样顺序拼接成单文件 `dist/tunnel-manager.py`（纯源码，不含 exec）。
所以本文件里可以直接引用其它切片定义的函数与常量，无需 import。跨切片调用是既有事实。
本模块对外提供：SNAP_FILE、forget_fingerprint、identify_outlet、load_fingerprints、save_fingerprint
本模块依赖其它切片：_base、detect/scan、outlet/scene_ops、util、win/nat_net、win/outlets、win/probe、win/switch
"""
>>>SLICE_BODY<<<
def load_fingerprints():
    try:
        with open(FP_FILE, encoding="utf-8") as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def save_fingerprint(key, ifaces, routes, note=""):
    fps = load_fingerprints()
    fps[key] = {"ifaces": sorted(set(ifaces)), "routes": sorted(set(routes)),
                "at": time.time(), "note": note}
    try:
        os.makedirs(CONFIG_DIR, exist_ok=True)
        with open(FP_FILE, "w", encoding="utf-8") as f:
            json.dump(fps, f, ensure_ascii=False, indent=2)
        return True, "ok"
    except OSError as e:
        return False, str(e)


def forget_fingerprint(key):
    """忘掉某个出口的归属记忆（确认错了、或换了客户端时用）。"""
    fps = load_fingerprints()
    if key not in fps:
        return False, f"{key} 没有已记录的归属记忆"
    fps.pop(key, None)
    try:
        with open(FP_FILE, "w", encoding="utf-8") as f:
            json.dump(fps, f, ensure_ascii=False, indent=2)
    except OSError as e:
        return False, str(e)
    return True, f"已忘掉「{key}」的归属记忆"


def _routes_snapshot():
    """当前 IPv4 路由集合：{(dest, iface)}。"""
    if IS_WIN:
        if not ps_available()[0]:
            return _nat_routes_snapshot()
        # Windows 用 Get-NetRoute，能和 macOS 一样拿到「接口别名」而不是 IP
        # （route print 的 Interface 列给的是 IP，还得再翻译一次）。
        rc, out, _ = run_ps(
            "[Console]::OutputEncoding=[Text.Encoding]::UTF8;"
            "Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue | "
            "Select-Object DestinationPrefix,InterfaceAlias | "
            "ConvertTo-Json -Depth 3"
        )
        if rc != 0 or not out:
            return set()
        try:
            data = json.loads(out)
        except json.JSONDecodeError:
            return set()
        if isinstance(data, dict):
            data = [data]
        res = set()
        for d in data:
            dest = str(d.get("DestinationPrefix") or "")
            if not dest:
                continue
            if dest == "0.0.0.0/0":
                dest = "default"          # 与 macOS 的写法对齐，好让上层统一过滤
            res.add((dest, str(d.get("InterfaceAlias") or "")))
        return res
    out = set()
    for line in _sh("netstat -rn -f inet").splitlines():
        p = line.split()
        if len(p) >= 4 and p[0] not in ("Destination", "Internet:"):
            out.add((p[0], p[3]))
    return out


SNAP_FILE = os.path.join(CONFIG_DIR, "identify_snap.json")


def _identify_twostep(key, name):
    """两段式归属确认 —— 给「不能自动停止」的客户端用（雷神 / 网易UU 这类）。

    第一次点：记下「关掉它之前」的路由/接口快照，并提示你去手动关；
    第二次点：对比，得出它独有的路由，存成指纹。
    """
    cur_r, cur_i = _routes_snapshot(), active_ifaces()

    try:
        with open(SNAP_FILE, encoding="utf-8") as f:
            pend = json.load(f)
    except (OSError, ValueError):
        pend = None

    if not isinstance(pend, dict) or pend.get("key") != key:
        try:
            os.makedirs(CONFIG_DIR, exist_ok=True)
            with open(SNAP_FILE, "w", encoding="utf-8") as f:
                json.dump({"key": key,
                           "routes": sorted(f"{d}|{i}" for d, i in cur_r),
                           "ifaces": sorted(cur_i), "at": time.time()},
                          f, ensure_ascii=False)
        except OSError as e:
            return {"ok": False, "message": f"快照写入失败：{e}"}
        return {"ok": True, "phase": "before", "key": key, "name": name,
                "message": f"已记下「关掉 {name} 之前」的状态。"
                           f"请现在手动把它关掉，然后回来再点一次「确认归属」。"}

    before_r = set()
    for r in pend.get("routes") or []:
        if "|" in r:
            d, i = r.split("|", 1)
            before_r.add((d, i))
    before_i = set(pend.get("ifaces") or [])
    gone_r = sorted(d for (d, _i) in (before_r - cur_r) if d != "default")
    gone_i = sorted(before_i - cur_i)
    try:
        os.remove(SNAP_FILE)
    except OSError:
        pass

    saved = False
    if gone_r or gone_i:
        saved, _ = save_fingerprint(key, gone_i, gone_r, note="由「手动关掉→对比」得出")

    parts = []
    if gone_i:
        parts.append("接口 " + "、".join(gone_i))
    if gone_r:
        parts.append(f"{len(gone_r)} 条路由")
    detail = "；".join(parts) if parts else "没有发现任何路由/接口随它消失（它可能本来就没在跑）"
    return {"ok": True, "phase": "after", "key": key, "name": name,
            "owned_ifaces": gone_i, "owned_routes": gone_r, "saved": saved,
            "message": f"{name} 的归属已确认：{detail}"
                       + ("（已存为指纹）" if saved else "")}


def identify_outlet(key, pw=None, wait=6):
    """确认某个出口的路由归属：停它 → 看哪些路由/接口跟着消失 → 立刻恢复。

    这是唯一**通用可靠**的归属确认法。代价是需要短暂停掉该客户端
    （aTrust 恢复后可能还要重新登录）。
    """
    res = do_scan()
    o = next((x for x in discover_outlets(res) if x["key"] == key), None)
    if not o:
        return {"ok": False, "message": f"未知出口：{key}"}
    if not o["can_stop"]:
        return _identify_twostep(key, o["name"])

    before_r, before_i = _routes_snapshot(), active_ifaces()

    ok, msg = outlet_stop(key, pw, res)
    if not ok:
        return {"ok": False, "message": msg}

    time.sleep(max(2, int(wait)))

    # ⚠️ 这里以前写的是 `_ifaces_snapshot()` —— 那个名字**从来没定义过**，
    #    所以凡是「能自动停止」的出口（aTrust 这类）一点「确认归属」就 NameError。
    #    它和上面 `before_i` 取的是同一个东西，直接用 active_ifaces()。
    mid_r, mid_i = _routes_snapshot(), active_ifaces()

    # 无论成败都要恢复
    ok2, msg2 = outlet_start(key, pw, res)

    gone_routes = sorted(d for (d, _i) in (before_r - mid_r) if d != "default")
    gone_ifaces = sorted(before_i - mid_i)

    saved = False
    if gone_routes or gone_ifaces:
        saved, _ = save_fingerprint(key, gone_ifaces, gone_routes,
                                    note="由「停掉→对比」实测得出")

    parts = []
    if gone_ifaces:
        parts.append("接口 " + "、".join(gone_ifaces))
    if gone_routes:
        parts.append(f"{len(gone_routes)} 条路由")
    detail = ("；".join(parts) if parts else "没有发现任何路由/接口随它消失")

    return {
        "ok": True, "key": key, "name": o["name"],
        "owned_ifaces": gone_ifaces, "owned_routes": gone_routes,
        "saved": saved, "restored": bool(ok2), "restore_detail": msg2,
        "message": f"{o['name']} 的归属已确认：{detail}"
                   + ("（已存为指纹）" if saved else ""),
    }


