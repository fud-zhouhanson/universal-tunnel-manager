# -*- coding: utf-8 -*-
"""tunnel_manager.outlet/scene — 情景判定（游戏模式 / 校内模式 / 直连）

由 P2 从 outlet/scene.py 的第 1–175 行**原样拆出**，正文逐字未改（与 P1 一样，只搬不改）。

【切片规则 —— 这不是漏写 import】
本项目按设计保持**单一扁平命名空间**：
  · 开发期入口 `python -m tunnel_manager.main` → 把所有切片拼进一个命名空间再执行；
  · 构建期 `bundle.py` → 同样顺序拼接成单文件 `dist/tunnel-manager.py`（纯源码，不含 exec）。
所以本文件里可以直接引用其它切片定义的函数与常量，无需 import。跨切片调用是既有事实。
本模块对外提供：ATRUST_JOBS、ATRUST_PLISTS、KNOWN_OWNER_NAMES、OUTLET_CATS、SCENES、detect_scene
本模块依赖其它切片：consts、win/identify
"""
>>>SLICE_BODY<<<
# ======================================================================
# 八·五、情景判定（游戏模式 / 校内模式 / 直连）
# ======================================================================

SCENES = {
    "game":    {"name": "游戏模式", "desc": "加速器独占出口（Steam 等游戏走专线）"},
    "campus":  {"name": "校内模式", "desc": "aTrust 独占出口（校园资源、文献、数据库）"},
    "direct":  {"name": "直连模式", "desc": "无隧道接管，全部走物理宽带"},
    "tunnel":  {"name": "隧道接管", "desc": "有隧道接口在承载公网（归属未识别）"},
    "mixed":   {"name": "多出口冲突", "desc": "多个隧道客户端同时接管公网，可能互相踩死"},
    "unknown": {"name": "未知", "desc": ""},
}

# 能当「出口」用的类别（覆盖网络、虚拟网卡不是出口，只做识别不参与切换）
OUTLET_CATS = ("企业VPN", "开源VPN", "系统VPN", "代理", "加速器")

KNOWN_OWNER_NAMES = {k["name"] for k in TUNNEL_KNOWLEDGE}


def _owner_scene(owner):
    """把隧道归属映射到情景。不认识的一律 'other'（不参与情景判定）。"""
    o = owner or ""
    low = o.lower()
    if "atrust" in low or "深信服" in o or "sangfor" in low:
        return "campus"
    if "雷神" in o or "leigod" in low:
        return "game"
    if "网易uu" in o or "uubooster" in low or "uu加速" in o:
        return "game"
    return "other"


def _iface_owners(res):
    """算出每个隧道接口的归属：{iface: {"owner": str, "guessed": bool}}。

    为什么需要「猜」：实测在 macOS 上**拿不到 TUN 接口的厂商信息**——
    `lsof | grep utun` 看不到、`ifconfig` 没有 description、
    `system_profiler SPNetworkDataType` 也不列 utun。
    而 Clash / sing-box / 雷神这类客户端建的接口**全都叫 utunN**，名字毫无特征。
    所以只能退而求其次：用「谁在跑」反推，并且**只在证据唯一时才认领**，
    认不出来就如实标成未识别 —— 宁可显示「未识别」也不要瞎指一个。
    """
    ifaces = res.get("interfaces") or []
    software = [s["name"] for s in (res.get("running_software") or [])]

    owners, claimed, ghosts = {}, set(), []

    # ① 最高优先级：已确认过的指纹。
    #    **按「路由特征」匹配，而不是按接口名** —— 这点很关键：
    #    接口名 utunN 每次重连/重启都可能换号（雷神这次是 utun6，下次可能就是 utun8），
    #    但客户端加的那组路由（雷神固定是 1/2/4/8/16/32/64/128 那八条拆分，
    #    aTrust 是 198.18.0.0/24 + 198.18.255.0/24 + 128.0/3…）才是它的"签名"。
    #    按签名认，换多少次接口号都认得出来。
    fps = load_fingerprints()
    cur_routes = _routes_snapshot()
    for key, fp in fps.items():
        want = set(fp.get("routes") or [])
        if want:
            hit_ifaces = {i for (d, i) in cur_routes if d in want}
            if len(hit_ifaces) == 1:
                owners[hit_ifaces.pop()] = {"owner": key, "guessed": False,
                                            "from": "fingerprint-route"}
                claimed.add(key)
                continue
        for name in fp.get("ifaces") or []:
            if name not in owners:
                owners[name] = {"owner": key, "guessed": False,
                                "from": "fingerprint-iface"}
                claimed.add(key)

    for i in ifaces:
        if i.get("kind") != "隧道":
            continue
        name = i["name"]
        if name in owners:
            continue                       # 指纹已经认领
        own = i.get("owner") or ""
        if own in KNOWN_OWNER_NAMES:
            owners[name] = {"owner": own, "guessed": False}
            claimed.add(own)
        elif i.get("ipv4"):
            ghosts.append(name)          # 有 IPv4 但认不出厂商的隧道接口

    outlet_names = {k["name"] for k in TUNNEL_KNOWLEDGE if k.get("cat") in OUTLET_CATS}
    loose = [s for s in software if s in outlet_names and s not in claimed]

    if len(ghosts) == 1 and len(loose) == 1:
        owners[ghosts[0]] = {"owner": loose[0], "guessed": True}
    else:
        for g in ghosts:
            owners[g] = {"owner": "", "guessed": True}
    return owners


def detect_scene(res):
    """判定当前出口情景。

    「谁在承载公网」= 多点抽查（egress_counts）里命中公网探测点的**隧道**接口。
    只有隧道接口才算——物理网卡命中是正常现象；系统隧道 / ZeroTier 之类不承载公网，
    用 _owner_scene 归为 other 后排除。

    返回 {key, name, desc, directors, egress, main_egress}
    """
    if not isinstance(res, dict) or res.get("error"):
        return {"key": "unknown", "name": SCENES["unknown"]["name"],
                "desc": "", "directors": [], "egress": {}, "main_egress": ""}

    egress = res.get("egress_counts") or {}
    owners = _iface_owners(res)

    carriers = {}   # iface -> (scene, hits, owner)
    for name, hits in egress.items():
        try:
            hits = int(hits)
        except (TypeError, ValueError):
            continue
        if hits <= 0:
            continue
        info = owners.get(name)
        if info is None:
            continue                       # 物理网卡 / 回环 / 系统隧道
        own = info["owner"]
        sc = _owner_scene(own) if own else "tunnel"
        if sc == "other":
            continue                       # 系统隧道等，不参与
        carriers[name] = (sc, hits, own)

    if not carriers:
        key, directors = "direct", []
    else:
        scenes = {v[0] for v in carriers.values()}
        if len(scenes) == 1:
            key = scenes.pop()
        elif scenes - {"tunnel"}:
            key = "mixed"
        else:
            key = "tunnel"
        directors = sorted(
            ({"iface": k, "owner": v[2] or "（归属未识别）", "hits": v[1],
              "scene": v[0], "guessed": (owners.get(k) or {}).get("guessed", False)}
             for k, v in carriers.items()),
            key=lambda x: -x["hits"])

    info = SCENES.get(key, SCENES["unknown"])
    return {
        "key": key, "name": info["name"], "desc": info["desc"],
        "directors": directors, "egress": egress,
        "main_egress": res.get("main_egress") or "",
    }


# ======================================================================
# 八·六、情景切换（游戏模式 ⇄ 校内模式）
# ======================================================================
#
# 为什么是「半自动」：实测雷神与 aTrust 都是「拆分整段公网」的全量接管，
# 同时开必然在同一张路由表里争夺最长前缀 → 只能二选一（PLAN 路线 E）。
# 但两件事脚本做不到：
#   1) 雷神的「开始/停止加速」只在它自己的 GUI 里（helper 的 127.0.0.1:10908
#      WebSocket 控制口协议尚未还原）；
#   2) aTrust 重新拉起后需要用户登录。
# 所以工具负责「可自动的那半」：停对家、清残留、校验；GUI 那半交给用户。

ATRUST_JOBS = [
    "system/com.sangfor.aTrustTunnelWatchDog",   # 必须先停守卫：KeepAlive 会把隧道拉回来
    "system/com.sangfor.aTrustTunnel",
    "system/com.sangfor.aTrustDaemon",
]
ATRUST_PLISTS = [
    "/Library/LaunchDaemons/com.sangfor.aTrustDaemon.plist",
    "/Library/LaunchDaemons/com.sangfor.aTrustTunnel.plist",
    "/Library/LaunchDaemons/com.sangfor.aTrustTunnelWatchDog.plist",
]


