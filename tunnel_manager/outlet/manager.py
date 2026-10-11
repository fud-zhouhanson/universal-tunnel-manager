# -*- coding: utf-8 -*-
"""tunnel_manager.outlet/manager — 通用出口管理（三个可控点）

由 P1 从 server.py 的第 1636–1808 行**整块搬迁**而来，正文逐字未改。

【切片规则 —— 这不是漏写 import】
本项目按设计保持**单一扁平命名空间**：
  · 开发期入口 `python -m tunnel_manager.main` → 把所有切片拼进一个命名空间再执行；
  · 构建期 `bundle.py` → 同样顺序拼接成单文件 `dist/tunnel-manager.py`（纯源码，不含 exec）。
所以本文件里可以直接引用其它切片定义的函数与常量，无需 import。跨切片调用是既有事实。
本模块对外提供：ACTIVE_FILE、ACTIVE_TTL、DIRECT_OUTLET、OUTLET_RULES、PRIV_MSGS、VPN_PREFIX 等 10 个
本模块依赖其它切片：_base
"""
>>>SLICE_BODY<<<
# ======================================================================
# 八·七、通用出口管理（Outlet）—— 不为 35 种客户端手写适配
# ======================================================================
#
# 把「切换」抽象成「选一个出口」：物理直连 / 某个隧道客户端 / 某个系统 VPN。
# 关键设计：**不去为每种客户端写死适配**，而是自动探测三个「可控点」——
#   1) 装没装 .app         → 能 `open -a` 启动
#   2) 有没有 launchd 作业  → 能 `bootout` 停 / `bootstrap` 启
#   3) 有没有系统 VPN 配置  → `scutil --nc start/stop`（不需要 root）
# 三个都没有就退化为「引导用户手点」（manual）。
#
# 实测归属：aTrust → launchd(2)；ZeroTier → app+launchd(1,2)；
# 雷神 / 网易UU → 只有 app(1)，但加速开关在 App 内部 ⇒ 实际是 manual。

DIRECT_OUTLET = "__direct__"
VPN_PREFIX = "__vpn__:"            # Windows 自带 VPN 的出口键前缀（见 discover_outlets）
# 「缺权限」的两个哨兵：macOS 是 sudo 密码，Windows 是 UAC 授权 ——
# 前端提示语完全不同（Windows 上没有密码可输），所以必须分开传。
PRIV_MSGS = ("NEED_SUDO", "NEED_ADMIN")


def priv_error(message=""):
    """「缺权限」回给前端的错误体。

    macOS 要用户输 sudo 密码，Windows 只要点一下 UAC —— 提示语完全不同，
    所以错误码也分开，前端才不会在 Windows 上弹一个没用的密码框。
    """
    if IS_WIN:
        return {"ok": False, "error": "NEED_ADMIN",
                "message": message or "需要管理员授权（会弹出 UAC 确认框）"}
    return {"ok": False, "error": "NEED_SUDO",
            "message": message or "需要管理员密码"}

# 「关闭方式」显式表 —— 只给少数需要特判的客户端配，其余走自动探测。
#
# 为什么雷神 / UU 必须是 manual：它们的 `com.leigod.helper` / `com.netease.uumac.helper`
# 是**引擎本体**、KeepAlive 常驻 —— 停掉它等于把整个加速器搞坏，而不是「停止加速」；
# 而真正的加速开关只在 App 内部（PLAN §2.5.3 也记了这条）。
# aTrust 则相反：它有三个**专门承载隧道**的守护作业，bootout 掉才是正确的「完全退出」。
OUTLET_RULES = {
    "aTrust (深信服零信任)": {
        "stop_jobs": [
            "system/com.sangfor.aTrustTunnelWatchDog",   # 必须先停：它是 KeepAlive，会立刻把隧道拉回来
            "system/com.sangfor.aTrustTunnel",
            "system/com.sangfor.aTrustDaemon",
        ],
        "start_plists": [
            "/Library/LaunchDaemons/com.sangfor.aTrustDaemon.plist",
            "/Library/LaunchDaemons/com.sangfor.aTrustTunnel.plist",
            "/Library/LaunchDaemons/com.sangfor.aTrustTunnelWatchDog.plist",
        ],
    },
    "雷神加速器": {"mode": "manual",
                 "reason": "helper 是引擎本体、常驻，不能停；加速开关只在它 App 内"},
    "网易UU加速器": {"mode": "manual",
                    "reason": "helper 是常驻服务；加速开关只在它 App 内"},
    "迅游加速器": {"mode": "manual", "reason": "加速开关只在它 App 内"},
    "奇游加速器": {"mode": "manual", "reason": "加速开关只在它 App 内"},
    "biubiu 加速器": {"mode": "manual", "reason": "加速开关只在它 App 内"},
}

# 这些作业名一看就是「看护 / 资源 / 卸载」类，不是承载隧道的服务 —— 自动模式下不动它们
_JOB_NOISE = re.compile(
    r"helper|uninstall|monitor|limit|maxfiles|crashpad|update|telemetry", re.I)


def _stoppable(jobs):
    """从自动探测到的作业里，挑出真能用来关闭出口的那些。"""
    return [j for j in jobs if not _JOB_NOISE.search(j["label"])]


# 「上次切到哪个出口」的记忆。
# 为什么需要：TUN 接口认不出归属（见 _iface_owners 的说明），纯靠系统探测
# 无法回答「我现在用的到底是哪个」。所以在用户点过切换之后记下来，
# 界面就能显示得准 —— 并且明确标注这是「你上次切的」，不是我们猜出来的。
ACTIVE_FILE = os.path.join(CONFIG_DIR, "active_outlet.json")
ACTIVE_TTL = 3600


def remember_outlet(key):
    try:
        os.makedirs(CONFIG_DIR, exist_ok=True)
        with open(ACTIVE_FILE, "w", encoding="utf-8") as f:
            json.dump({"key": key, "ts": time.time()}, f)
    except OSError:
        pass


def remembered_outlet():
    try:
        with open(ACTIVE_FILE, encoding="utf-8") as f:
            d = json.load(f)
        if time.time() - float(d.get("ts") or 0) < ACTIVE_TTL:
            return d.get("key")
    except (OSError, ValueError, TypeError):
        pass
    return None


def forget_active_outlet():
    """抹掉「上次切到哪个出口」这笔记录（界面上的「取消这次切换」用它）。"""
    try:
        os.remove(ACTIVE_FILE)
        return True
    except OSError:
        return False


def _kb_keywords(entry):
    kws = list(entry.get("proc") or []) + list(entry.get("iface") or [])
    return sorted({k.lower() for k in kws if k})


def _find_apps(keywords):
    """在系统与应用目录里找匹配的 .app。"""
    hits = []
    for base in ("/Applications", os.path.expanduser("~/Applications")):
        try:
            for n in sorted(os.listdir(base)):
                if n.endswith(".app") and any(k in n.lower() for k in keywords):
                    hits.append(os.path.join(base, n))
        except OSError:
            pass
    return hits


def _find_launchd(keywords):
    """找标签匹配的 launchd 作业。返回 (daemons, agents)。"""
    daemons, agents = [], []
    home = os.path.expanduser("~")
    for d, bucket, domain in (
            ("/Library/LaunchDaemons", daemons, "system"),
            ("/Library/LaunchAgents", agents, f"gui/{os.getuid()}"),
            (os.path.join(home, "Library/LaunchAgents"), agents, f"gui/{os.getuid()}")):
        try:
            for n in sorted(os.listdir(d)):
                if n.endswith(".plist") and any(k in n.lower() for k in keywords):
                    bucket.append({"label": n[:-6], "plist": os.path.join(d, n),
                                   "domain": domain})
        except OSError:
            pass
    return daemons, agents


# ---- Windows 侧的三个「可控点」探测 ----
#
# 与 macOS 一一对应，缺一不可：
#   应用     ←→ /Applications 里的 .app
#   服务     ←→ launchd 作业（Windows 的等价物就是 SCM 服务）
#   系统 VPN ←→ scutil --nc（Windows 用 Get-VpnConnection + rasdial）
#
# ⚠️ 全部**只读**，探测失败一律返回空 → 上层退化成「需要手动」。
# 宁可显示「手动」，也不猜一个服务名去停 —— 停错服务比不做事危险得多。
# ⚠️ 本机是 macOS，这段**没有真机验证过**，见 README「Windows 未验证」一节。

_WIN_CACHE_LOCK = threading.Lock()
_WIN_CACHE = {"apps": (0.0, []), "svcs": (0.0, [])}


def _win_cached(slot, ttl, loader):
    """注册表/服务枚举各要 1 秒上下，加个短缓存免得每次扫描都重来。"""
    now = time.time()
    with _WIN_CACHE_LOCK:
        at, val = _WIN_CACHE.get(slot) or (0.0, [])
    if val and now - at < ttl:
        return val
    val = loader() or []
    if val:
        with _WIN_CACHE_LOCK:
            _WIN_CACHE[slot] = (now, val)
    return val


