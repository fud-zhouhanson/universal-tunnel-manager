# -*- coding: utf-8 -*-
"""tunnel_manager.config — 配置读写与域名解析

由 P2 从 config.py 的第 1–110 行**原样拆出**，正文逐字未改（与 P1 一样，只搬不改）。

【切片规则 —— 这不是漏写 import】
本项目按设计保持**单一扁平命名空间**：
  · 开发期入口 `python -m tunnel_manager.main` → 把所有切片拼进一个命名空间再执行；
  · 构建期 `bundle.py` → 同样顺序拼接成单文件 `dist/tunnel-manager.py`（纯源码，不含 exec）。
所以本文件里可以直接引用其它切片定义的函数与常量，无需 import。跨切片调用是既有事实。
本模块对外提供：AUTO_EXPIRE、AUTO_INTERVAL、AUTO_MAX、AUTO_WINDOW、DEFAULT_DOMAINS、DNS_TTL 等 9 个
本模块依赖其它切片：_base、consts
"""
>>>SLICE_BODY<<<
# ======================================================================
# 六、配置
# ======================================================================

# 默认目标域名：几个通用示例站点。
# 用途：页面「目标域名的路由走向」表里默认展示这些站走直连还是走隧道。
# 可在页面上自由增删，配置存 ~/.tunnel-manager/config.json。
# 请把它换成你自己常访问、且希望「走物理直连」的站点（学校/单位的门户、教务、图书馆等）。
DEFAULT_DOMAINS = [
    # 常见网站
    "www.baidu.com", "www.bing.com", "github.com", "www.zhihu.com",
    # 注意：**不要把 VPN 客户端「自身服务器」的域名放进来** —— 例如某些校内 VPN 的
    # vpn.<学校域名> 解析到的正是客户端自己的外层传输服务器，让本工具去托管它的
    # 保活通路既无意义也有风险（见 EXCLUDED 机制）。
]


def load_config():
    try:
        with open(CONFIG_FILE, encoding="utf-8") as f:
            cfg = json.load(f)
        domains = cfg.get("domains") or []
        if domains:
            return domains
    except (OSError, json.JSONDecodeError):
        pass
    return list(DEFAULT_DOMAINS)


def save_config(domains):
    os.makedirs(CONFIG_DIR, exist_ok=True)
    cleaned = []
    for d in domains:
        d = (d or "").strip().lower()
        if d and d not in cleaned:
            cleaned.append(d)
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump({"domains": cleaned}, f, ensure_ascii=False, indent=2)
    return cleaned


_dns_cache = {}          # domain -> (expire_ts, [ips])
DNS_TTL = 60             # 秒。扫描一次会用到两遍解析结果，加缓存避免重复查 DNS


def resolve_a(domain):
    """解析 A 记录，只返回公网 IP（私网/保留地址一律剔除，防 DNS 投毒）。"""
    now = time.time()
    hit = _dns_cache.get(domain)
    if hit and hit[0] > now:
        return hit[1]
    try:
        _, _, ips = socket.gethostbyname_ex(domain)
    except (socket.gaierror, OSError):
        _dns_cache[domain] = (now + DNS_TTL, [])
        return []
    out = []
    for ip in ips:
        if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", ip) and is_public_ip(ip):
            out.append(ip)
    _dns_cache[domain] = (now + DNS_TTL, out)
    return out


# ======================================================================
# 六.5 自动追踪：浏览器新开的网站
# ======================================================================
# 原理：每 30 秒扫一次各浏览器的历史记录库（只读，SQLite），
#   · 最近 AUTO_WINDOW 秒内访问过的新域名 → 自动加入「目标域名」
#   · 超过 AUTO_EXPIRE 秒没再访问的自动域名 → 自动移除
#   实测 Chrome / Edge / Firefox / Safari 的历史库都能读到，Safari 需要完全磁盘访问权限。
#
# ⚠️ 三条踩过的坑，别改回去：
#
#  1) **不要剥掉 `www.`**（曾这么干过，是错的）。
#     实测国内站的 apex 与 www 解析出来的公网 IP **零交集**：
#       www.baidu.com → 180.101.51.73      baidu.com → 111.63.65.103
#       www.zhihu.com → 43.242.197.211     zhihu.com → 182.61.194.9
#       www.bilibili.com → 114.230.222.139 bilibili.com → 119.3.70.188  …共 6 个站全部 0 交集
#     只有 github.com 这种本来就无 www 的才对得上。
#     浏览器连的是 **www 的 IP**；存成 apex 就会给一批用不上的 IP 加直连路由，
#     「追踪 → 应用」整条链路看着成功、实际一条都没生效。原样保留 host 最准。
#
#  2) **读取失败绝不能吞**。macOS 上 Safari 的历史库受 TCC（完全磁盘访问）保护，
#     直读报 `unable to open database file`、先复制再读报 `EPERM`。
#     以前是 `except: pass`，界面于是永远显示「追踪中 · 0 个」，
#     用户分不清「没开浏览器」/「没授权」/「刚开过但都超了 3 分钟」。
#     现在每次扫描都留一份 _auto_status，经 /api/scan 送到前端展示。
#
#  3) **临时文件要放在 finally 里删**。Chrome 的库要先复制再读（运行时被锁），
#     复制失败时如果 unlink 不在 finally，副本会永远留下 —— 每 30 秒一轮、失败一次留一个。

AUTO_WINDOW = 180    # 最近 3 分钟内访问过 = 「正在看」
AUTO_EXPIRE = 600    # 10 分钟没再看 = 「关了」，移除
AUTO_INTERVAL = 30   # 扫描周期
AUTO_MAX = 60        # 追踪集合的上限（防「浏览一天 → 上百条路由」失控），超出丢最旧的。
                     # 为什么不是 100：追踪到的域名现在**真的会变成直连路由**，
                     # 每个域名解析出 2~4 个 IP，而 Windows 上每条 IP 要起两次 route.exe
                     # （先 delete 再 -p add），100 个域名 ≈ 800 次进程创建，
                     # 逼近 run_elevated_win 的 90 秒超时。60 个留足余量。

_auto_domains = {}          # {domain: last_seen_timestamp}
_auto_lock = threading.Lock()
_auto_thread = None
_auto_enabled = True        # 前端可开关
# 最近一次扫描的实况：给界面回答「为什么这里是空的」
_auto_status = {"at": 0.0, "found": 0, "tracked": 0, "sources": [], "error": ""}



