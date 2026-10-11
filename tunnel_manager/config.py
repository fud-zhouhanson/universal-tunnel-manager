# -*- coding: utf-8 -*-
"""tunnel_manager.config — 配置读写与域名解析

由 P2 从 config.py 的第 1–110 行**原样拆出**，正文逐字未改（与 P1 一样，只搬不改）。

【切片规则 —— 这不是漏写 import】
本项目按设计保持**单一扁平命名空间**：
  · 开发期入口 `python -m tunnel_manager.main` → 把所有切片拼进一个命名空间再执行；
  · 构建期 `bundle.py` → 同样顺序拼接成单文件 `dist/tunnel-manager.py`（纯源码，不含 exec）。
所以本文件里可以直接引用其它切片定义的函数与常量，无需 import。跨切片调用是既有事实。
本模块对外提供：AUTO_EXPIRE、AUTO_INTERVAL、AUTO_MAX、AUTO_WINDOW、DEFAULT_DOMAINS、DNS_TTL 等 13 个
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


def load_config_raw():
    """读整份 config.json；不存在 / 写坏了 / 不是对象 → 一律给空 dict。

    以前只有 load_config()（只取 domains 一项），而 save_config() 是**整份覆盖写**
    —— 任何「顺带存个别的键」都会被下一次保存域名冲掉。
    现在多了假 IP 池规则这类可配置项，必须先补上「读整份」的能力。
    """
    try:
        with open(CONFIG_FILE, encoding="utf-8") as f:
            cfg = json.load(f)
        return cfg if isinstance(cfg, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def load_config():
    domains = load_config_raw().get("domains") or []
    return domains if domains else list(DEFAULT_DOMAINS)


def save_config(domains):
    os.makedirs(CONFIG_DIR, exist_ok=True)
    cleaned = []
    for d in domains:
        d = (d or "").strip().lower()
        if d and d not in cleaned:
            cleaned.append(d)
    # ⚠️ 必须**读-改-写**。以前只写 {"domains": […] }，会把文件里其它键一并抹掉
    # —— 表现是「保存一次域名表，假 IP 池配置就没了」。
    cfg = load_config_raw()
    cfg["domains"] = cleaned
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)
    return cleaned


# ======================================================================
# 六.2 假 IP 池规则（可配置）
# ======================================================================
# 隧道 / 加速器客户端惯用的把戏：把域名解析到一组「假 IP」，再在假 IP 上做分流。
# 表现就是「显示在加速中、实际没效果」。判定规则**外置成数据**，
# 想给自己的环境再加一段，不必改代码 —— 在 ~/.tunnel-manager/config.json 里写：
#
#   {"fake_ip_pools": {"host": ["198\\.18\\.", "10\\.10\\."],
#                      "net":  ["172\\.31\\."]}}
#
# 只做**整体替换**，不做合并 —— 覆盖语义越简单越不容易误判。
#
# ⚠️ 两组规则语义不同，**不要合并成一组**：
#   host —— 与「域名解析出来的那个地址」做前缀匹配
#   net  —— 与「路由表里的目的网段地址」做前缀匹配
# 为什么不能合并：host 侧必须连 127. / 169.254. 一起排除（正常域名不该解析到
# 本机地址与链路本地地址），但 net 侧若也这么干，就会去删 **169.254.0.0/16
# 这类合法的链路本地路由** —— 那是会把用户网络搞断的事故。
# 所以 net 侧**刻意收窄**，只认「一看就是隧道假 IP 池」的那三段。

FAKE_POOL_HOST_RULES = (
    r"0\.0\.0\.0", r"127\.", r"169\.254\.",
    r"198\.1[89]\.", r"100\.6[4-9]\.", r"100\.[7-9]\d\.", r"100\.1[0-2]\d\.",
    r"240\.0\.0\.", r"255\.255\.255\.255",
)
FAKE_POOL_NET_RULES = (
    r"198\.1[89]\.", r"100\.6[4-9]\.", r"240\.0\.0\.",
)

_fake_rule_cache = {}      # kind -> (expire_ts, rules, 已编译正则)
_FAKE_RULE_TTL = 30        # 秒。别为每个域名 / 每条路由都去读一次配置文件


def _fake_compiled(kind):
    """(规则元组, 编译好的正则)，带缓存。用户正则写坏了就退回内置默认。"""
    now = time.time()
    hit = _fake_rule_cache.get(kind)
    if hit and hit[0] > now:
        return hit[1], hit[2]
    builtin = FAKE_POOL_HOST_RULES if kind == "host" else FAKE_POOL_NET_RULES
    got = (load_config_raw().get("fake_ip_pools") or {}).get(kind)
    rules = tuple(str(r) for r in got
                  if isinstance(r, str) and r.strip()) if isinstance(got, list) else ()
    if not rules:
        rules = tuple(builtin)
    try:
        rx = re.compile("|".join(rules))
    except re.error:
        rules = tuple(builtin)      # 绝不让一条写坏的配置把整个界面搞崩
        rx = re.compile("|".join(rules))
    _fake_rule_cache[kind] = (now + _FAKE_RULE_TTL, rules, rx)
    return rules, rx


def is_fake_pool_host(ip):
    """域名「解析」出来的地址是不是落进了假 IP 池。

    ⚠️ 这里原先写的是 `^(…|127\\.|198\\.1[89]\\.|…)$` —— 结尾那个 `$` 紧跟在
    点号后面，等于要求整串就是 "127." / "198.18." 这几个字符串本身，
    **任何真实 IP 都匹配不上**，于是整条「DNS 被改写进假 IP 池」的检测一直是哑的
    （体检报告里永远查不出假 IP，不是没问题，是没在查）。
    现在改成纯前缀匹配，并把规则外置。
    """
    s = (ip or "").strip()
    return bool(s) and bool(_fake_compiled("host")[1].match(s))


def is_fake_pool_net(dest):
    """路由目的地址是不是「隧道假 IP 池」网段。"""
    s = (dest or "").strip()
    return bool(s) and bool(_fake_compiled("net")[1].match(s))


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



