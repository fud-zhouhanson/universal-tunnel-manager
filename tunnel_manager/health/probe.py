# -*- coding: utf-8 -*-
"""tunnel_manager.health/probe — 流量体检基座（本地地址映射 / 首跳 / 并发）

由 P2 从 health/flow.py 的第 1–146 行**原样拆出**，正文逐字未改（与 P1 一样，只搬不改）。

【切片规则 —— 这不是漏写 import】
本项目按设计保持**单一扁平命名空间**：
  · 开发期入口 `python -m tunnel_manager.main` → 把所有切片拼进一个命名空间再执行；
  · 构建期 `bundle.py` → 同样顺序拼接成单文件 `dist/tunnel-manager.py`（纯源码，不含 exec）。
所以本文件里可以直接引用其它切片定义的函数与常量，无需 import。跨切片调用是既有事实。
本模块对外提供：HEALTH_FILE、RESCUE_LOG、TRUTH_DOMAINS、TRUTH_TARGETS、first_hop 等 10 个
本模块依赖其它切片：_base、config、detect/iface、outlet/scene_ops、util
"""
>>>SLICE_BODY<<<
# ======================================================================
# 七·五、真实流量体检（"流量到底去哪了"）+ 一键应急恢复
# ======================================================================
#
# 为什么不能只读配置：路由表和 DNS 都是「声明」，不是「事实」。
# DNS 与隧道被倒腾乱之后，最典型的三类故障，光看配置全都"正常"：
#   1) 声明走物理、实际被拽进隧道，或干脆被黑洞 —— 配置看不出任何问题
#   2) DNS 被隧道改写，把域名解析进假 IP 池（198.18.x.x 之类）——
#      表现就是"显示在加速但没效果"
#   3) DNS 服务器早已失效 / 指向不存在的地址
# 所以这里一律用「观测」：真解析一次、真连一次、真看第一跳。

TRUTH_TARGETS = [
    ("腾讯", "119.29.29.29"),
    ("阿里 DNS", "223.5.5.5"),
    ("百度", "110.242.68.66"),
    ("Cloudflare", "1.1.1.1"),
    ("GitHub", "140.82.112.3"),
]

TRUTH_DOMAINS = ["www.baidu.com", "www.qq.com", "github.com"]

# 假 IP 池的判定规则**不在本文件** —— 它已经外置到 config.py（可配置），
# 用 is_fake_pool_host() / is_fake_pool_net() 取用。这里只留一句提醒：
# 两组规则的语义不同（host 前缀 vs net 前缀），不要合并，理由见 config.py 的注释。

HEALTH_FILE = os.path.join(CONFIG_DIR, "health.json")
RESCUE_LOG = os.path.join(CONFIG_DIR, "rescue.log")


def local_addr_map(interfaces=None):
    """IPv4 → 接口名。用来把内核选中的源地址翻译成「实际从哪出去」。"""
    m = {}
    if interfaces:
        for i in interfaces:
            if i.get("ipv4"):
                m[i["ipv4"]] = i["name"]
        if m:
            return m
    if IS_WIN:
        for i in scan_interfaces_win():
            if i.get("ipv4"):
                m[i["ipv4"]] = i["name"]
        return m
    cur = ""
    for line in _sh("ifconfig").splitlines():
        if line and not line[0].isspace():
            cur = line.split(":")[0].strip()
        else:
            mm = re.search(r"\binet\s+(\d+\.\d+\.\d+\.\d+)", line)
            if mm and cur:
                m[mm.group(1)] = cur
    return m


def src_addr_for(ip, port=53, timeout=1.0):
    """UDP connect 一个包都不发，但内核会按路由表选路并挑好源地址 ——
    这是「实际会从哪出去」最直接的证据，比读路由表更接近事实。"""
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        return s.getsockname()[0]
    except OSError:
        return ""
    finally:
        if s:
            s.close()


def tcp_probe(ip, port=443, timeout=2.0):
    s = None
    t0 = time.time()
    try:
        s = socket.create_connection((ip, port), timeout=timeout)
        return True, round((time.time() - t0) * 1000), s.getsockname()[0]
    except OSError:
        return False, None, ""
    finally:
        if s:
            try:
                s.close()
            except OSError:
                pass


def first_hop(ip):
    """第一跳到底是谁 —— 这是**实测**，不是读路由表。

    做法：发一个 TTL=1 的 ping，逼第一跳路由器回一条 "Time to live exceeded"，
    从回复里把它的地址读出来。macOS 的 ping 是 setuid 的，普通用户就能跑
    （这点比 traceroute 强 —— 后者在很多受限环境里会被拒）。
    实在拿不到再退回 traceroute。
    """
    if IS_WIN:
        # Windows 的 ping 用 `-i` 指定 TTL、`-w` 是毫秒超时。
        # TTL=1 会逼第一跳回一条 "Reply from x.x.x.x: TTL expired in transit."
        rc, out, _ = run(["ping", "-n", "1", "-i", "1", "-w", "1000", ip],
                         timeout=6)
        m = re.search(r"[Rr]eply from\s+(\d+\.\d+\.\d+\.\d+)", out or "")
        return m.group(1) if m else ""
    out = _sh(f"ping -c 1 -m 1 -W 400 -t 2 {ip} 2>&1", timeout=4)
    m = re.search(r"from\s+\S+\s+\((\d+\.\d+\.\d+\.\d+)\)", out)
    if m:
        return m.group(1)
    m = re.search(r"[Ff]rom\s+(\d+\.\d+\.\d+\.\d+)", out)
    if m:
        return m.group(1)
    return ""


def parallel_map(fn, items, workers=6):
    """小并发跑一批「只读探测」（ping / DNS / TCP）。

    体检如果全串行要 10 秒以上，点一下按钮等十秒太难受；
    这些操作彼此完全独立、也没有共享状态，并发起来能压到 2 秒左右。
    """
    items = list(items)
    if not items:
        return []
    out = [None] * len(items)
    pending = list(range(len(items)))
    lock = threading.Lock()

    def worker():
        while True:
            with lock:
                if not pending:
                    return
                i = pending.pop(0)
            try:
                out[i] = fn(items[i])
            except Exception:       # noqa: BLE001 —— 单个探测失败不影响其它
                out[i] = None

    threads = [threading.Thread(target=worker, daemon=True)
               for _ in range(max(1, min(workers, len(items))))]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return out


