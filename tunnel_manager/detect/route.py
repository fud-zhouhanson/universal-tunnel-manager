# -*- coding: utf-8 -*-
"""tunnel_manager.detect/route — 路由证据（含聚合路由多点抽查）

由 P1 从 server.py 的第 620–758 行**整块搬迁**而来，正文逐字未改。

【切片规则 —— 这不是漏写 import】
本项目按设计保持**单一扁平命名空间**：
  · 开发期入口 `python -m tunnel_manager.main` → 把所有切片拼进一个命名空间再执行；
  · 构建期 `bundle.py` → 同样顺序拼接成单文件 `dist/tunnel-manager.py`（纯源码，不含 exec）。
所以本文件里可以直接引用其它切片定义的函数与常量，无需 import。跨切片调用是既有事实。
本模块对外提供：PROBE_TARGETS、default_route、default_route_mac、default_route_win、iface_of_ip、iface_of_mac 等 11 个
本模块依赖其它切片：_base、detect/iface、util、win/native
"""
>>>SLICE_BODY<<<
# ======================================================================
# 五、路由证据（v2：加聚合路由多点抽查）
# ======================================================================

# 公网多点探测目标 —— 覆盖各聚合路由段，用来抓
# 「默认路由正常、但聚合路由被隧道隐性接管」的客户端。
#
# 背景：aTrust / 雷神这类客户端**不动默认路由**，而是往路由表里塞一组
# 二分之一递减的聚合路由（俗称「1/2/4/8/16/32/64/128 拆分」）：
#     0.0.0.0/1   → 0–127          128.0.0.0/2 → 128–191
#     192.0.0.0/3 → 192–223        224.0.0.0/4 → 224–239（组播段，不会被接管）
#     240.0.0.0/5 → 240–247        248/6 · 252/7 · 254/8 → 248–255（保留）
# 只看默认路由会漏判，所以要在**每一段里各挑几个点**实际探一探。
#
# 12 个点按首字节的分布：0 1 8 20 48 96 | 128 160 176 | 200 208 | 240
#   · 0.0.0.0/1 是最大的一段，给了 6 个点
#   · 224.0.0.0/4 是组播段，客户端不会接管 → **故意不设点**
#
# ⚠️ 改这张表请同步跑 selftest「第十三段」：那里断言了覆盖的完整性 ——
#    少掉一整段就等于那一整块公网失去监控，而这种退化不看断言根本发现不了。
PROBE_TARGETS = [
    "0.1.1.1", "1.1.1.1", "8.8.8.8", "20.20.20.20", "48.48.48.48",
    "96.96.96.96", "128.0.0.1", "160.0.0.1", "176.0.0.1",
    "200.0.0.1", "208.0.0.1", "240.0.0.1",
]


def default_route_mac():
    rc, out, _ = run(["route", "-n", "get", "default"])
    iface = gw = ""
    if rc == 0:
        m = re.search(r"interface:\s*(\S+)", out)
        if m:
            iface = m.group(1)
        m = re.search(r"gateway:\s*(\S+)", out)
        if m:
            gw = m.group(1)
    return iface, gw


def iface_of_mac(ip):
    rc, out, _ = run(["route", "-n", "get", ip])
    if rc != 0:
        return ""
    m = re.search(r"interface:\s*(\S+)", out)
    return m.group(1) if m else ""


def phys_gateway_mac(phys_iface):
    rc, out, _ = run(["ipconfig", "getoption", phys_iface, "router"])
    if rc == 0 and re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", out.strip()):
        return out.strip()
    _, _, gw = default_route_mac()
    return gw


def probe_egress_mac():
    """多点抽查公网出口，返回 {接口: 命中点数}。"""
    counts = {}
    for t in PROBE_TARGETS:
        i = iface_of_mac(t)
        if i:
            counts[i] = counts.get(i, 0) + 1
    return counts


def win_snapshot():
    """默认路由快照：优先 PowerShell，被拦住时退回 `route print` 解析。"""
    if not ps_available()[0]:
        return _nat_snapshot()
    return _win_snapshot_ps()


def _win_snapshot_ps():
    rc, out, _ = run_ps(
        "[Console]::OutputEncoding=[Text.Encoding]::UTF8;"
        "try { [PSCustomObject]@{"
        "routes = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | "
        "Select InterfaceAlias,NextHop,InterfaceMetric) } | "
        "ConvertTo-Json -Depth 4 } catch {}"
    )
    if rc != 0 or not out:
        return {}
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return {}


def default_route_win(snap):
    for r in snap.get("routes", []):
        alias = r.get("InterfaceAlias", "")
        if not is_tunnel_iface(alias, ""):
            return alias, r.get("NextHop", "")
    routes = snap.get("routes", [])
    if routes:
        return routes[0].get("InterfaceAlias", ""), routes[0].get("NextHop", "")
    return "", ""


def default_route():
    """当前默认路由 (接口, 网关) —— 跨平台。"""
    if IS_WIN:
        return default_route_win(win_snapshot())
    return default_route_mac()


def phys_gateway(iface):
    """物理网卡的网关 —— 跨平台。"""
    if IS_WIN:
        for r in (win_snapshot().get("routes") or []):
            if r.get("InterfaceAlias") == iface and r.get("NextHop"):
                return r.get("NextHop", "")
        return ""
    return phys_gateway_mac(iface)


def iface_of_ip(ip):
    """某个目标 IP 按路由表会从哪个接口出去 —— 跨平台。"""
    if IS_WIN:
        return (iface_of_win_batch([ip]) or {}).get(ip, "") or ""
    return iface_of_mac(ip)


def iface_of_win_batch(ips):
    if not ips:
        return {}
    if not ps_available()[0]:
        return _nat_iface_of_batch(ips)     # 自家长前缀匹配，无本地化风险
    ip_list = ",".join(f"'{i}'" for i in ips)
    rc, out, _ = run_ps(
        "[Console]::OutputEncoding=[Text.Encoding]::UTF8;"
        f"$ips = @({ip_list});"
        "foreach ($i in $ips) {"
        "  $r = Find-NetRoute -DestinationIPAddress $i "
        "-ErrorAction SilentlyContinue | Select-Object -First 1;"
        "  [PSCustomObject]@{ ip = $i; iface = $r.InterfaceAlias }"
        "} | ConvertTo-Json"
    )
    result = {}
    if rc != 0 or not out:
        return result
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return result
    if isinstance(data, dict):
        data = [data]
    for row in data:
        result[row.get("ip", "")] = row.get("iface", "") or ""
    return result


