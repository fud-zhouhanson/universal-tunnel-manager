# -*- coding: utf-8 -*-
"""tunnel_manager.health/snapshot — 健康基线快照与假 IP 池

由 P2 从 health/flow.py 的第 474–545 行**原样拆出**，正文逐字未改（与 P1 一样，只搬不改）。

【切片规则 —— 这不是漏写 import】
本项目按设计保持**单一扁平命名空间**：
  · 开发期入口 `python -m tunnel_manager.main` → 把所有切片拼进一个命名空间再执行；
  · 构建期 `bundle.py` → 同样顺序拼接成单文件 `dist/tunnel-manager.py`（纯源码，不含 exec）。
所以本文件里可以直接引用其它切片定义的函数与常量，无需 import。跨切片调用是既有事实。
本模块对外提供：fake_pool_routes、health_snapshot、load_health、net_service_for_iface、save_health
本模块依赖其它切片：_base、detect/route、health/dns、health/egress、health/probe、outlet/scene_ops、win/identify
"""
>>>SLICE_BODY<<<
def net_service_for_iface(iface):
    """networksetup 要的是「网络服务名」（如 Wi-Fi），不是接口名 en0。"""
    if not iface:
        return ""
    out = _sh("networksetup -listnetworkserviceorder 2>/dev/null")
    for m in re.finditer(r"\(\d+\)\s*(.+?)\n\(Hardware Port:.*?Device:\s*([^\)\n]+)\)", out):
        if m.group(2).strip() == iface:
            return m.group(1).strip()
    return ""


def health_snapshot():
    """采集一份「健康基线」：物理出口 / 网关 / 网络服务名 / 各级 DNS。"""
    phys, gw = phys_iface_guess()
    if not phys:
        return None
    return {
        "at": time.time(),
        "phys_iface": phys,
        "phys_gw": gw,
        "net_service": net_service_for_iface(phys),
        "dns_dhcp": dhcp_dns(phys),
        "dns_now": system_dns_servers(),
        "default_iface": default_route_mac()[0],
    }


def save_health():
    snap = health_snapshot()
    if not snap:
        return False, "识别不出物理网卡，无法保存基线"
    try:
        os.makedirs(CONFIG_DIR, exist_ok=True)
        with open(HEALTH_FILE, "w", encoding="utf-8") as f:
            json.dump(snap, f, ensure_ascii=False, indent=2)
    except OSError as e:
        return False, f"写入失败：{e}"
    return True, (f"健康基线已保存：物理出口 {snap['phys_iface']} / 网关 "
                  f"{snap.get('phys_gw') or '?'} / DNS "
                  f"{'、'.join(snap.get('dns_dhcp') or []) or '由 DHCP 自动分配'}")


def load_health():
    try:
        with open(HEALTH_FILE, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def fake_pool_routes():
    """路由表里指向「假 IP 池」网段的条目（隧道接管的典型痕迹）。"""
    found = []
    for dest, _alias in _routes_snapshot():
        if "/" not in dest:
            continue
        if re.match(r"^(198\.1[89]\.|100\.6[4-9]\.|240\.0\.0\.)", dest.split("/")[0]):
            found.append(dest)
    return sorted(set(found))


def _rescue_log(lines):
    try:
        os.makedirs(CONFIG_DIR, exist_ok=True)
        if os.path.isfile(RESCUE_LOG) and os.path.getsize(RESCUE_LOG) > 512_000:
            os.replace(RESCUE_LOG, RESCUE_LOG + ".1")
        with open(RESCUE_LOG, "a", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
    except OSError:
        pass


