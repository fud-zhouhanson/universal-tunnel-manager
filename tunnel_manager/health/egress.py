# -*- coding: utf-8 -*-
"""tunnel_manager.health/egress — 出口猜测与快速出口探测

由 P2 从 health/flow.py 的第 287–335 行**原样拆出**，正文逐字未改（与 P1 一样，只搬不改）。

【切片规则 —— 这不是漏写 import】
本项目按设计保持**单一扁平命名空间**：
  · 开发期入口 `python -m tunnel_manager.main` → 把所有切片拼进一个命名空间再执行；
  · 构建期 `bundle.py` → 同样顺序拼接成单文件 `dist/tunnel-manager.py`（纯源码，不含 exec）。
所以本文件里可以直接引用其它切片定义的函数与常量，无需 import。跨切片调用是既有事实。
本模块对外提供：phys_iface_guess、quick_egress
本模块依赖其它切片：_base、detect/iface、detect/route、health/probe
"""
>>>SLICE_BODY<<<
def phys_iface_guess():
    """猜物理出口：默认路由那条若非隧道就用它，否则找第一个活跃的物理口。"""
    if IS_WIN:
        def_iface, def_gw = default_route()
        phys = def_iface if is_phys_iface(def_iface) else ""
        if not phys:
            for i in scan_interfaces_win():
                if i.get("status") != "active":
                    continue
                if is_phys_iface(i["name"], i.get("desc") or ""):
                    phys = i["name"]
                    break
        gw = def_gw if phys == def_iface else (phys_gateway(phys) if phys else def_gw)
        return phys, gw
    def_iface, def_gw = default_route_mac()
    phys = def_iface if is_phys_iface(def_iface) else ""
    if not phys:
        for _ip, n in sorted(local_addr_map().items()):
            if is_phys_iface(n):
                phys = n
                break
    return phys, (def_gw if phys == def_iface else (phys_gateway_mac(phys) if phys else def_gw))


def quick_egress(res):
    """轻量版「声明 vs 实测」：只做 UDP 选路（不发包、微秒级），可随每次扫描跑。

    Windows 的「声明」要一次问完 —— Find-NetRoute 每条都起一次 PowerShell
    太慢，所以先把这几个目标凑成一批。
    """
    am = local_addr_map(res.get("interfaces"))
    targets = TRUTH_TARGETS[:4]
    if IS_WIN:
        decls = iface_of_win_batch([ip for _l, ip in targets])
    else:
        decls = {ip: iface_of_mac(ip) for _l, ip in targets}
    rows = []
    for label, ip in targets:
        decl = decls.get(ip, "")
        src = src_addr_for(ip)
        sif = am.get(src, "")
        rows.append({
            "label": label, "ip": ip,
            "declared_iface": decl, "src_ip": src, "src_iface": sif,
            "mismatch": bool(decl and sif and decl != sif),
        })
    return rows


