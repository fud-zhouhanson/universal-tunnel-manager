# -*- coding: utf-8 -*-
"""tunnel_manager.health/trace — 路径追踪 do_trace（只观测不声明）

由 P2 从 health/flow.py 的第 336–473 行**原样拆出**，正文逐字未改（与 P1 一样，只搬不改）。

【切片规则 —— 这不是漏写 import】
本项目按设计保持**单一扁平命名空间**：
  · 开发期入口 `python -m tunnel_manager.main` → 把所有切片拼进一个命名空间再执行；
  · 构建期 `bundle.py` → 同样顺序拼接成单文件 `dist/tunnel-manager.py`（纯源码，不含 exec）。
所以本文件里可以直接引用其它切片定义的函数与常量，无需 import。跨切片调用是既有事实。
本模块对外提供：do_trace
本模块依赖其它切片：_base、detect/iface、detect/route、health/dns、health/egress、health/probe
"""
>>>SLICE_BODY<<<
def do_trace():
    """真实流量体检：不看配置，只看事实。返回结构化报告 + 一句话结论。"""
    t0 = time.time()
    phys, phys_gw = phys_iface_guess()
    def_iface, def_gw = default_route()
    dhcp = dhcp_dns(phys)
    cur_dns = system_dns_servers()
    query_dns = ipv4_dns_servers(cur_dns) or ["223.5.5.5"]   # 直查只用 IPv4

    # ---- 面板 1：路由（声明 vs 实测）----
    # 用固定 IP 而不是域名 —— 这样即使 DNS 已经挂了，这一栏照样能出结论
    am = local_addr_map()
    hops = parallel_map(first_hop, [ip for _l, ip in TRUTH_TARGETS], workers=6)
    decl_map = (iface_of_win_batch([ip for _l, ip in TRUTH_TARGETS])
                if IS_WIN
                else {ip: iface_of_mac(ip) for _l, ip in TRUTH_TARGETS})
    routes = []
    for (label, ip), hop in zip(TRUTH_TARGETS, hops):
        hop = hop or ""                          # 实测：TTL=1 逼出来的第一跳
        decl = decl_map.get(ip, "")              # 声明：路由表怎么写的
        src = src_addr_for(ip)                   # 实测：内核给这个目标挑了哪个源地址
        sif = am.get(src, "")

        hop_is_phys = bool(hop and phys_gw and hop == phys_gw)
        hop_other = bool(hop and not hop_is_phys)
        if hop_is_phys:
            actual = phys
        elif hop_other:
            actual = f"非物理（{hop}）"
        else:
            actual = sif or "?"

        mismatch = False
        if decl and is_tunnel_iface(decl) and hop_is_phys:
            mismatch = True                      # 路由说走隧道，包却从物理出去了
        elif decl and is_phys_iface(decl) and hop_other:
            mismatch = True                      # 路由说走物理，包却被拽到别处
        elif decl and sif and decl != sif and not hop:
            mismatch = True

        routes.append({
            "label": label, "ip": ip, "declared_iface": decl,
            "src_ip": src, "src_iface": sif, "first_hop": hop,
            "actual": actual, "mismatch": mismatch,
        })

    # ---- 面板 2：DNS（系统解析 vs 绕过系统直查）----
    servers = query_dns[:2]
    resolved = parallel_map(sys_resolve, TRUTH_DOMAINS, workers=4)
    pairs = [(srv, dom) for dom in TRUTH_DOMAINS for srv in servers]
    raws = parallel_map(lambda p: dns_query(p[0], p[1], timeout=2.5), pairs, workers=6)

    dns_rows, sys_cache = [], {}
    for i, dom in enumerate(TRUTH_DOMAINS):
        ips, ms, err = resolved[i] or ([], None, "")
        sys_cache[dom] = ips
        direct = []
        for j, srv in enumerate(servers):
            rc_, d_ips = raws[i * len(servers) + j] or (None, [])
            direct.append({"server": srv, "rcode": rc_, "ips": d_ips})
        fake = sorted({p for p in ips if FAKE_IP_RE.match(p)})
        dset = set()
        for d in direct:
            dset |= set(d["ips"])
        dns_rows.append({
            "domain": dom, "sys_ips": ips, "sys_ms": ms, "sys_err": err,
            "direct": direct, "fake_ips": fake,
            "disagree": bool(ips and dset and not (set(ips) & dset)),
        })

    # ---- 面板 3：连通性（照 DNS 结果真连一次）----
    probe_list = [(dom, ip) for dom in TRUTH_DOMAINS
                  for ip in (sys_cache.get(dom) or [])[:2]]
    pres = parallel_map(lambda t: tcp_probe(t[1], 443, timeout=3), probe_list, workers=6)
    phops = parallel_map(lambda t: first_hop(t[1]), probe_list, workers=6)
    conns_map = {dom: [] for dom in TRUTH_DOMAINS}
    for (dom, ip), pr, ph in zip(probe_list, pres, phops):
        ok_c, ms_c, _s = pr or (False, None, "")
        conns_map[dom].append({"ip": ip, "ok": ok_c, "ms": ms_c,
                               "first_hop": ph or ""})
    conns = [{"domain": dom, "ips": conns_map[dom],
              "ok": any(e["ok"] for e in conns_map[dom])} for dom in TRUTH_DOMAINS]

    # ---- 面板 4：汇总判定 ----
    issues, notes = [], []
    mm = [r for r in routes if r["mismatch"]]
    if mm:
        issues.append(f"{len(mm)} 个探测点的「路由表说的」和「实际走的」不一致")
    no_hop = [r for r in routes if not r["first_hop"]]
    if no_hop:
        notes.append(f"{len(no_hop)} 个探测点没拿到第一跳（丢包，或该目标不回 TTL 超时包）")
    fake_dom = [d for d in dns_rows if d["fake_ips"]]
    if fake_dom:
        issues.append("、".join(d["domain"] for d in fake_dom)
                      + f" 被解析进假 IP 池（如 {fake_dom[0]['fake_ips'][0]}）—— 典型的隧道接管特征")
    bad_dns = [d for d in dns_rows if not d["sys_ips"]]
    if bad_dns:
        issues.append("、".join(d["domain"] for d in bad_dns) + " 解析失败（DNS 可能已失效）")
    dis = [d for d in dns_rows if d["disagree"] and not d["fake_ips"]]
    if dis:
        issues.append("、".join(d["domain"] for d in dis)
                      + " 的系统解析结果与直查不一致（可能被改写，也可能只是 CDN 差异）")
    down = [c for c in conns if not c["ok"]]
    if down:
        issues.append("、".join(c["domain"] for c in down) + " 连不上（可能被黑洞或被拦）")
    dns_overridden = bool(dhcp and cur_dns and not (set(dhcp) & set(cur_dns)))
    if dns_overridden:
        issues.append("系统 DNS 与物理网络 DHCP 给的（" + "、".join(dhcp) + "）完全不同，DNS 已被覆盖")

    phys_n = sum(1 for r in routes if r["actual"] == phys)
    via_summary = (f"{len(routes)} 个探测点里 {phys_n} 个确认从物理网卡"
                   f"（{phys or def_iface or '?'}）出去，{len(routes) - phys_n} 个走了别的路径")

    if not issues:
        summary = (f"流量正常：{via_summary}；"
                   f"DNS（{'、'.join(cur_dns) or '系统默认'}）解析正常，"
                   f"{len(conns)} 个网站都能连通")
    else:
        summary = f"发现 {len(issues)} 项异常：" + "；".join(issues)

    return {
        "ok": True, "at": time.time(),
        "elapsed_ms": round((time.time() - t0) * 1000),
        "clean": not issues,
        "phys_iface": phys, "phys_gw": phys_gw,
        "default_iface": def_iface, "default_gw": def_gw,
        "dns_now": cur_dns, "dns_dhcp": dhcp, "dns_query_used": query_dns,
        "dns_overridden": dns_overridden,
        "routes": routes, "dns": dns_rows, "conns": conns,
        "via_summary": via_summary,
        "issues": issues, "notes": notes, "summary": summary,
    }


# ----------------------------------------------------------------------
# 应急恢复
# ----------------------------------------------------------------------

