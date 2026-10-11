# -*- coding: utf-8 -*-
"""tunnel_manager.steam/commands — Steam 体检端点入口

由 P2 从 health/flowrate.py 的第 419–559 行**原样拆出**，正文逐字未改（与 P1 一样，只搬不改）。

【切片规则 —— 这不是漏写 import】
本项目按设计保持**单一扁平命名空间**：
  · 开发期入口 `python -m tunnel_manager.main` → 把所有切片拼进一个命名空间再执行；
  · 构建期 `bundle.py` → 同样顺序拼接成单文件 `dist/tunnel-manager.py`（纯源码，不含 exec）。
所以本文件里可以直接引用其它切片定义的函数与常量，无需 import。跨切片调用是既有事实。
本模块对外提供：do_steam_diagnose、do_steam_overview、do_steam_probe
本模块依赖其它切片：_base、detect/iface、health/egress、health/probe、steam/api、steam/capture、steam/paths、steam/sdr、steam/summary、steam/trace
"""
>>>SLICE_BODY<<<
def do_steam_overview():
    """快照：安装/运行/账号/下载区域 + 平台网（CM 延迟）+ 游戏进程 + 采样状态。"""
    t0 = time.time()
    env = steam_env()
    cl = parse_steam_conn_log()
    csl = parse_steam_console_log()
    cl["latest"] = annotate_conn_rows(cl.get("latest") or [])
    return {
        "ok": True, "at": time.time(),
        "elapsed_ms": round((time.time() - t0) * 1000),
        "env": env, "cm": cl, "console": csl,
        "store_domains": STEAM_STORE_DOMAINS,
        "capture": capture_state(),
        "sdr_meta": {"source": "local" if env.get("sdr_cache") else "",
                     "error": ""},
    }


def do_steam_probe(appid=None, cell=None, force_online=False):
    """排行：CM 集群 / SDR 中继 / CDN / 商店 —— 真解析、真连、真看第一跳。"""
    if not IS_MAC:
        return {"error": f"实时探测暂仅支持 macOS（当前 {PLATFORM}）"}
    t0 = time.time()
    env = steam_env()
    appid, app_name = (str(appid), "") if appid else steam_guess_appid(env)
    cell_id = int(cell) if cell else env.get("cell_id") or STEAM_CDN_CELL

    pops, sdr_meta = steam_sdr_pops(appid, prefer_online=force_online)
    relays = sdr_relay_targets(pops, limit=12)
    phys, phys_gw = phys_iface_guess()
    am = local_addr_map()

    # 中继：先 ICMP（网络层参考值），再判它走哪条路。
    # 这里**不做第一跳** —— 每个目标 ping 一次要等超时，几十个目标会把体检拖到一分钟。
    # 判定「走没走加速器」靠源地址 + 路由声明就够了（和 quick_egress 同口径）。
    rtts = parallel_map(lambda r: icmp_probe(r["ip"]), relays, workers=12)
    for r, pair in zip(relays, rtts):
        ok, ms = pair or (False, None)
        r["icmp_ok"], r["icmp_ms"] = ok, ms
        p = steam_path_of(r["ip"], am, phys_gw, want_hop=False)
        for k in ("declared_iface", "src_ip", "src_iface", "first_hop",
                  "is_tunnel", "is_phys", "mismatch", "via"):
            r[k] = p[k]

    # CM 集群（平台网）
    cms = cm_targets(cell_id, limit=6)
    crows = parallel_map(
        lambda c: probe_host(c["host"], int(c["port"] or 443), am, phys_gw,
                             want_hop=False), cms, workers=6)
    for c, row in zip(cms, crows):
        c.update(row or {"via": "解析失败"})

    # 商店 / 社区 / API —— 这一组开第一跳：它是「直连还是加速器」证据最强的一栏
    stores = parallel_map(
        lambda d: probe_host(d, 443, am, phys_gw, want_hop=True),
        STEAM_STORE_DOMAINS, workers=4)

    # 内容分发网：官方列表 + 历史真实主机
    cdn = steam_cdn_servers(cell_id)
    for c in steam_cdn_history():
        if c["host"] not in [x["host"] for x in cdn]:
            cdn.append(c)
    cdn = cdn[:10]
    crows2 = parallel_map(
        lambda c: probe_host(c["host"], 80, am, phys_gw, want_hop=False),
        cdn, workers=6)
    for c, row in zip(cdn, crows2):
        c.update(row or {"via": "解析失败"})

    # 隧道 MTU 事实
    low_mtu = []
    try:
        for i in scan_interfaces_mac():
            if (i.get("status") == "active" and is_tunnel_iface(i["name"])
                    and i.get("mtu") and i["mtu"] < 1400):
                low_mtu.append((i["name"], i["mtu"]))
    except Exception:       # noqa: BLE001 —— 拿不到就不报
        pass

    return {
        "ok": True, "at": time.time(),
        "elapsed_ms": round((time.time() - t0) * 1000),
        "appid": appid, "app_name": app_name,
        "cell_id": cell_id,
        "phys_iface": phys, "phys_gw": phys_gw,
        "sdr_meta": sdr_meta, "pop_count": len(pops),
        "relays": relays, "cm": cms, "store": stores, "cdn": cdn,
        "low_mtu_tunnels": low_mtu,
        "capture": capture_result(relays),
    }


def do_steam_diagnose(appid=None, cell=None):
    """体检结论：把三类观测汇到规则库，产出「原因 + 建议」。"""
    if not IS_MAC:
        return {"error": f"暂仅支持 macOS（当前 {PLATFORM}）"}
    ov = do_steam_overview()
    pb = do_steam_probe(appid=appid, cell=cell)
    if pb.get("error"):
        return pb
    facts = {
        "env": ov.get("env") or {},
        "cm": ov.get("cm") or {},
        "console": ov.get("console") or {},
        "relays": pb.get("relays") or [],
        "cms": pb.get("cm") or [],
        "store": pb.get("store") or [],
        "cdn": pb.get("cdn") or [],
        "sdr_meta": pb.get("sdr_meta") or {},
        "low_mtu_tunnels": pb.get("low_mtu_tunnels") or [],
        "capture": pb.get("capture") or {},
    }
    findings = steam_diagnose(facts)
    hi = [f for f in findings if f["level"] == "high"]
    mid = [f for f in findings if f["level"] == "mid"]
    if hi:
        summary = f"发现 {len(hi)} 项高优先级问题：" + hi[0]["title"]
    elif mid:
        summary = f"发现 {len(mid)} 项需要注意的问题：" + mid[0]["title"]
    else:
        summary = "没有发现明显问题（已完成的观测范围内）"
    return {
        "ok": True, "at": time.time(),
        "appid": pb.get("appid"), "app_name": pb.get("app_name"),
        "cell_id": pb.get("cell_id"),
        "elapsed_ms": (ov.get("elapsed_ms") or 0) + (pb.get("elapsed_ms") or 0),
        "summary": summary,
        "counts": {"high": len(hi), "mid": len(mid),
                   "info": len(findings) - len(hi) - len(mid)},
        "findings": findings,
        "relays": pb.get("relays") or [],
        "cm": pb.get("cm") or [],
        "store": pb.get("store") or [],
        "cdn": pb.get("cdn") or [],
        "capture": pb.get("capture") or {},
        "sdr_meta": pb.get("sdr_meta") or {},
        "low_mtu_tunnels": pb.get("low_mtu_tunnels") or [],
        "phys_iface": pb.get("phys_iface"), "phys_gw": pb.get("phys_gw"),
    }


