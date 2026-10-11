# -*- coding: utf-8 -*-
"""tunnel_manager.steam/summary — Steam 体检汇总

由 P2 从 health/flowrate.py 的第 236–418 行**原样拆出**，正文逐字未改（与 P1 一样，只搬不改）。

【切片规则 —— 这不是漏写 import】
本项目按设计保持**单一扁平命名空间**：
  · 开发期入口 `python -m tunnel_manager.main` → 把所有切片拼进一个命名空间再执行；
  · 构建期 `bundle.py` → 同样顺序拼接成单文件 `dist/tunnel-manager.py`（纯源码，不含 exec）。
所以本文件里可以直接引用其它切片定义的函数与常量，无需 import。跨切片调用是既有事实。
本模块对外提供：steam_diagnose、steam_summary
本模块依赖其它切片：_base、steam/api、steam/capture、steam/trace
"""
>>>SLICE_BODY<<<
def steam_diagnose(facts):
    """把观测事实映射成「原因 + 建议」。没有证据就不下结论。"""
    out = []

    def add(level, title, detail, advice=""):
        out.append({"level": level, "title": title, "detail": detail,
                    "advice": advice})

    env = facts.get("env") or {}
    if not env.get("installed"):
        add("info", "没找到 Steam 安装",
            "按该平台的常见路径都没找到 Steam 目录，下面所有检测都没有对象。",
            "先装好 Steam 并至少登录一次。")
        return out
    if not env.get("running"):
        add("info", "Steam 当前没在运行",
            "「连接日志」里的记录是上一次连接时写下的，可能已经过期；"
            "游戏进程相关的判断也会缺数据。",
            "开着 Steam 再做体检更准。")

    # R1 加速器接管了 SDR 中继 ★最重要的一条
    relays = facts.get("relays") or []
    tun_relays = [r for r in relays if r.get("is_tunnel")]
    if tun_relays:
        names = "、".join(f"{r['pop']}({r['ip']})" for r in tun_relays[:4])
        add("high", "加速器正在接管 SDR 中继",
            f"{len(tun_relays)} 个中继点（{names}）的流量走了隧道接口而不是物理网卡。"
            "杀戮尖塔这类游戏联机走的是 Steam Datagram Relay（Valve 自己的骨干中继），"
            "绕经加速器只会多一跳、还把可用 MTU 压小。",
            "在加速器里针对该游戏关闭加速，或整体停掉加速后重测。")

    # R2 隧道 MTU 偏小
    low = facts.get("low_mtu_tunnels") or []
    if low:
        names = "、".join(f"{n}（MTU {m}）" for n, m in low)
        add("high", "隧道 MTU 偏小，UDP 大包会被分片丢弃",
            f"{names} 的 MTU 低于 1400。游戏联机走 UDP，大包一旦分片，"
            "任何一片丢失都要整包重传 —— 表现就是「能进游戏但频繁瞬卡或掉线」。",
            "关掉这些隧道，或在客户端里把 MTU 调大。")

    # R3 实际命中的中继点
    cap = facts.get("capture") or {}
    an = cap.get("analysis") or {}
    hit = an.get("hit_relays") or []
    unknown = an.get("unknown_peers") or []
    if hit:
        pops = sorted({h["pop"] for h in hit})
        txt = "、".join(f"{h['pop']}（{h.get('pop_cn') or '?'}）{h['ip']}:{h['port']}"
                        for h in hit[:4])
        if "hkg" not in pops:
            add("mid", "实际连的中继不是香港",
                f"采样期间对端是 {txt}。国内玩家最近的 SDR 中继在香港（hkg），"
                "命中别的 pop 说明去香港的链路可能异常，或加速器改掉了选点。",
                "对比 hkg 各中继的 RTT 后再决定是否关加速。")
        else:
            add("info", "实际连的中继在香港",
                f"采样期间对端是 {txt} —— 这是国内玩家最理想的中继位置。")
        sub_only = [h for h in hit if h.get("match") == "subnet"]
        if sub_only:
            add("info", "有中继是按同网段推断的归属",
                "、".join(f"{h['ip']}（{h['pop']}）" for h in sub_only[:4])
                + " 不在本地缓存的 SDR 名单里，是按同一个 /24 网段推断出来的。"
                "Steam 的中继 IP 会换号，本地缓存只在上次联网时更新。",
                "点「刷新 SDR 名单」从官方接口重拉一次，归属会更准。")
    elif unknown:
        add("info", "抓到了对端，但认不出是哪个中继",
            "采样期间该进程连过 " + "、".join(f"{u['ip']}:{u['port']}"
                                        for u in unknown[:4])
            + "，这些 IP 不在已知中继名单里。可能是较新的中继（本地 SDR 缓存偏旧），"
            "也可能根本不是 Steam 的中继流量。",
            "点「刷新 SDR 名单」后重测，或进入对局后再采样一次。")
    elif cap.get("done"):
        add("info", "没抓到游戏的对端 IP",
            "采样期间该进程没有出现公网 UDP/TCP 对端。可能当时不在联机中，"
            "也可能游戏走的是别的进程。",
            "进入对局后再采样一次。")

    # R4 断续与乱序
    zr = an.get("zero_ratio")
    if zr is not None and zr > 0.2:
        add("mid", f"联机流量断续：{int(zr * 100)}% 的秒数没有数据",
            f"采样 {an.get('active_seconds')} 个有效秒里有 {an.get('zero_seconds')} 秒"
            "收发都为 0。" + ("期间目标进程还消失了 "
                          f"{an.get('missing_seconds')} 秒（可能已退出对局）。"
                          if an.get("missing_seconds") else ""),
            "配合下面「走哪条路」的判断一起看，先排除加速器与 MTU 问题。")
    if (an.get("rx_ooo_delta") or 0) > 0 or (an.get("re_tx_delta") or 0) > 0:
        add("mid", "出现乱序 / 重传",
            f"采样期间累计乱序 {an.get('rx_ooo_delta')} 字节、"
            f"重传 {an.get('re_tx_delta')} 次。这是「卡一下再跳回来」的直接物证。",
            "如果同时存在隧道接管或 MTU 偏小，优先处理那两项。")

    # R5 Steam 客户端自身反复重连（只算最近 24 小时，避免把历史累积误读成现状）
    cl = facts.get("console") or {}
    r24 = cl.get("restarts_24h") or 0
    if r24 >= 8:
        add("mid", "Steam 客户端反复重连",
            f"最近 24 小时的日志里出现 {r24} 次「Game process added」，"
            "说明客户端层在反复起停游戏进程 —— 这与加速器无关。",
            "先确认 Steam 自身网络正常，再看联机质量。")

    # R6 商店 / 社区
    tun_store = [d for d in (facts.get("store") or []) if d.get("is_tunnel")]
    if tun_store:
        add("mid", "商店 / 社区流量被隧道接管",
            "、".join(f"{d['host']}（{d['via']}）" for d in tun_store[:4])
            + "。商店和社区被绕进隧道后，常见症状是登录转圈、社区打不开。",
            "如果只是要开社区，考虑把这几个域名切到直连再试。")

    # R7 下载 CDN
    tun_cdn = [c for c in (facts.get("cdn") or []) if c.get("is_tunnel")]
    if tun_cdn:
        add("mid", "下载 CDN 被隧道接管",
            "、".join(f"{c['host']}（{c['via']}）" for c in tun_cdn[:4])
            + "。Steam 下载走的是国内 CDN，被加速器绕出去通常只会更慢。",
            "下载时建议关掉加速器。")

    # R8 ICMP 几乎全不可达 —— 如实说明这只是参考值
    if relays:
        dead = [r for r in relays if not r.get("icmp_ok")]
        if len(dead) > len(relays) * 0.6:
            add("info", "多数中继不回 ICMP",
                f"{len(dead)}/{len(relays)} 个中继点 ping 不通。"
                "SDR 走 UDP，中继不回 ICMP 是常见现象，**不代表游戏连不上**，"
                "别据此判断联机质量。",
                "以「实测联机」与「采样」的结论为准。")

    # R9 SDR 配置拿不到
    if (facts.get("sdr_meta") or {}).get("error"):
        add("info", "SDR 中继列表不完整",
            (facts.get("sdr_meta") or {}).get("error") or "",
            "中继探测结果可能不全，等 Steam 客户端跑过一次再试。")

    # R10 还没采样
    if not cap.get("done"):
        add("info", "还没做过联机采样",
            "P2P 稳定性必须在对局中边跑边采样才能判断，单看配置得不出结论。",
            "进游戏开一局，点「开始采样」，样本越长越准（建议 60 秒）。")

    return out


# ----------------------------------------------------------------------
# 对外入口
# ----------------------------------------------------------------------

def steam_summary():
    """给 /api/scan 用的**轻量摘要**：只读进程 + 日志尾部，不跑任何网络探测。

    必须保持在几十毫秒量级 —— 不能把扫描拖慢。
    """
    if not IS_MAC and not IS_WIN:
        return {"supported": False}
    env = steam_env()
    if not env.get("installed"):
        return {"supported": True, "installed": False, "running": False}
    cl = parse_steam_conn_log()
    best = (cl.get("cm") or [None])[0]
    last = (cl.get("latest") or [None])[-1]
    if last:
        last = dict(last)
        _iface, _verdict = _local_ip_verdict(last.get("local_ip"))
        last["local_iface"], last["verdict"] = _iface, _verdict
    return {
        "supported": True,
        "installed": True,
        "running": env.get("running"),
        "cell_id": env.get("cell_id"),
        "game_name": env.get("game_name"),
        "running_game": (env.get("running_game") or {}).get("app_dir", ""),
        "cm_best": ({"dc": best.get("dc"), "dc_cn": best.get("dc_cn"),
                     "ms": best.get("ms")} if best else None),
        "cm_count": len(cl.get("cm") or []),
        "last_conn": ({"at": last.get("at"), "server_ip": last.get("server_ip"),
                       "local_ip": last.get("local_ip"),
                       "local_iface": last.get("local_iface"),
                       "verdict": last.get("verdict")} if last else None),
        "log_at": cl.get("at") or "",
        "log_error": cl.get("error") or "",
        "capture": capture_state(),
    }


