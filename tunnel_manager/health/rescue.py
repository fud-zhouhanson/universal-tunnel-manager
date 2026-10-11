# -*- coding: utf-8 -*-
"""tunnel_manager.health/rescue — 应急恢复 · 跨平台入口

由 P2 从 health/flow.py 的第 702–843 行**原样拆出**，正文逐字未改（与 P1 一样，只搬不改）。

【切片规则 —— 这不是漏写 import】
本项目按设计保持**单一扁平命名空间**：
  · 开发期入口 `python -m tunnel_manager.main` → 把所有切片拼进一个命名空间再执行；
  · 构建期 `bundle.py` → 同样顺序拼接成单文件 `dist/tunnel-manager.py`（纯源码，不含 exec）。
所以本文件里可以直接引用其它切片定义的函数与常量，无需 import。跨切片调用是既有事实。
本模块对外提供：do_rescue
本模块依赖其它切片：_base、detect/route、health/dns、health/probe、health/rescue_win、health/snapshot、outlet/scene_ops、util
"""
>>>SLICE_BODY<<<
def do_rescue(pw=None):
    """一键应急恢复：把路由与 DNS 救回「本机直连」的干净状态。

    设计原则：
      · 只做「恢复」不做「优化」—— 目标是让网络回到能用，不是变快
      · 每步都记 before/after 并落 rescue.log，事后能审计、能对照
      · 不做不可逆的事（不删配置、不动 hosts、不卸软件）
    """
    if IS_WIN:
        return _win_do_rescue()
    if not IS_MAC:
        return {"ok": False, "message": f"暂仅支持 Windows / macOS（当前 {PLATFORM}）"}

    steps, manual = [], []
    need_pw = False

    snap = load_health() or health_snapshot() or {}
    phys = snap.get("phys_iface") or ""
    gw = snap.get("phys_gw") or ""
    svc = snap.get("net_service") or net_service_for_iface(phys)

    before = {
        "at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "default_route": list(default_route_mac()),
        "dns": system_dns_servers(),
    }

    def add(name, ok, detail):
        steps.append({"name": name, "ok": bool(ok), "detail": detail})

    # 1) 默认路由回到物理网关
    d_iface, d_gw = before["default_route"]
    if phys and gw:
        if d_iface == phys and (not d_gw or d_gw == gw):
            add("默认路由 → 物理网关", True, f"已是 {phys} / {gw}，无需改动")
        else:
            rc, _o, _e = run_root(f"route -n change default {gw}", pw)
            if rc == 403:
                need_pw = True
                add("默认路由 → 物理网关", False, "需要管理员密码")
            else:
                add("默认路由 → 物理网关", rc == 0,
                    f"{d_iface or '?'}/{d_gw or '?'} → {phys}/{gw}")
    else:
        add("默认路由 → 物理网关", False, "识别不出物理网卡或网关，跳过")

    # 2) 残留黑洞路由（指向已消失的接口）
    if not need_pw:
        n, msg = clean_residual_routes(pw)
        if msg == "NEED_SUDO":
            need_pw = True
            add("清理残留黑洞路由", False, "需要管理员密码")
        else:
            add("清理残留黑洞路由", True, msg)

    # 3) 假 IP 池路由
    if not need_pw:
        fake = fake_pool_routes()
        if not fake:
            add("清除假 IP 池路由", True, "未发现假 IP 池路由")
        else:
            rc, _o, _e = run_root(" ; ".join(_del_route_cmd(d) for d in fake), pw)
            if rc == 403:
                need_pw = True
                add("清除假 IP 池路由", False, "需要管理员密码")
            else:
                add("清除假 IP 池路由", rc == 0,
                    f"删除 {len(fake)} 条（{', '.join(fake[:5])}）")

    # 4) DNS 恢复
    #    优先恢复到「用户自己存过的健康基线」（尊重他本来就有的自定义 DNS）；
    #    没有基线就设成 Empty —— 即清掉一切自定义，交回 DHCP / 系统自动派生。
    #    不直接把 DNS 写死成路由器 IP：那样换个网络就失效了。
    if not need_pw:
        saved = load_health()
        base_dns = ipv4_dns_servers((saved or {}).get("dns_now") or [])
        cur = before["dns"]
        if base_dns:
            target, why = base_dns, "恢复到保存的健康基线"
        else:
            target, why = ["Empty"], "清掉自定义 DNS，交回 DHCP 自动分配"
        if not svc:
            add("DNS 恢复", False, f"找不到 {phys} 对应的网络服务名，跳过")
        elif cur and base_dns and set(cur) == set(base_dns):
            add("DNS 恢复", True, f"已是 {'、'.join(cur)}，无需改动")
        else:
            rc, _o, _e = run_root(
                f'networksetup -setdnsservers "{svc}" ' + " ".join(target), pw)
            if rc == 403:
                need_pw = True
                add("DNS 恢复", False, "需要管理员密码")
            else:
                after_txt = "、".join(base_dns) if base_dns else "由 DHCP 自动分配"
                add("DNS 恢复", rc == 0,
                    f"{'、'.join(cur) or '(空)'} → {after_txt}（{why}）")

    # 5) 刷新 DNS 缓存
    if not need_pw:
        rc, _o, _e = run_root("dscacheutil -flushcache; killall -HUP mDNSResponder", pw)
        if rc == 403:
            need_pw = True
            add("刷新 DNS 缓存", False, "需要管理员密码")
        else:
            add("刷新 DNS 缓存", rc == 0, "已清空缓存并让 mDNSResponder 重读配置")

    verify = after = None
    if not need_pw:
        time.sleep(0.6)
        ok_v, ms_v, _ = tcp_probe("223.5.5.5", 443, timeout=3)
        ips_v, ms_r, _err = sys_resolve("www.baidu.com")
        verify = {"tcp_ok": ok_v, "tcp_ms": ms_v, "dns_ok": bool(ips_v),
                  "dns_ips": ips_v[:3], "dns_ms": ms_r, "phys_iface": phys}
        add("复验", bool(ok_v and ips_v),
            ("能" if ok_v else "不能") + f"连通外网（{ms_v if ms_v is not None else '-'} ms）；"
            + ("DNS 解析成功 " + "、".join(ips_v[:2]) if ips_v else "DNS 解析仍失败"))
        after = {"default_route": list(default_route_mac()), "dns": system_dns_servers()}
        _rescue_log(
            ["=" * 60, f"[{before['at']}] 应急恢复",
             f"  before: 默认路由={before['default_route']}  DNS={before['dns']}",
             f"  after : 默认路由={after['default_route']}  DNS={after['dns']}"]
            + [f"  {s['name']}: {'OK' if s['ok'] else 'FAIL'} — {s['detail']}" for s in steps])

    manual.append("如果隧道客户端（aTrust / 雷神 / 网易UU 等）还在跑，它可能再次改写 DNS 和路由 —— "
                  "建议在它的界面里停止加速，或用上面的「出口管理」切到「物理直连」。")
    if verify and not verify["dns_ok"]:
        manual.append("DNS 仍解析失败：多半是隧道客户端还在接管，或路由器本身的 DNS 有问题。"
                      "可以试着把 DNS 手动改成 223.5.5.5 / 119.29.29.29。")

    if need_pw:
        return {"ok": False, "error": "NEED_SUDO", "message": "需要管理员密码",
                "rescue": {"steps": steps, "manual": manual, "before": before}}

    ok_all = all(s["ok"] for s in steps)
    return {
        "ok": ok_all,
        "message": ("应急恢复完成，网络已回到本机直连状态"
                    if ok_all else "应急恢复部分完成，请查看下面哪一步失败了"),
        "rescue": {"steps": steps, "manual": manual, "before": before,
                   "after": after, "verify": verify},
    }


