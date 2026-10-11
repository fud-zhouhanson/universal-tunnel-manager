# -*- coding: utf-8 -*-
"""tunnel_manager.health/rescue_win — 应急恢复 · Windows 分支

由 P2 从 health/flow.py 的第 546–701 行**原样拆出**，正文逐字未改（与 P1 一样，只搬不改）。

【切片规则 —— 这不是漏写 import】
本项目按设计保持**单一扁平命名空间**：
  · 开发期入口 `python -m tunnel_manager.main` → 把所有切片拼进一个命名空间再执行；
  · 构建期 `bundle.py` → 同样顺序拼接成单文件 `dist/tunnel-manager.py`（纯源码，不含 exec）。
所以本文件里可以直接引用其它切片定义的函数与常量，无需 import。跨切片调用是既有事实。
本模块对外提供：（无公开符号）
本模块依赖其它切片：detect/iface、detect/route、health/dns、health/egress、health/probe、health/snapshot、outlet/scene_ops、util、win/outlets、win/probe
"""
>>>SLICE_BODY<<<
def _win_do_rescue():
    """Windows 版应急恢复。

    与 macOS 同一条原则：**只做恢复，不做优化**；每步记 before/after；
    不做不可逆的事。但有三处必须如实区别对待：

      · 默认出口：**不自动改接口跃点数**。Windows 的跃点数是持久化的网络配置，
        乱改会在换网络以后留下后遗症 —— 代价大于收益。这里只报告 + 指路。
      · 残留路由：与 macOS 同口径，只删「指向已消失接口」的条目，绝不动默认路由。
      · DNS：交回 DHCP 自动派生（ResetServerAddresses），并清一次解析缓存。

    ⚠️ 提权走 UAC，**没有密码可输** —— 用户点了「否」我们只能如实说没做完，
    绝不返回 NEED_SUDO 去要密码。
    """
    steps, manual = [], []
    need_admin = False

    snap = load_health() or {}
    phys = snap.get("phys_iface") or ""
    if not phys:
        phys, _gw = phys_iface_guess()
    gw = snap.get("phys_gw") or ""
    if not gw and phys:
        gw = phys_gateway(phys)

    before = {
        "at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "default_route": list(default_route()),
        "dns": system_dns_servers(),
    }

    def add(name, ok, detail):
        steps.append({"name": name, "ok": bool(ok), "detail": detail})

    # 1) 默认出口：只报告，不自动改（见 docstring）
    d_iface, d_gw = before["default_route"]
    if d_iface and is_tunnel_iface(d_iface):
        add("默认出口 → 物理网卡", False,
            "默认路由现在在隧道「%s」上。本工具不自动改接口跃点数"
            "（那是持久化配置，换网络后会留下后遗症）—— "
            "请用上面的「出口管理」把隧道停掉。" % d_iface)
    else:
        add("默认出口 → 物理网卡", True,
            "已在物理口 %s 上，无需改动"
            % ("/".join(x for x in (d_iface, d_gw) if x) or "?"))

    # 2) 残留黑洞路由（指向已消失的接口）
    n, msg = clean_residual_routes()
    if msg == "NEED_SUDO":
        need_admin = True
        add("清理残留黑洞路由", False, "管理员授权被取消")
    else:
        add("清理残留黑洞路由", not msg.startswith("清理未完全成功"), msg)

    # 3) 假 IP 池路由
    fake = fake_pool_routes()
    if not fake:
        add("清除假 IP 池路由", True, "未发现假 IP 池路由")
    else:
        lines = ["$ok=$true"]
        for d in fake:
            s = str(d).replace("'", "''")
            lines.append("try { Remove-NetRoute -DestinationPrefix '%s' "
                         "-Confirm:$false -ErrorAction Stop } catch { $ok=$false; "
                         "Write-Output ('ERR %s: ' + $_.Exception.Message) }"
                         % (s, s))
        lines.append("if ($ok) { Write-Output '__TM_OK__' } "
                     "else { Write-Output '__TM_FAIL__' }")
        ok, text, cancelled = _win_elevated(lines, _cmd_remove_routes(fake))
        if cancelled:
            need_admin = True
            add("清除假 IP 池路由", False, "管理员授权被取消")
        else:
            add("清除假 IP 池路由", ok,
                ("删除 %d 条（%s）" % (len(fake), ", ".join(fake[:5]))) if ok
                else (text[:160] or "未知原因"))

    # 4) DNS：优先恢复保存过的健康基线，否则交回 DHCP
    if not phys:
        add("DNS 恢复", False, "识别不出物理网卡，跳过")
    else:
        saved = load_health()
        base_dns = ipv4_dns_servers((saved or {}).get("dns_now") or [])
        cur = before["dns"]
        if base_dns and set(cur) == set(base_dns):
            add("DNS 恢复", True, "已是 %s，无需改动" % "、".join(cur))
        else:
            alias = str(phys).replace("'", "''")
            arg = ("-ServerAddresses '%s'" % ",".join(base_dns)) if base_dns \
                else "-ResetServerAddresses"
            ok, text, cancelled = _win_elevated([
                "try { Set-DnsClientServerAddress -InterfaceAlias '%s' %s "
                "-ErrorAction Stop; Write-Output '__TM_OK__' } "
                "catch { Write-Output '__TM_FAIL__'; "
                "Write-Output ('ERR ' + $_.Exception.Message) }" % (alias, arg)],
                _cmd_set_dns(phys, base_dns))
            if cancelled:
                need_admin = True
                add("DNS 恢复", False, "管理员授权被取消")
            else:
                after_txt = "、".join(base_dns) if base_dns else "由 DHCP 自动分配"
                add("DNS 恢复", ok,
                    ("%s → %s（%s）" % ("、".join(cur) or "(空)", after_txt,
                                       "恢复到保存的健康基线" if base_dns
                                       else "交回 DHCP 自动分配")) if ok
                    else (text[:160] or "未知原因"))

    # 5) 刷新 DNS 缓存（Windows 上这一步不需要管理员）
    if ps_available()[0]:
        rc, out, err = run_ps("Clear-DnsClientCache; if ($?) { '__TM_OK__' }")
        ok5 = rc == 0 and "__TM_OK__" in (out or "")
        err5 = err
    else:
        rc5, out5, err5 = run(["ipconfig", "/flushdns"], timeout=30)
        ok5 = rc5 == 0
    add("刷新 DNS 缓存", ok5, "已清空解析缓存" if ok5 else (err5 or "清理失败")[:120])

    # 复验
    time.sleep(0.6)
    ok_v, ms_v, _ = tcp_probe("223.5.5.5", 443, timeout=3)
    ips_v, _ms_r, _err = sys_resolve("www.baidu.com")
    verify = {"tcp_ok": ok_v, "tcp_ms": ms_v, "dns_ok": bool(ips_v),
              "dns_ips": ips_v[:3], "phys_iface": phys}
    add("复验", bool(ok_v and ips_v),
        ("能" if ok_v else "不能") + "连通外网（%s ms）；"
        % (ms_v if ms_v is not None else "-")
        + ("DNS 解析成功 " + "、".join(ips_v[:2]) if ips_v else "DNS 解析仍失败"))
    after = {"default_route": list(default_route()), "dns": system_dns_servers()}
    _rescue_log(
        ["=" * 60, "[%s] 应急恢复（Windows）" % before["at"],
         "  before: 默认路由=%s  DNS=%s" % (before["default_route"], before["dns"]),
         "  after : 默认路由=%s  DNS=%s" % (after["default_route"], after["dns"])]
        + ["  %s: %s — %s" % (s["name"], "OK" if s["ok"] else "FAIL", s["detail"])
           for s in steps])

    manual.append("如果隧道客户端还在跑，它可能再次改写 DNS 和路由 —— "
                  "建议在它的界面里停止加速，或用上面的「出口管理」切到「物理直连」。")
    if not verify["dns_ok"]:
        manual.append("DNS 仍解析失败：多半是隧道客户端还在接管，或路由器本身的 DNS 有问题。"
                      "可以试着把 DNS 手动改成 223.5.5.5 / 119.29.29.29。")

    body = {"steps": steps, "manual": manual, "before": before,
            "after": after, "verify": verify}
    if need_admin:
        return {"ok": False,
                "message": "有步骤的「管理员授权」被取消或超时，没做完 —— 可以再点一次",
                "rescue": body}
    ok_all = all(s["ok"] for s in steps)
    return {
        "ok": ok_all,
        "message": ("应急恢复完成，网络已回到本机直连状态"
                    if ok_all else "应急恢复部分完成，请查看下面哪一步失败了"),
        "rescue": body,
    }


