# -*- coding: utf-8 -*-
"""tunnel_manager.steam/capture — Steam 抓包采样与结论判定

由 P2 从 steam/diagnose.py 的第 833–1094 行**原样拆出**，正文逐字未改（与 P1 一样，只搬不改）。

【切片规则 —— 这不是漏写 import】
本项目按设计保持**单一扁平命名空间**：
  · 开发期入口 `python -m tunnel_manager.main` → 把所有切片拼进一个命名空间再执行；
  · 构建期 `bundle.py` → 同样顺序拼接成单文件 `dist/tunnel-manager.py`（纯源码，不含 exec）。
所以本文件里可以直接引用其它切片定义的函数与常量，无需 import。跨切片调用是既有事实。
本模块对外提供：capture_result、capture_start、capture_state、capture_stop、steam_peers
本模块依赖其它切片：_base、consts、outlet/scene_ops、steam/api、steam/sdr
"""
>>>SLICE_BODY<<<
def _cap_pick_target(frame, pid):
    """用第一帧的进程名单决定「看谁」：给定 pid → 正在跑的游戏 → 所有 steam* 进程。"""
    if pid and str(pid).isdigit():
        keys = [k for k in frame if k.endswith(f".{pid}")]
        if keys:
            return "game", keys
    gp = (steam_running_game() or {}).get("pid")
    if gp:
        keys = [k for k in frame if k.endswith(f".{gp}")]
        if keys:
            return "game", keys
    keys = [k for k in frame if _is_steam_proc(k)]
    if keys:
        return "steam", keys
    return "", []


def _cap_append(frame, kind, keys, started_at):
    """把一帧汇总成一条样本（累计值原样存下，差分在 _cap_analyze 里做）。"""
    if kind == "steam":
        keys = [k for k in frame if _is_steam_proc(k)]
    got = {k: frame[k] for k in keys if k in frame}
    agg = {"bi": 0, "bo": 0, "ooo": 0, "rtx": 0}
    for v in got.values():
        agg["bi"] += v["bytes_in"]
        agg["bo"] += v["bytes_out"]
        agg["ooo"] += v["rx_ooo"]
        agg["rtx"] += v["re_tx"]
    with _CAP_LOCK:
        _CAP["samples"].append({
            "t": round(time.time() - started_at, 1), "procs": len(got),
            "bytes_in": agg["bi"], "bytes_out": agg["bo"],
            "rx_ooo": agg["ooo"], "re_tx": agg["rtx"],
            "names": sorted(got)[:6],
        })
        _CAP["elapsed"] = round(time.time() - started_at, 1)
        if not _CAP["target"] and got:
            _CAP["target"] = "、".join(sorted(got))
    return bool(got)


def _cap_loop(seconds, pid):
    keys, kind = [], ""
    proc = None
    try:
        n = max(2, min(_CAP_MAX, int(seconds)) + 1)
        cmd = ["nettop", "-P", "-x", "-l", str(n), "-s", "1",
               "-J", "bytes_in,bytes_out,rx_ooo,re-tx"]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL,
                                text=True, errors="replace")
        _CAP_PROC["p"] = proc
        started_at = _CAP["started_at"] or time.time()
        frame, frames = {}, 0
        for line in proc.stdout:
            name, vals = _parse_nettop_line(line)
            if name is None:
                if frame:
                    frames += 1
                    if not kind:
                        kind, keys = _cap_pick_target(frame, pid)
                        with _CAP_LOCK:
                            _CAP["target_kind"] = kind
                            _CAP["pid"] = (pid or (steam_running_game() or {}).get("pid", ""))
                    _cap_append(frame, kind, keys, started_at)
                frame = {}
                continue
            frame[name] = vals
        if frame:                       # 收尾最后一帧
            frames += 1
            if not kind:
                kind, keys = _cap_pick_target(frame, pid)
                with _CAP_LOCK:
                    _CAP["target_kind"] = kind
            _cap_append(frame, kind, keys, started_at)
        try:
            proc.wait(timeout=5)
        except Exception:               # noqa: BLE001 —— 收尾而已
            pass
        with _CAP_LOCK:
            _CAP["running"] = False
            _CAP["done"] = True
            _CAP["frames"] = frames
            _CAP["finished_at"] = time.time()
        if not frames:
            with _CAP_LOCK:
                _CAP["error"] = "nettop 没有输出任何采样帧（可能被系统权限拦住）"
        _CAP["peers"] = steam_peers(pid, keys)
    except Exception as e:      # noqa: BLE001 —— 采样线程绝不能把服务带崩
        with _CAP_LOCK:
            _CAP["running"] = False
            _CAP["done"] = True
            _CAP["error"] = str(e)
    finally:
        _CAP_PROC["p"] = None
        if proc and proc.poll() is None:
            try:
                proc.terminate()
            except OSError:
                pass


def steam_peers(pid=None, keys=None):
    """目标进程当前的**对端 IP** —— 「实际连的是哪个中继 / 哪个 CDN」的直接证据。"""
    if not IS_MAC:
        return []
    pids = []
    if pid and str(pid).isdigit():
        pids.append(str(pid))
    else:
        gp = (steam_running_game() or {}).get("pid")
        if gp:
            pids.append(gp)
    if not pids:
        for k in (keys or []):
            tail = k.rsplit(".", 1)[-1]
            if tail.isdigit():
                pids.append(tail)
    found = {}
    for p in pids[:4]:
        txt = _sh(f"lsof -nP -i -a -p {p} 2>/dev/null", timeout=10)
        for line in txt.splitlines():
            m = re.search(r"->(\d+\.\d+\.\d+\.\d+):(\d+)", line)
            if not m:
                continue
            ip, port = m.group(1), m.group(2)
            if not is_public_ip(ip):
                continue
            k = f"{ip}:{port}"
            found[k] = found.get(k, 0) + 1
    return [{"peer": k, "hits": v}
            for k, v in sorted(found.items(), key=lambda x: -x[1])[:20]]


def _cap_analyze(samples, peers=None, relays=None):
    """把累计值换算成速率与质量增量，并给出「断续率」。"""
    if len(samples) < 2:
        return {}
    secs, total_in, total_out, missing = [], 0, 0, 0
    for a, b in zip(samples, samples[1:]):
        span = max(0.001, b["t"] - a["t"])
        d_in = b["bytes_in"] - a["bytes_in"]
        if d_in < 0:                # 计数器回绕 / 进程重启
            d_in = b["bytes_in"]
        d_out = b["bytes_out"] - a["bytes_out"]
        if d_out < 0:
            d_out = b["bytes_out"]
        d_ooo = max(0, b["rx_ooo"] - a["rx_ooo"])
        d_rtx = max(0, b["re_tx"] - a["re_tx"])
        if b.get("procs") == 0:
            missing += 1
            continue
        secs.append({"t": b["t"], "in": d_in, "out": d_out,
                     "ooo": d_ooo, "rtx": d_rtx, "s": round(span, 2)})
        total_in += d_in
        total_out += d_out
    span = max(1.0, samples[-1]["t"] - samples[0]["t"])
    zero = sum(1 for s in secs if s["in"] == 0 and s["out"] == 0)

    # 对端 IP → 命中哪个中继
    #
    # 先精确匹配；匹配不到再退一步按 /24 同网段推断。
    # 为什么必须退这一步：本地 SDR 缓存（appcache/sdr_config.txt）是 Steam 上次联网时
    # 写下的，中继 IP **会换号** —— 实测本机缓存里 hkg 是 103.28.54.163/.164/…，
    # 而实时抓到的对端却是 103.28.54.102，同网段但不在旧名单里。
    # 少了这一步，最关键的「实际命中哪个中继」就会长期为空。
    # 推断出来的必须标 match="subnet"，界面上如实说明这是推断而非确证。
    hit, unknown = [], []
    rmap = {r["ip"]: r for r in (relays or [])}
    sub = {}
    for r in (relays or []):
        sub.setdefault(r["ip"].rsplit(".", 1)[0], r)
    for p in (peers or []):
        ip = p["peer"].split(":")[0]
        port = p["peer"].split(":")[-1]
        r = rmap.get(ip)
        match = "exact"
        if not r:
            r = sub.get(ip.rsplit(".", 1)[0])
            match = "subnet" if r else ""
        if r:
            hit.append({"ip": ip, "port": port, "pop": r["pop"],
                        "pop_cn": r.get("pop_cn") or "", "hits": p["hits"],
                        "match": match})
        else:
            unknown.append({"ip": ip, "port": port, "hits": p["hits"]})
    return {
        "span": round(span, 1),
        "samples": len(samples),
        "active_seconds": len(secs),
        "missing_seconds": missing,
        "zero_seconds": zero,
        "zero_ratio": round(zero / len(secs), 3) if secs else None,
        "rate_kbps_in": round(total_in / span * 8 / 1000, 1),
        "rate_kbps_out": round(total_out / span * 8 / 1000, 1),
        "total_in": total_in,
        "rx_ooo_delta": sum(s["ooo"] for s in secs),
        "re_tx_delta": sum(s["rtx"] for s in secs),
        "series": secs,
        "peers": peers or [],
        "hit_relays": hit,
        "unknown_peers": unknown,
    }


def capture_state():
    with _CAP_LOCK:
        st = {"running": _CAP["running"], "done": _CAP["done"],
              "seconds": _CAP["seconds"], "elapsed": _CAP["elapsed"],
              "target": _CAP["target"], "target_kind": _CAP["target_kind"],
              "pid": _CAP["pid"], "samples": len(_CAP["samples"]),
              "frames": _CAP["frames"], "interrupted": _CAP["interrupted"],
              "error": _CAP["error"], "started_at": _CAP["started_at"],
              "finished_at": _CAP["finished_at"]}
        st["progress"] = (round(st["elapsed"] / st["seconds"], 2)
                          if st["seconds"] else 0)
        return st


def capture_start(seconds=60, pid=""):
    with _CAP_LOCK:
        if _CAP["running"]:
            return False, "已经有一次采样在进行中，等它结束或先停止。"
        try:
            secs = int(seconds)
        except (TypeError, ValueError):
            secs = 60
        secs = max(10, min(_CAP_MAX, secs))
        _CAP.update({"running": True, "done": False, "seconds": secs,
                     "elapsed": 0, "samples": [], "frames": 0, "peers": [],
                     "error": "", "interrupted": False, "target": "",
                     "target_kind": "", "pid": str(pid or ""),
                     "started_at": time.time(), "finished_at": 0.0})
    threading.Thread(target=_cap_loop, args=(secs, str(pid or "")),
                     daemon=True).start()
    return True, f"已开始采样（{secs} 秒）。采样期间请保持游戏联机状态。"


def capture_stop():
    with _CAP_LOCK:
        if not _CAP["running"]:
            return False, "当前没有正在进行的采样。"
        _CAP["interrupted"] = True
        _CAP["seconds"] = max(1, int(_CAP["elapsed"] or 1))
    p = _CAP_PROC.get("p")
    if p:
        try:
            p.terminate()          # 真结束 nettop，不等它跑满
        except OSError:
            pass
    return True, "已请求提前结束，正在收尾。"


def capture_result(relays=None):
    st = capture_state()
    with _CAP_LOCK:
        samples = list(_CAP["samples"])
        peers = list(_CAP["peers"])
    st["analysis"] = _cap_analyze(samples, peers, relays)
    return st


