# -*- coding: utf-8 -*-
"""tunnel_manager.steam/sdr — SDR 中继诊断（CM / 中继目标 / CDN）

由 P2 从 steam/diagnose.py 的第 666–832 行**原样拆出**，正文逐字未改（与 P1 一样，只搬不改）。

【切片规则 —— 这不是漏写 import】
本项目按设计保持**单一扁平命名空间**：
  · 开发期入口 `python -m tunnel_manager.main` → 把所有切片拼进一个命名空间再执行；
  · 构建期 `bundle.py` → 同样顺序拼接成单文件 `dist/tunnel-manager.py`（纯源码，不含 exec）。
所以本文件里可以直接引用其它切片定义的函数与常量，无需 import。跨切片调用是既有事实。
本模块对外提供：cm_targets、sdr_relay_targets、steam_cdn_history、steam_cdn_servers、steam_sdr_pops
本模块依赖其它切片：steam/api、steam/paths
"""
>>>SLICE_BODY<<<
def _read_local_sdr():
    """Steam 客户端自己缓存的 appcache/sdr_config.txt —— 离线可用。"""
    p = steam_path("appcache", "sdr_config.txt")
    txt = read_tail(p, 512 * 1024) if p else ""
    if not txt:
        return {}, None
    i = txt.find("{")
    if i < 0:
        return {}, None
    try:
        d = json.loads(txt[i:])
    except ValueError:
        return {}, None
    pops = d.get("pops")
    return (pops if isinstance(pops, dict) else {}), d.get("revision")


def steam_sdr_pops(appid, prefer_online=False):
    """返回 (pops, meta)。

    数据源优先级：本地缓存（快、离线）→ 官方 GetSDRConfig（权威、按 appid）。
    两个都拿不到时如实返回空 + 原因，绝不编造。
    """
    if not prefer_online:
        local, rev = _read_local_sdr()
        if local:
            return local, {"source": "local", "revision": rev, "error": ""}
    d = steam_api_json(
        f"{STEAM_API}/ISteamApps/GetSDRConfig/v1/?appid={appid}&format=json", ttl=1800)
    if isinstance(d, dict) and d.get("pops"):
        return d["pops"], {"source": "online", "revision": d.get("revision"), "error": ""}
    local, rev = _read_local_sdr()          # 在线失败再兜一次本地
    if local:
        return local, {"source": "local", "revision": rev,
                       "error": "官方接口不可达，已降级用本地缓存"}
    return {}, {"source": "", "revision": None,
                "error": "拿不到 SDR 配置（本地缓存缺失，且官方接口不可达）"}


def sdr_relay_targets(pops, limit=24):
    """从 pop 表抽出「优先探测」的中继 IP（近的先来）。"""
    out = []
    order = [k for k in STEAM_NEAR_POPS if k in (pops or {})]
    order += [k for k in sorted(pops or {}) if k not in order]
    for k in order:
        v = pops.get(k) or {}
        for r in (v.get("relays") or []):
            ip = r.get("ipv4")
            if not ip:
                continue
            pr = r.get("port_range") or []
            out.append({
                "pop": k, "pop_cn": STEAM_POP_NAMES.get(k, ""),
                "desc": v.get("desc") or "", "tier": v.get("tier"),
                "ip": ip, "port": (pr[0] if pr else None),
            })
            if len(out) >= limit:
                return out
    return out


def cm_targets(cell_id, limit=10):
    """CM 集群（平台网，登录/好友/商店走的那条）。"""
    url = (f"{STEAM_API}/ISteamDirectory/GetCMListForConnect/v1/"
           f"?cellid={cell_id}&qoslevel=2&format=json")
    d = steam_api_json(url, ttl=900)
    rows = ((d or {}).get("response") or {}).get("serverlist") or []
    best = {}
    for s in rows:
        ep = s.get("endpoint") or ""
        dc = s.get("dc") or ""
        if not ep or not dc:
            continue
        cur = best.get(dc)
        load = s.get("wtd_load") or s.get("load") or 0
        if not cur or load < cur["_load"]:
            host, _, port = ep.partition(":")
            best[dc] = {"dc": dc, "dc_cn": STEAM_POP_NAMES.get(dc, ""),
                        "host": host, "port": port or "443", "_load": load}
    out = sorted(best.values(), key=lambda x: x["_load"])
    for r in out:
        r.pop("_load", None)
    return out[:limit]


# ----------------------------------------------------------------------
# 内容分发网：下载主机 + 连接方式
# ----------------------------------------------------------------------

def steam_cdn_servers(cell_id):
    """官方接口：这个 CellID 下「现在会用」的下载主机。"""
    url = (f"{STEAM_API}/IContentServerDirectoryService/GetServersForSteamPipe/v1/"
           f"?cell_id={cell_id}&max_servers=20&format=json")
    d = steam_api_json(url, ttl=1800)
    out, seen = [], set()
    for s in ((d or {}).get("response") or {}).get("servers") or []:
        h = (s.get("host") or s.get("vhost") or "").strip()
        if h and h not in seen:
            seen.add(h)
            out.append({"host": h, "source": "api", "type": s.get("type") or "",
                        "load": s.get("load"), "wtd_load": s.get("weighted_load"),
                        "client_list": s.get("num_entries_in_client_list")})
    return out


_CDN_HOST_RE = re.compile(r"https?://([a-zA-Z0-9._-]+\.(?:com|net|cn|org))/")


def steam_cdn_history():
    """content_log.txt 里**真的用过**的下载主机 —— 比任何猜测都准。"""
    txt = read_tail(steam_path("logs", "content_log.txt"), 512 * 1024)
    seen = {}
    for m in _CDN_HOST_RE.finditer(txt):
        h = m.group(1).lower()
        seen[h] = seen.get(h, 0) + 1
    return [{"host": h, "hits": n, "source": "history"}
            for h, n in sorted(seen.items(), key=lambda x: -x[1])[:10]]


# ----------------------------------------------------------------------
# 逐进程采样（nettop）—— 真速度只能这么测
# ----------------------------------------------------------------------

_CAP_LOCK = threading.Lock()
_CAP = {
    "running": False, "done": False, "seconds": 0, "elapsed": 0,
    "target": "", "target_kind": "", "pid": "", "samples": [], "frames": 0,
    "peers": [], "error": "", "started_at": 0.0, "finished_at": 0.0,
    "interrupted": False,
}
_CAP_MAX = 300
_CAP_PROC = {"p": None}     # 正在跑的 nettop 进程句柄（capture_stop 用）


def _parse_nettop_line(line):
    """解析 nettop 输出的一行 → (进程名.pid, 四个累计计数)；表头行返回 (None, None)。

    两个实测结论决定了这里的写法：

    1. `nettop` 给的是**累计值**（进程启动以来的总量），所以速率必须靠相邻两帧差分；
    2. `nettop` **单次调用有约 5 秒固定开销**（要重新枚举所有进程）。因此采样绝不能
       「每秒起一个新进程」—— 那样 60 秒的采样会变成五分钟。正确做法是起一个进程，
       用 `-l N -s 1` 让它自己连续采（见 _cap_loop）。

    进程名可能带空格（如 `Steam Helper.1040`），所以从行尾往左取数字，剩下才是名字。
    """
    if not line or line[0] in " \t":
        return None, None           # 表头行 = 新一帧的开始
    parts = line.rstrip().split()
    nums = []
    while parts and re.fullmatch(r"-?\d+", parts[-1]):
        nums.insert(0, int(parts.pop()))
    name = " ".join(parts).strip()
    if not name or not re.search(r"\.\d+$", name):
        return None, None           # 脏行
    return name, {
        "bytes_in": nums[0] if len(nums) > 0 else 0,
        "bytes_out": nums[1] if len(nums) > 1 else 0,
        "rx_ooo": nums[2] if len(nums) > 2 else 0,
        "re_tx": nums[3] if len(nums) > 3 else 0,
    }


def _is_steam_proc(name):
    return "steam" in name.rsplit(".", 1)[0].lower()


