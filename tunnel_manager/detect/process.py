# -*- coding: utf-8 -*-
"""tunnel_manager.detect/process — 进程证据：谁在运行

由 P1 从 server.py 的第 435–470 行**整块搬迁**而来，正文逐字未改。

【切片规则 —— 这不是漏写 import】
本项目按设计保持**单一扁平命名空间**：
  · 开发期入口 `python -m tunnel_manager.main` → 把所有切片拼进一个命名空间再执行；
  · 构建期 `bundle.py` → 同样顺序拼接成单文件 `dist/tunnel-manager.py`（纯源码，不含 exec）。
所以本文件里可以直接引用其它切片定义的函数与常量，无需 import。跨切片调用是既有事实。
本模块对外提供：detect_software、list_processes
本模块依赖其它切片：_base、consts、util、win/native
"""
>>>SLICE_BODY<<<
# ======================================================================
# 三、进程证据：谁在运行
# ======================================================================

def list_processes():
    """返回一个可搜索的进程名/命令行文本（全小写）。"""
    if IS_MAC:
        # ps 可能被沙箱拒，退路 pgrep -fl
        rc, out, _ = run(["ps", "axww", "-o", "command"])
        if rc != 0:
            rc2, out2, _ = run(["ps", "axco", "pid,comm"])
            out = out2 if rc2 == 0 else ""
        return out.lower()
    if IS_WIN:
        if not ps_available()[0]:
            return _nat_processes()          # tasklist /fo csv
        rc, out, _ = run_ps(
            "[Console]::OutputEncoding=[Text.Encoding]::UTF8;"
            "Get-Process | Select-Object -ExpandProperty Name"
        )
        return out.lower()
    rc, out, _ = run(["ps", "auxww"])
    return out.lower()


def detect_software(procs_blob):
    """在进程列表里搜已知隧道软件，返回命中的软件信息列表。"""
    seen = {}
    for sw in TUNNEL_KNOWLEDGE:
        for kw in sw["proc"]:
            if kw.lower() in procs_blob:
                seen.setdefault(sw["name"], sw)
                break
    return list(seen.values())


