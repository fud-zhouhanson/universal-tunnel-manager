#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""通用隧道管理器 · 运行环境自检

放在解压后的 TunnelManager-Windows-x64 目录里（和 START-双击启动.bat 同级），
双击同目录的「检查运行.bat」即可。也可以在装了 Python 的机器上直接跑：
    python selftest.py

它做三件事：
  1. 只读检查 —— 系统 / 运行时 / 依赖模块 / 系统命令 / 端口 / DNS
  2. 真跑一遍程序 —— 加载 app/tunnel-manager.py，调用它自己的 do_scan()，
     不启动网页服务、不打开浏览器
  3. 把结论写成「检查报告.txt」，直接发回即可

安全声明：本脚本是**只读**的。不改路由、不动 DNS、不装任何东西、不写系统目录。
唯一的写入是脚本目录下的「检查报告.txt」和几个用完就删的临时文件。
"""

import base64
import hashlib
import importlib.util
import os
import platform
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPORT = os.path.join(HERE, "检查报告.txt")


def find_app():
    r"""找到程序主体 tunnel-manager.py。

    它在两个平台上的落点不一样，所以两边都要找：
      · Windows 免安装包：<本目录>/app/tunnel-manager.py
      · macOS 安装之后：  <本目录>/tunnel-manager.py
    找不到时返回第一个候选，好让报错信息里显示的是"期望的位置"。
    """
    candidates = [
        os.path.join(HERE, "app", "tunnel-manager.py"),
        os.path.join(HERE, "tunnel-manager.py"),
    ]
    for p in candidates:
        if os.path.isfile(p):
            return p
    return candidates[0]


APP = find_app()
IS_WIN = platform.system() == "Windows"
NO_WINDOW = 0x08000000 if IS_WIN else 0     # CREATE_NO_WINDOW，避免弹黑框

# 记录原始的 stdout 编码 —— 这是我们要诊断的东西，改之前先记下来
ORIG_STDOUT_ENC = getattr(sys.stdout, "encoding", None)

# 所有输出先进缓冲，最后一次性写文件 + 打印
OUT = []                # 报告行
R = []                  # (level, name, detail)


def rec(level, name, detail=""):
    R.append((level, name, detail))


def ok(n, d=""):    rec("PASS", n, d)
def warn(n, d=""):  rec("WARN", n, d)
def fail(n, d=""):  rec("FAIL", n, d)
def info(n, d=""):  rec("INFO", n, d)
def skip(n, d=""):  rec("SKIP", n, d)
def sec(t):         rec("SEC", t, "")


# ----------------------------------------------------------------------
# 工具
# ----------------------------------------------------------------------
def _dec(b):
    """命令输出解码：中文 Windows 是 GBK，英文版可能是 cp1252，逐个试。"""
    if not b:
        return ""
    for enc in ("utf-8", "gbk", "latin-1"):
        try:
            return b.decode(enc)
        except UnicodeDecodeError:
            continue
    return b.decode("latin-1", "replace")


def sh(cmd, timeout=25):
    """跑条命令 → (returncode | None, 文本)。只读命令，不会改系统。"""
    try:
        p = subprocess.run(cmd, capture_output=True,
                           creationflags=NO_WINDOW, timeout=timeout)
    except subprocess.TimeoutExpired:
        return None, "（超时 %ss）" % timeout
    except OSError as e:
        return None, "无法执行：%s" % e
    txt = _dec(p.stdout)
    err = _dec(p.stderr)
    if err.strip():
        txt = (txt + "\n" + err) if txt.strip() else err
    return p.returncode, txt.strip()


def call_timeout(fn, timeout, *a, **kw):
    """带超时地调用一个函数（Windows 没有 SIGALRM，用线程实现）。"""
    box = {}

    def runner():
        try:
            box["r"] = fn(*a, **kw)
        except BaseException as e:      # noqa: BLE001
            box["e"] = e

    t = threading.Thread(target=runner, daemon=True)
    t.start()
    t.join(timeout)
    if t.is_alive():
        return None, "超时（%ds 未返回）" % timeout
    if "e" in box:
        return None, box["e"]
    return box.get("r"), None


# ----------------------------------------------------------------------
# 一、系统与当前进程
# ----------------------------------------------------------------------
def check_system():
    sec("一、系统与当前进程")
    info("时间", time.strftime("%Y-%m-%d %H:%M:%S"))
    info("主机名 / 用户", "%s / %s" % (
        platform.node(),
        os.environ.get("USERNAME") or os.environ.get("USER") or "?"))
    info("系统", "%s %s" % (platform.system(), platform.release()))
    info("版本号", platform.version())
    machine = platform.machine() or "?"
    info("CPU 架构", machine)

    if platform.system() == "Darwin":
        macver = platform.mac_ver()[0]
        rc, out = sh(["sw_vers", "-buildVersion"], timeout=10)
        build = (out or "").strip()
        ok("macOS 版本", "%s%s" % (macver or "?", (" (build %s)" % build) if build else ""))
        if machine.lower() in ("arm64", "aarch64"):
            info("芯片", "Apple Silicon（原生 arm64）")
        elif machine.lower() in ("x86_64", "amd64"):
            info("芯片", "Intel")

    bits = struct.calcsize("P") * 8
    if IS_WIN:
        if bits == 64:
            ok("解释器位数", "64 位（与包内 amd64 运行时匹配）")
        else:
            warn("解释器位数",
                 "%d 位 —— 你正用 32 位 Python 跑这个检查；包内运行时是 64 位的，"
                 "正式启动请用 START-双击启动.bat（不要用系统的 python）" % bits)
        machine_u = machine.upper()
        if "ARM" in machine_u or "AARCH" in machine_u:
            warn("CPU 架构",
                 "ARM 架构 —— 本包内置的是 amd64 版 Python，在 ARM Windows 上靠 x64 "
                 "模拟运行，能用但可能偏慢；需要原生 ARM 版请反馈")
    else:
        info("解释器位数", "%d 位" % bits)

    if IS_WIN:
        try:
            import ctypes
            admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:               # noqa: BLE001
            admin = None
        if admin is True:
            ok("管理员权限", "有 —— 改路由的操作不会弹 UAC")
        elif admin is False:
            warn("管理员权限", "没有 —— 这是正常的。「切到直连 / 交回隧道 / 应急恢复」"
                               "这类要改路由的操作会弹 UAC 让你输密码，不是故障")
        else:
            warn("管理员权限", "无法判定")

        rc, out = sh(["chcp"], timeout=10)
        info("控制台代码页", (out or "?").strip())
    else:
        skip("管理员权限 / 代码页", "只有 Windows 需要看这两项，macOS 上不适用")


# ----------------------------------------------------------------------
# 二、中文输出与编码（最容易出问题的一项）
# ----------------------------------------------------------------------
def check_encoding():
    sec("二、中文输出与编码")
    enc = ORIG_STDOUT_ENC or "?"
    info("stdout 原始编码", str(enc))

    sample = "中文测试：你好世界 · 箭头 → ⇄ ↩ · 标记 ✓ ✗ ⚠"
    # 只做能力检测，不靠 print —— 避免检测动作本身把脚本搞崩
    try:
        sample.encode(enc if enc and enc != "?" else "ascii")
        ok("当前编码支持中文", "可以（程序里的中文提示不会出问题）")
    except (UnicodeEncodeError, LookupError):
        fail("当前编码支持中文",
             "不支持 —— 输出中文会抛 UnicodeEncodeError。"
             "这正是启动脚本必须带 -X utf8 的原因；"
             "如果你是用「检查运行.bat」双击的，请把这一条发回来看")

    # 文件读写（报告本身以及程序写日志都依赖这个）
    try:
        p = os.path.join(tempfile.gettempdir(), "tm_enc_test.tmp")
        with open(p, "w", encoding="utf-8") as f:
            f.write(sample)
        with open(p, encoding="utf-8") as f:
            back = f.read()
        os.remove(p)
        if back == sample:
            ok("UTF-8 文件读写", "正常")
        else:
            warn("UTF-8 文件读写", "读回内容与写入不一致")
    except OSError as e:
        fail("UTF-8 文件读写", str(e))


# ----------------------------------------------------------------------
# 三、Python 运行时与依赖模块
# ----------------------------------------------------------------------
def check_runtime():
    sec("三、Python 运行时与依赖模块")
    ex = os.path.abspath(sys.executable)
    info("解释器", ex)
    inside = os.path.normcase(ex).startswith(os.path.normcase(os.path.abspath(HERE) + os.sep))
    if inside:
        ok("解释器来源", "来自本包内置的 runtime（对方机器不需要装 Python）")
    else:
        info("解释器来源", "系统里装的 Python，不是包内 runtime")
    info("版本", sys.version.split()[0])

    mods = ["base64", "hashlib", "json", "os", "platform", "re", "secrets", "shutil",
            "socket", "sqlite3", "struct", "subprocess", "ssl", "tempfile",
            "threading", "time", "urllib.parse", "webbrowser", "http.server",
            "ctypes", "encodings.gbk"]
    bad = []
    for m in mods:
        try:
            __import__(m)
        except Exception as e:          # noqa: BLE001
            bad.append("%s(%s)" % (m, e))
    if bad:
        fail("依赖模块", "导入失败： " + "、".join(bad))
    else:
        ok("依赖模块", "%d 个全部可用（含 sqlite3 / ssl / socket / http.server）" % len(mods))


# ----------------------------------------------------------------------
# 四、程序文件
# ----------------------------------------------------------------------
def check_files():
    sec("四、程序文件")
    if not os.path.isfile(APP):
        fail("程序主体 tunnel-manager.py",
             "找不到。请把 selftest.py 和启动器**放在程序所在的目录里**：\n"
             "  · Windows 免安装包 → 解压后的 TunnelManager-Windows-x64 目录"
             "（和 START-双击启动.bat 同级）\n"
             "  · macOS 装完之后   → ~/.tunnel-manager 目录")
        return
    raw = open(APP, "rb").read()
    rel = os.path.relpath(APP, HERE)
    ok("程序主体 " + (rel if not rel.startswith("..") else APP), "%d 字节" % len(raw))
    info("sha256", hashlib.sha256(raw).hexdigest())

    try:
        import re as _re
        txt = raw.decode("utf-8", "replace")
        m = _re.search(
            r'EMBEDDED_HTML\s*=\s*__import__\("base64"\)\.b64decode\("([A-Za-z0-9+/=]+)"\)',
            txt)
        if m:
            html = base64.b64decode(m.group(1))
            ok("内嵌的前端页面", "%d 字节" % len(html))
        else:
            fail("内嵌的前端页面", "没找到内嵌的 HTML —— 文件可能损坏或不完整")
    except Exception as e:              # noqa: BLE001
        fail("内嵌的前端页面", str(e))

    try:
        import py_compile
        cfile = os.path.join(tempfile.gettempdir(), "tm_syntax_check.pyc")
        py_compile.compile(APP, cfile=cfile, doraise=True)
        try:
            os.remove(cfile)
        except OSError:
            pass
        ok("语法编译检查", "通过")
    except Exception as e:              # noqa: BLE001
        fail("语法编译检查", str(e))


# ----------------------------------------------------------------------
# 五、系统命令（程序靠这些读路由 / 网卡 / 进程 —— 两个平台各查各的）
# ----------------------------------------------------------------------
# macOS：下面这些是 server.py 真在用的（读路由、读网卡、认隧道客户端、第一跳探测）
MAC_CMDS = [
    ("route -n get default（默认路由）", ["route", "-n", "get", "default"], 20),
    ("netstat -rn（路由表）", ["netstat", "-rn"], 30),
    ("ifconfig（网卡列表）", ["ifconfig"], 20),
    ("arp -an（邻居表）", ["arp", "-an"], 20),
    ("networksetup（改 DNS 要用）", ["networksetup", "-listallnetworkservices"], 25),
    ("scutil --dns（DNS 配置）", ["scutil", "--dns"], 20),
    ("lsof（进程与连接的映射）", ["lsof", "-nP", "-iTCP", "-sTCP:LISTEN"], 30),
    ("ps（进程列表）", ["ps", "-Ao", "pid,comm"], 20),
]


def _cmd_result(label, rc, out):
    """统一判定一条只读命令的结果。

    注意：**返回码为 0 就算可用**，哪怕这次没有输出 ——
    `arp -an` 在 ARP 缓存为空时就是完全没有输出，那不是故障。
    （这条是实测踩出来的：最初写成 `rc == 0 and out.strip()`，把空输出误判成了失败。）
    """
    if rc is None:
        fail(label, out)
    elif rc == 0:
        n = len((out or "").splitlines())
        ok(label, ("可用（输出 %d 行）" % n) if n else "可用（本次输出为空，属正常）")
    else:
        fail(label, "返回码 %s；%s" % (rc, (out or "").strip()[:140]))


def check_cmds():
    sec("五、系统命令可用性")
    sysname = platform.system()

    if sysname == "Windows":
        for label, cmd, tmo in (
                ("route print（读路由表）", ["route", "print"], 30),
                ("ipconfig（读网卡）", ["ipconfig"], 30),
                ("arp -a（读邻居表）", ["arp", "-a"], 25)):
            rc, out = sh(cmd, timeout=tmo)
            _cmd_result(label, rc, out)
        rc, out = sh(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command",
                      "Get-NetRoute -AddressFamily IPv4 | Select-Object -First 3 | "
                      "Format-Table -AutoSize | Out-String -Width 200"], timeout=45)
        if rc == 0 and (out or "").strip():
            ok("powershell Get-NetRoute", "可用（默认路由的读取走它）")
        else:
            warn("powershell Get-NetRoute",
                 "返回码 %s；%s" % (rc, (out or "").strip()[:160]))
        return

    if sysname == "Darwin":
        for label, cmd, tmo in MAC_CMDS:
            rc, out = sh(cmd, timeout=tmo)
            _cmd_result(label, rc, out)

        # 「真实流量体检」的第一跳判定靠 ping -m 1：macOS 的 ping 是 setuid 的，
        # 普通用户就能跑；而 traceroute 在受限环境下常被拒（实测本机就是）。
        # 这条不通的话，体检功能会退化成拿不到第一跳。
        rc, out = sh(["ping", "-c", "1", "-m", "1", "-W", "1500", "8.8.8.8"], timeout=15)
        if "Time to live exceeded" in (out or ""):
            ok("ping -m 1（第一跳探测）", "可用 —— 「真实流量体检」的第一跳判定靠它")
        elif rc == 0:
            warn("ping -m 1（第一跳探测）",
                 "命令能跑，但没拿到 TTL 超时回复；体检里「第一跳」可能显示为空")
        else:
            fail("ping -m 1（第一跳探测）",
                 "不可用：%s" % (out or "").strip()[:160])

        # 改路由表要 root。这里只探测 sudo 是否免密（-n = 绝不提示输入），
        # 不会真的执行任何特权命令，也不会弹密码框。
        rc, _out = sh(["sudo", "-n", "true"], timeout=10)
        if rc == 0:
            ok("sudo", "可免密 —— 改路由的操作不会弹密码框")
        else:
            info("sudo", "需要密码（这是正常的）：切到直连 / 应急恢复时会弹框要开机密码")
        return

    skip("系统命令", "非 macOS / Windows，跳过")


# ----------------------------------------------------------------------
# 六、端口
# ----------------------------------------------------------------------
def check_ports():
    sec("六、端口占用")
    free_any = False
    for port in (7531, 7532, 7533, 7530, 7800):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("127.0.0.1", port))
            free = True
        except OSError:
            free = False
        finally:
            s.close()
        if free:
            ok("端口 %d" % port, "空闲")
            free_any = True
        else:
            warn("端口 %d" % port, "被占用（程序会自动往后找，不一定是问题）")
    if free_any:
        ok("端口可用性", "至少有一个空闲端口，程序能启动")
    else:
        fail("端口可用性", "7531/7532/7533/7530/7800 全部被占用 —— 程序会启动失败")


# ----------------------------------------------------------------------
# 七、内置网页服务能力
# ----------------------------------------------------------------------
def check_httpserver():
    sec("七、内置网页服务能力")
    try:
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

        class _H(BaseHTTPRequestHandler):
            def log_message(self, *a):      # 静音
                pass

        srv = ThreadingHTTPServer(("127.0.0.1", 0), _H)
        port = srv.server_address[1]
        srv.server_close()
        ok("HTTP 服务", "能绑定回环地址（试绑 :%d 成功）" % port)
    except Exception as e:                  # noqa: BLE001
        fail("HTTP 服务", "%s: %s" % (type(e).__name__, e))


# ----------------------------------------------------------------------
# 八、DNS 解析
# ----------------------------------------------------------------------
def check_dns():
    sec("八、DNS 解析能力")
    for dom in ("www.baidu.com", "www.qq.com"):
        try:
            ips = sorted({i[4][0] for i in socket.getaddrinfo(dom, None, socket.AF_INET)})
            ok("解析 " + dom, "、".join(ips[:3]) if ips else "（没有 A 记录）")
        except Exception as e:              # noqa: BLE001
            fail("解析 " + dom, "%s: %s" % (type(e).__name__, e))


# ----------------------------------------------------------------------
# 九、真跑一遍程序
# ----------------------------------------------------------------------
def check_app_real():
    sec("九、真跑一遍程序（加载它自己的代码并调用扫描）")
    if not os.path.isfile(APP):
        skip("加载程序", "app/tunnel-manager.py 不存在")
        return

    try:
        spec = importlib.util.spec_from_file_location("tm_selftest_app", APP)
        mod = importlib.util.module_from_spec(spec)
        sys.modules["tm_selftest_app"] = mod
        t0 = time.time()
        # 注意：顶层只在 __name__ == "__main__" 时才 main()，这里不会启动服务、不弹浏览器
        spec.loader.exec_module(mod)
        ok("加载模块", "成功（%.2fs）" % (time.time() - t0))
    except Exception as e:                  # noqa: BLE001
        import traceback
        fail("加载模块", "%s: %s" % (type(e).__name__, e))
        info("  堆栈", traceback.format_exc(limit=4).replace("\n", " | "))
        return

    if not hasattr(mod, "do_scan"):
        fail("扫描函数", "模块里找不到 do_scan()")
        return

    t0 = time.time()
    res, err = call_timeout(mod.do_scan, 120)
    dt = time.time() - t0
    if err is not None:
        fail("调用 do_scan()", "%s（耗时 %.1fs）" % (err, dt))
        return
    if not isinstance(res, dict):
        fail("调用 do_scan()", "返回了意外类型：%r" % type(res))
        return
    if res.get("error"):
        fail("调用 do_scan()", "返回错误：%s（耗时 %.1fs）" % (res.get("error"), dt))
        return

    ok("调用 do_scan()", "成功（耗时 %.1fs）" % dt)
    info("  platform", str(res.get("platform")))
    info("  mode", str(res.get("mode")))
    info("  物理出口 / 默认路由", "%s / %s" % (res.get("phys_iface") or "?",
                                              res.get("default_iface") or "?"))

    ifs = res.get("interfaces") or []
    ok("扫描到网络接口", "%d 个" % len(ifs))
    for i in ifs[:8]:
        info("    · %s" % (i.get("name") or "?"),
             "%s / %s / %s" % (i.get("kind") or "-", i.get("owner") or "-",
                               i.get("ipv4") or "-"))
    if len(ifs) > 8:
        info("    …", "另有 %d 个" % (len(ifs) - 8))

    outs = res.get("outlets") or []
    if outs:
        ok("扫描到可管理出口", "%d 个：%s" % (len(outs),
            "、".join(str(o.get("name") or "?") for o in outs)))
        for o in outs[:6]:
            info("    · %s" % (o.get("name") or "?"),
                 "类别=%s 在用=%s 运行中=%s" % (o.get("cat") or "-",
                                              o.get("in_use"), o.get("running")))
    else:
        warn("扫描到可管理出口", "0 个 —— 这台机器上没检测到已知的隧道/加速器客户端，"
                                 "程序仍能运行，但「切换出口」没有对象")

    doms = res.get("domains") or []
    info("域名路由表", "%d 个域名" % len(doms))
    for d in doms[:3]:
        ips = d.get("ips") or []
        info("    · %s" % (d.get("domain") or "?"),
             "%d 个 IP，首个走 %s" % (len(ips), (ips[0].get("iface") if ips else "?")))

    if res.get("egress_truth"):
        bad = [x for x in res["egress_truth"] if x.get("mismatch")]
        if bad:
            warn("路由表 vs 实测出口", "%d 个探测点不一致（可能是隧道客户端造成的，不一定是故障）"
                 % len(bad))
        else:
            ok("路由表 vs 实测出口", "一致")


# ----------------------------------------------------------------------
# 十、客户端进程
# ----------------------------------------------------------------------
def check_clients():
    sec("十、检测到的隧道 / 加速器客户端进程")
    if not IS_WIN:
        skip("客户端进程", "macOS 上不单独列：第九段真跑 do_scan() 时已经报告了"
                          "扫描到的可管理出口，那比单纯列进程更准")
        return
    rc, out = sh(["tasklist", "/fo", "csv", "/nh"], timeout=35)
    if rc != 0 or not out.strip():
        warn("tasklist", "拿不到进程列表（返回码 %s）" % rc)
        return
    low = out.lower()
    groups = {
        "aTrust（深信服）": ["atrust"],
        "深信服 EasyConnect": ["easyconnect", "sangforcsclient"],
        "雷神加速器": ["leigod"],
        "网易UU加速器": ["uu.exe", "uuaccel", "neteaseuu"],
        "Clash / sing-box / v2ray 类": ["clash", "sing-box", "v2ray", "xray", "verge"],
        "ZeroTier": ["zerotier"],
        "Tailscale": ["tailscale"],
        "OpenVPN": ["openvpn"],
        "WireGuard": ["wireguard"],
    }
    hits = [n for n, pats in groups.items() if any(p in low for p in pats)]
    if hits:
        ok("正在运行的客户端", "、".join(hits))
    else:
        info("正在运行的客户端", "没检测到已知的隧道客户端")


# ----------------------------------------------------------------------
# 汇总输出
# ----------------------------------------------------------------------
def render():
    counts = {"PASS": 0, "WARN": 0, "FAIL": 0, "SKIP": 0, "INFO": 0, "SEC": 0}
    for lv, _n, _d in R:
        counts[lv] = counts.get(lv, 0) + 1

    W = 24          # 名字列的显示宽度（东亚字符按 2 列算，否则中文会把对齐挤歪）

    def _pad(s, w):
        import unicodedata
        wid = sum(2 if unicodedata.east_asian_width(c) in "WF" else 1 for c in s)
        return s + " " * max(1, w - wid)

    out = []
    out.append("=" * 70)
    out.append("  通用隧道管理器 · 运行环境自检报告")
    out.append("=" * 70)
    out.append("生成时间：%s" % time.strftime("%Y-%m-%d %H:%M:%S"))
    out.append("主机：%s    系统：%s %s    Python：%s"
               % (platform.node(), platform.system(), platform.release(),
                  sys.version.split()[0]))
    out.append("被检查的程序：%s" % APP)
    out.append("-" * 70)

    for lv, name, detail in R:
        if lv == "SEC":
            out.append("")
            out.append("【%s】" % name)
            continue
        tag = {"PASS": "[通过]", "WARN": "[注意]", "FAIL": "[失败]",
               "INFO": "[信息]", "SKIP": "[跳过]"}.get(lv, lv)
        if detail:
            # 多行详情缩进对齐（与名字列对齐）
            parts = str(detail).split("\n")
            out.append("  %s %s%s" % (tag, _pad(name, W), parts[0]))
            for p in parts[1:]:
                out.append(" " * (2 + 6 + 1 + W) + p)
        else:
            out.append("  %s %s" % (tag, name))

    out.append("")
    out.append("-" * 70)
    out.append("【汇总】")
    out.append("  通过 %d · 注意 %d · 失败 %d · 跳过 %d"
               % (counts["PASS"], counts["WARN"], counts["FAIL"], counts["SKIP"]))

    if counts["FAIL"]:
        verdict = ("结论：发现 %d 个失败项 —— 程序很可能跑不起来或功能不完整。"
                   "请把本报告发回，FAIL 项就是线索。" % counts["FAIL"])
    elif counts["WARN"]:
        verdict = ("结论：程序应该能正常运行，但有 %d 项需要注意（多数是正常的，"
                   "比如没有管理员权限、端口被占）。可以直接试着重启程序。" % counts["WARN"])
    else:
        verdict = "结论：环境完全正常，可以直接双击 START-双击启动.bat 使用。"
    out.append("  " + verdict)
    out.append("")
    out.append("  提示：本报告不含任何隐私信息（只有系统版本、网卡名、路由状态）。")
    out.append("=" * 70)

    text = "\n".join(out)

    # ① 写报告文件（utf-8-sig，记事本能正确打开中文）
    try:
        with open(REPORT, "w", encoding="utf-8-sig", newline="\r\n") as f:
            f.write(text)
        wrote = True
    except OSError as e:
        wrote = False
        err = str(e)

    # ② 打印到屏幕
    try:
        print(text)
    except UnicodeEncodeError:
        # 兜底：编码不支持就直接写字节，保证用户至少能看到东西
        try:
            sys.stdout.buffer.write(text.encode("utf-8", "replace"))
        except Exception:               # noqa: BLE001
            pass

    if wrote:
        print()
        print("  报告已保存：%s" % REPORT)
        print("  请把这个文件发回来。")
    else:
        print()
        print("  [!] 无法写入报告文件：%s" % err)
        print("  请直接把上面的内容复制粘贴发回来。")


def main():
    # 先把 stdout 改成 utf-8 + 容错，保证**脚本自己**不会因为中文崩溃
    # （原始编码已经在 ORIG_STDOUT_ENC 里记下来了，报告里会体现）
    for stream in ("stdout", "stderr"):
        s = getattr(sys, stream, None)
        try:
            if s is not None and hasattr(s, "reconfigure"):
                s.reconfigure(encoding="utf-8", errors="replace")
        except Exception:               # noqa: BLE001
            pass

    for fn in (check_system, check_encoding, check_runtime, check_files,
               check_cmds, check_ports, check_httpserver, check_dns,
               check_app_real, check_clients):
        try:
            fn()
        except BaseException as e:      # noqa: BLE001 —— 单项崩了不能拖垮整份报告
            import traceback
            fail("检查项内部异常（%s）" % fn.__name__,
                 "%s: %s || %s" % (type(e).__name__, e,
                                   traceback.format_exc(limit=3).replace("\n", " | ")))
    render()


if __name__ == "__main__":
    main()
