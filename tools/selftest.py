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
import json
import os
import platform
import shutil
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

_APP_MOD = {"m": None}


def load_app():
    """加载程序主体（只加载一次，多个检查项共用同一个模块实例）。"""
    if _APP_MOD["m"] is not None:
        return _APP_MOD["m"]
    spec = importlib.util.spec_from_file_location("tm_selftest_app", APP)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["tm_selftest_app"] = mod
    spec.loader.exec_module(mod)
    _APP_MOD["m"] = mod
    return mod


# 第十二段采集到的原始输出 —— 附在报告末尾，用于校准解析器
EXTRA_DUMP = []

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
# macOS：下面这些是程序主体真在用的（读路由、读网卡、认隧道客户端、第一跳探测）
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
                 "返回码 %s；%s —— "
                 "**这不影响使用**：程序会自动改用系统自带的原生命令"
                 "（route / arp / netsh / sc / tasklist），"
                 "是否已成功回退见第十二段「系统查询通道」。"
                 % (rc, (out or "").strip()[:160]))
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
# 十一、出口切换的探测层（Windows）
# ----------------------------------------------------------------------
def check_outlets():
    """真跑一遍「出口切换」的探测层 —— **全程只读**。

    Windows 上「切隧道」要靠三件事，这一段逐项验证它们在这台机器上到底行不行：
      ① 注册表 → 认出装了哪些客户端
      ② SCM    → 认出哪些服务可以停 / 启
      ③ 系统 VPN → 认出可以 rasdial 的连接

    ⚠️ 这一段**不会**停任何服务、**不会**改任何路由、**不会**主动弹 UAC。
    它只回答一个问题：真点「切到这里」时，有多少步骤能自动完成。
    """
    sec("十一、出口切换的探测层（Windows）")
    if not IS_WIN:
        skip("Windows 出口适配",
             "当前不是 Windows，跳过（macOS 走 launchd 那套，见第九段）")
        return
    if not os.path.isfile(APP):
        skip("Windows 出口适配", "app/tunnel-manager.py 不存在")
        return

    try:
        spec = importlib.util.spec_from_file_location("tm_selftest_outlets", APP)
        mod = importlib.util.module_from_spec(spec)
        sys.modules["tm_selftest_outlets"] = mod
        spec.loader.exec_module(mod)
    except Exception as e:                  # noqa: BLE001
        fail("加载模块（出口适配）", "%s: %s" % (type(e).__name__, e))
        return

    # 版本闸门：旧版程序里根本没有这几个函数，直接说清楚，
    # 免得后面抛一堆 AttributeError 让人以为是自己机器的问题。
    if not hasattr(mod, "_win_registry_apps"):
        fail("程序版本",
             "这份 app/tunnel-manager.py 里**没有** Windows 出口适配的代码（是旧版）。"
             "请用同一批下载里的新包重新解压一份再跑。")
        return

    # ① 注册表 → 已安装程序
    apps, err = call_timeout(mod._win_registry_apps, 120)
    if err is not None:
        fail("读注册表（已安装程序）", str(err))
    elif apps:
        ok("读注册表（已安装程序）", "读到 %d 条" % len(apps))
        sample = [a["name"] for a in apps if a.get("name")][:5]
        info("  抽样", "、".join(sample))
    else:
        warn("读注册表（已安装程序）",
             "一条都没读到 —— 客户端会被判成「没安装」，出口列表里就不会出现")

    # ② SCM → 服务
    svcs, err = call_timeout(mod._win_service_list, 120)
    if err is not None:
        fail("枚举 Windows 服务", str(err))
        svcs = None
    elif not svcs:
        warn("枚举 Windows 服务", "一个都没读到 —— 「停止 / 启动」会退化成手动")
    else:
        ok("枚举 Windows 服务", "%d 个" % len(svcs))

    if svcs:
        kws = set()
        for entry in mod.TUNNEL_KNOWLEDGE:
            if entry.get("cat") in mod.OUTLET_CATS:
                kws |= set(mod._kb_keywords(entry))
        hit, err = call_timeout(mod._find_services_win, 60, sorted(kws))
        if err is not None:
            warn("按关键词匹配可停服务", str(err))
        elif hit:
            ok("按关键词匹配可停服务",
               "%d 个：%s" % (len(hit), "、".join(
                   "%s(%s)" % (s["name"], "运行中" if s["running"] else "已停")
                   for s in hit[:6])))
        else:
            info("按关键词匹配可停服务",
                 "0 个 —— 这台机器上没有以「服务」形式存在的隧道客户端。"
                 "加速器类多数只有界面开关，属正常，不影响其它功能")

    # ③ 系统自带 VPN
    vpns, err = call_timeout(mod._win_vpn_list, 90)
    if err is not None:
        warn("读系统 VPN（Get-VpnConnection）", str(err))
    elif vpns:
        ok("读系统 VPN（Get-VpnConnection）",
           "%d 个：%s" % (len(vpns), "、".join(v["name"] for v in vpns[:5])))
    else:
        info("读系统 VPN（Get-VpnConnection）", "没有配置系统自带的 VPN（正常）")

    # ④ 残留路由：**只列不删**
    try:
        valid = mod.active_ifaces()
        stale = sorted({d for d, a in mod._routes_snapshot()
                        if d != "default" and a and a not in valid},
                       key=lambda d: -len(d))
        if stale:
            warn("残留路由预演（只列不删）",
                 "%d 条指向已消失的接口：%s" % (len(stale), "、".join(stale[:6])))
        else:
            ok("残留路由预演（只列不删）", "没有指向已消失接口的路由")
    except Exception as e:                  # noqa: BLE001
        warn("残留路由预演（只列不删）", "%s: %s" % (type(e).__name__, e))

    # ⑤ 提权方式（**不主动触发**，只是说明）
    info("提权方式", "UAC —— 点「停止 / 启动 / 切换」时会弹确认框，点「是」即可。"
                     "本自检不会主动触发它")

    # ⑥ 把将要执行的 PowerShell 片段打印出来，方便人工核对 / 反馈
    try:
        lines = mod._ps_try_lines("Stop-Service -Force", ["__示例服务__"])
        if any("__TM_OK__" in x for x in lines):
            ok("生成提权脚本片段", "已生成（含成败标记）")
            for ln in lines:
                info("    |", ln[:130])
        else:
            fail("生成提权脚本片段", "片段里没有成败标记 —— 判定逻辑会失效")
    except Exception as e:                  # noqa: BLE001
        fail("生成提权脚本片段", "%s: %s" % (type(e).__name__, e))


# ----------------------------------------------------------------------
# 汇总输出
# ----------------------------------------------------------------------
def check_rules():
    """十三、判定规则的「表格与边界」自检。

    这一段守的是**看不见的退化**：程序里有两张表，一旦被改坏，
    界面不会报错、只是悄悄少管一块公网或少查一类故障 —— 不写断言根本发现不了。

      · 聚合路由抽查表 PROBE_TARGETS —— aTrust/雷神这类客户端不动默认路由，
        靠「1/2/4/8…」拆分整段公网来接管的。表里少掉一整段，
        就等于那一整块公网失去监控。
      · 假 IP 池规则 —— 隧道把域名解析进 198.18.x.x 之类假 IP 的证据链。
        这里曾经写成一个**永远匹配不上任何真实 IP** 的正则（结尾的 `$` 紧跟在
        点号后面），检测一直是哑的，所以现在把边界钉在断言里。

    另外顺带验证两件「防误伤」的事：
      · launchd 标签 / plist 路径要拼进 root shell，白名单必须挡住注入；
      · save_config 是读-改-写，不能把配置里其它键冲掉。

    全程只读；唯一写操作在临时目录里，用完即删。
    """
    sec("十三、判定规则与边界（聚合抽查表 / 假 IP 池 / 提权探测）")
    if not os.path.isfile(APP):
        skip("判定规则", "app/tunnel-manager.py 不存在")
        return
    try:
        mod = load_app()
    except Exception as e:                  # noqa: BLE001
        fail("加载模块（判定规则）", "%s: %s" % (type(e).__name__, e))
        return

    # ---- 1. 聚合路由抽查表 ----
    targets = getattr(mod, "PROBE_TARGETS", None)
    if not isinstance(targets, (list, tuple)) or not targets:
        fail("聚合路由抽查表", "程序里找不到 PROBE_TARGETS —— 这份包太旧，请用同一批下载里的新包")
    else:
        bad = [str(t) for t in targets
               if not isinstance(t, str) or mod.ip_to_int(t) is None]
        if bad:
            fail("抽查点是合法 IPv4", "这些不是：%s" % "、".join(bad))
        elif len(set(targets)) != len(targets):
            fail("抽查点无重复", "有重复项：%d 个点里只有 %d 个不同"
                 % (len(targets), len(set(targets))))
        else:
            ok("抽查点是合法 IPv4 且无重复", "%d 个探测点" % len(targets))

        try:
            first = [int(str(t).split(".")[0]) for t in targets]
            segs = [
                ("0.0.0.0/1（0–127）", sum(1 for o in first if o < 128)),
                ("128.0.0.0/2（128–191）", sum(1 for o in first if 128 <= o < 192)),
                ("192.0.0.0/3（192–223）", sum(1 for o in first if 192 <= o < 224)),
                ("240.0.0.0/4（240–255）", sum(1 for o in first if o >= 240)),
            ]
            empty = [n for n, c in segs if c == 0]
            blocks = len({o >> 4 for o in first})
            if empty:
                fail("聚合路由段覆盖完整",
                     "这些段一个探测点都没有：%s —— "
                     "等于那一整块公网不会被抽查到" % "、".join(empty))
            elif blocks < 10:
                fail("聚合路由段覆盖足够散", "只覆盖了 %d 个 /4 块（应 ≥10）" % blocks)
            else:
                ok("聚合路由段覆盖完整",
                   "四个聚合段都有点（%s），散布在 %d 个 /4 块里"
                   % ("、".join("%s×%d" % (n.split("（")[0], c) for n, c in segs), blocks))
            multicast = sum(1 for o in first if 224 <= o < 240)
            if multicast:
                warn("组播段 224.0.0.0/4", "有 %d 个探测点落在组播段 —— "
                     "客户端不会接管组播，这些点探不出东西" % multicast)
            else:
                info("组播段 224.0.0.0/4", "按设计不设点（客户端不接管组播）")
        except Exception as e:              # noqa: BLE001
            fail("聚合路由段覆盖核算", "%s: %s" % (type(e).__name__, e))

    # ---- 2. 假 IP 池规则 ----
    host_re, net_re = getattr(mod, "is_fake_pool_host", None), getattr(mod, "is_fake_pool_net", None)
    if not host_re or not net_re:
        fail("假 IP 池规则", "程序里找不到 is_fake_pool_host / is_fake_pool_net —— 这份包太旧")
    else:
        # (地址, 期望) —— 左边是隧道惯用的假 IP 池，右边是真公网，必须放过
        host_cases = [
            ("198.18.3.5", True), ("198.19.255.1", True), ("100.64.1.1", True),
            ("240.0.0.7", True), ("127.0.0.1", True), ("169.254.1.1", True),
            ("8.8.8.8", False), ("1.1.1.1", False), ("100.130.1.1", False),
            ("198.20.1.1", False),
        ]
        wrong = [(ip, mod.is_fake_pool_host(ip), want)
                 for ip, want in host_cases if mod.is_fake_pool_host(ip) != want]
        if wrong:
            fail("假 IP 池（域名解析侧）",
                 "判定不对：%s；" % "、".join(
                     "%s 得到 %s 应为 %s" % w for w in wrong) +
                 "注：这一项过去因为正则写错而**从不命中**，"
                 "若这里报错说明规则被改坏了。")
        else:
            ok("假 IP 池（域名解析侧）", "%d 个边界判定全对" % len(host_cases))

        # net 侧刻意收窄：宁可漏判，也绝不能删 169.254/16 这类合法链路本地路由
        net_cases = [("198.18.0.0", True), ("100.64.0.0", True), ("240.0.0.0", True),
                     ("169.254.0.0", False), ("100.70.0.0", False),
                     ("8.8.8.0", False), ("0.0.0.0", False)]
        wrong = [(d, mod.is_fake_pool_net(d), want)
                 for d, want in net_cases if mod.is_fake_pool_net(d) != want]
        if wrong:
            fail("假 IP 池（路由侧，刻意收窄）",
                 "判定不对：%s" % "、".join("%s 得到 %s 应为 %s" % w for w in wrong))
        else:
            ok("假 IP 池（路由侧，刻意收窄）",
               "%d 个边界判定全对（169.254 / 100.70+ 都放过，不会误删合法路由）"
               % len(net_cases))

    # ---- 3. launchd 标签白名单（拼进 root shell 前的注入防线）----
    safe_fn = getattr(mod, "_safe_launchd_tokens", None)
    if not safe_fn:
        info("launchd 标签白名单", "这份包里还没有这个函数（旧版），跳过")
    else:
        good = ["system/com.sangfor.aTrustTunnel",
                "/Library/LaunchDaemons/com.sangfor.aTrustTunnel.plist"]
        evil = ["com.x; rm -rf /", "a$(whoami)b", "a`id`b", "a&b", "a>b",
                "com x y", "-flag", "a'b"]
        missed = [t for t in evil if safe_fn([t])]
        broke = [t for t in good if not safe_fn([t])]
        if missed:
            fail("launchd 标签白名单", "这些可疑串**没被拦住**：%s"
                 % "、".join(repr(t) for t in missed))
        elif broke:
            fail("launchd 标签白名单", "这些正常标签被误拦：%s"
                 % "、".join(repr(t) for t in broke))
        else:
            ok("launchd 标签白名单",
               "%d 个可疑串全被拦、%d 个正常标签放行" % (len(evil), len(good)))

    # ---- 4. 提权探测 ----
    try:
        st = mod.priv_status()
    except Exception as e:                  # noqa: BLE001
        st = None
        fail("提权能力探测", "%s: %s" % (type(e).__name__, e))
    if isinstance(st, dict):
        missing = [k for k in ("can_elevate", "code", "text") if k not in st]
        if missing:
            fail("提权能力探测", "缺字段：%s" % "、".join(missing))
        elif st.get("can_elevate"):
            ok("提权能力探测", "当前**有**管理员权限（改路由 / 启停隧道不会弹密码框）")
        elif st.get("code") in ("NEED_SUDO", "NEED_ADMIN"):
            info("提权能力探测",
                 "当前为只读：%s（这是正常的，点「切到本机直连」时才会要授权；"
                 "程序会在动手前先探测，不会做一半失败）" % (st.get("text") or st.get("code")))
        else:
            fail("提权能力探测", "can_elevate=False 却没给出哨兵码：%r" % st)

    # ---- 5. save_config 是读-改-写（不能把配置里其它键冲掉）----
    saved = (getattr(mod, "CONFIG_DIR", None), getattr(mod, "CONFIG_FILE", None))
    tmpdir = None
    try:
        tmpdir = tempfile.mkdtemp(prefix="tm_selftest_cfg_")
        mod.CONFIG_DIR = tmpdir
        mod.CONFIG_FILE = os.path.join(tmpdir, "config.json")
        with open(mod.CONFIG_FILE, "w", encoding="utf-8") as f:
            f.write('{"domains": ["keep.example"], '
                    '"fake_ip_pools": {"host": ["9\\\\.9\\\\."]}, "misc": 42}')
        mod.save_config(["b.example", "B.example", "  c.example  "])
        with open(mod.CONFIG_FILE, encoding="utf-8") as f:
            after = json.load(f)
        if after.get("domains") != ["b.example", "c.example"]:
            fail("配置写入（读-改-写）", "域名没去重归一化：%r" % after.get("domains"))
        elif after.get("fake_ip_pools") != {"host": ["9\\.9\\."]} or after.get("misc") != 42:
            fail("配置写入（读-改-写）",
                 "保存域名把其它键冲掉了（fake_ip_pools=%r misc=%r）—— "
                 "用户表现是「改一次域名表，别处配置就没了」"
                 % (after.get("fake_ip_pools"), after.get("misc")))
        else:
            ok("配置写入（读-改-写）", "域名已归一化，其余键原样保留")
    except Exception as e:                  # noqa: BLE001
        fail("配置写入（读-改-写）", "%s: %s" % (type(e).__name__, e))
    finally:
        if saved[0] is not None:
            mod.CONFIG_DIR, mod.CONFIG_FILE = saved
        if tmpdir:
            shutil.rmtree(tmpdir, ignore_errors=True)


def check_api():
    """十四、HTTP 端点表与前端调用是否对得上。

    这一节守的是「前端点了个不存在的接口」这类问题 —— 症状通常是某个按钮
    毫无反应 / 报 404，而控制台不在这台机器上，靠肉眼很难发现。
    这里把三件事一次性钉住：

      ① 服务端路由表里的每个路径都能落到一个真实方法上；
      ② `/api/v1/xxx` 与 `/api/xxx` 等价（版本前缀是别名，老路径不许失效）；
      ③ 前端页面里出现的每一个接口路径，服务端都认。

    全程只读：不启动服务、不发任何网络请求。
    """
    sec("十四、HTTP 端点表与前端接口对账")
    if not os.path.isfile(APP):
        skip("HTTP 端点表", "app/tunnel-manager.py 不存在")
        return
    try:
        mod = load_app()
    except Exception as e:                  # noqa: BLE001
        fail("加载模块（端点表）", "%s: %s" % (type(e).__name__, e))
        return

    handler = getattr(mod, "Handler", None)
    if handler is None:
        fail("HTTP 端点表", "模块里找不到 Handler")
        return

    get_routes = getattr(handler, "GET_ROUTES", None)
    post_routes = getattr(handler, "POST_ROUTES", None)
    if not isinstance(get_routes, dict) or not isinstance(post_routes, dict):
        fail("HTTP 端点表",
             "Handler 上没有 GET_ROUTES / POST_ROUTES —— "
             "这份 app/tunnel-manager.py 是「路由表」改造之前的旧版，"
             "请用同一批下载里的新包重新解压一份再跑")
        return

    # ① 表里每一条都能落到真实方法
    broken = []
    for method_name, table in (("GET", get_routes), ("POST", post_routes)):
        for path, fn in sorted(table.items()):
            if not path.startswith("/api/"):
                broken.append("%s %s（路径不以 /api/ 开头）" % (method_name, path))
            elif not callable(getattr(handler, fn, None)):
                broken.append("%s %s → 找不到方法 %s" % (method_name, path, fn))
    if broken:
        fail("路由表指向真实方法", "；".join(broken[:6]))
    else:
        ok("路由表指向真实方法",
           "读端点 %d 条、写端点 %d 条，全部有对应方法"
           % (len(get_routes), len(post_routes)))

    # ② 版本前缀是别名
    api_path = getattr(mod, "api_path", None)
    if not callable(api_path):
        fail("接口版本前缀", "模块里没有 api_path()，无法确认 /api/v1/ 是否等价")
    else:
        cases = [("/api/v1/scan", "/api/scan"),
                 ("/api/v1/steam/capture/result", "/api/steam/capture/result"),
                 ("/api/scan", "/api/scan"),
                 ("/", "/"), ("/index.html", "/index.html")]
        wrong = [(a, api_path(a), b) for a, b in cases if api_path(a) != b]
        if wrong:
            fail("接口版本前缀",
                 "这些归一化结果不对：%s" % "、".join(
                     "%s→%s（应为 %s）" % w for w in wrong))
        else:
            ok("接口版本前缀",
               "/api/v1/xxx 与 /api/xxx 等价；老路径 %d 条继续可用（含根路径不受影响）"
               % len(get_routes))

    # ③ 前端用到的路径，服务端必须都认
    try:
        html = mod.get_html()
    except Exception as e:                  # noqa: BLE001
        fail("取前端页面", "%s: %s" % (type(e).__name__, e))
        html = ""
    if not html:
        warn("前端接口对账", "拿不到页面内容（既没有 index.html 也没有内嵌副本），跳过")
    else:
        import re as _re
        known = set(get_routes) | set(post_routes)
        used = set()
        for _pre, rest in _re.findall(r"(/api/(?:v1/)?)([A-Za-z0-9_/]+)", html):
            used.add("/api/" + rest.strip("/"))
        missing = sorted(p for p in used if p not in known)
        if missing:
            fail("前端接口对账",
                 "页面里调了服务端没有的接口：%s —— "
                 "点了这些按钮会 404（什么都没发生）" % "、".join(missing))
        else:
            unused = sorted(known - used)
            msg = "页面用到 %d 个接口，服务端全都认" % len(used)
            if unused:
                msg += "；另有 %d 个服务端接口页面暂时没用到（%s）" % (
                    len(unused), "、".join(unused[:4]))
            ok("前端接口对账", msg)


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
    if EXTRA_DUMP:
        out.append("-" * 70)
        out.append("【附：系统命令原始输出】")
        out.append("  下面这些是程序**读网卡/路由/服务时真正拿到的原始文本**。")
        out.append("  三行以上看不懂的可以整段忽略 —— 它的用处是：如果界面上哪一项")
        out.append("  显示不出来，凭这段就能精确定位是哪一步解析对不上。")
        out.append("")
        out.extend(EXTRA_DUMP)
        out.append("=" * 70)
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


RAW_DUMPS = [
    ("powershell 探测", ["powershell.exe", "-NoProfile", "-NonInteractive",
                         "-Command", "'__TM_PS_OK__'"]),
    ("route print -4", ["route", "print", "-4"]),
    ("arp -a", ["arp", "-a"]),
    ("netsh interface ipv4 show interfaces",
     ["netsh", "interface", "ipv4", "show", "interfaces"]),
    ("netsh interface ipv4 show addresses",
     ["netsh", "interface", "ipv4", "show", "addresses"]),
    ("sc query type= service state= all",
     ["sc.exe", "query", "type=", "service", "state=", "all"]),
    ("netstat -e", ["netstat", "-e"]),
]


def check_win_env():
    """十二、Windows 上「系统查询通道」到底通不通。

    背景（2026-10-11 真机报告）：有一台 Windows 11 上 powershell.exe 被管理员
    策略拦死（[WinError 786]），程序会「不崩溃但全瞎」——网卡 0 个、隧道 0 个。
    所以程序里加了一层**只吃 System32 原生命令**的回退解析，这一段验证它。

    ① 明确回答 PowerShell 能不能用；
    ② 不能用时，逐项验证原生回退有没有顶上；
    ③ 把原生命令的**原始输出**附到报告末尾 —— 解析器就是按这些排版写的，
       万一哪一项没解析出来，凭这段就能精确定位。

    全程只读：不启动服务、不改路由、不弹 UAC。
    """
    global EXTRA_DUMP
    sec("十二、系统查询通道（Windows 原生回退）")
    if not IS_WIN:
        skip("系统查询通道", "当前不是 Windows，跳过（macOS 用不到这一层）")
        return
    if not os.path.isfile(APP):
        skip("系统查询通道", "app/tunnel-manager.py 不存在")
        return

    try:
        mod = load_app()
    except Exception as e:                  # noqa: BLE001
        fail("加载模块（原生回退）", "%s: %s" % (type(e).__name__, e))
        return
    if not hasattr(mod, "ps_available") or not hasattr(mod, "_nat_interfaces"):
        fail("程序版本",
             "这份 app/tunnel-manager.py 里**没有**原生回退层的代码（是旧版）。"
             "请用同一批下载里的新包重新解压一份再跑。")
        return

    # ① PowerShell 能不能用
    ps_ok = None
    try:
        ps_ok, ps_err = mod.ps_available(force=True)
    except Exception as e:                  # noqa: BLE001
        fail("PowerShell 探测", "%s: %s" % (type(e).__name__, e))
        ps_err = ""
    if ps_ok:
        ok("PowerShell 可用", "系统查询走 PowerShell（信息最全的那条路）")
    elif ps_ok is False:
        warn("PowerShell 不可用",
             "被系统策略挡住了 —— 这不是程序的问题，装了企业安全管理软件"
             "（如深信服 / 奇安信 / 360 企业版）的电脑常见这种情况。"
             "程序会自动改用系统自带的原生命令（route / arp / netsh / sc / tasklist）。")
        info("  原始错误", (ps_err or "(空)")[:300])

    # ② 原生回退逐项体检（只在 PowerShell 不可用时才有意义）
    if ps_ok is False:
        probe = [
            ("网卡列表", mod._nat_interfaces, ()),
            ("默认路由", mod._nat_snapshot, ()),
            ("路由快照", mod._nat_routes_snapshot, ()),
            ("IP→接口（最长前缀匹配）", mod._nat_iface_of_batch,
             (["114.114.114.114", "8.8.8.8"],)),
            ("服务枚举（sc query）", mod._nat_service_list, ()),
            ("已安装程序（winreg）", mod._nat_registry_apps, ()),
            ("系统 VPN（rasphone.pbk）", mod._nat_vpn_list, ()),
            ("进程列表（tasklist）", mod._nat_processes, ()),
        ]
        ifaces = None
        for label, fn, args in probe:
            r, err = call_timeout(fn, 120, *args)
            if err is not None:
                warn("原生：" + label, str(err)[:180])
                continue
            empty = (not r)
            if empty:
                warn("原生：" + label,
                     "拿到空结果 —— 界面上这一项会是空的（原始输出见报告末尾）")
            else:
                n = len(r) if hasattr(r, "__len__") else None
                if isinstance(r, dict) and "routes" in r:
                    n = len(r.get("routes") or [])       # 默认路由快照：数里面的条数
                ok("原生：" + label, "%d 条" % n if n is not None else "有结果")
            if label == "网卡列表" and isinstance(r, list):
                ifaces = r
                for i in r[:8]:
                    info("    " + (i.get("name") or "?")[:24],
                         "type=%s %s ip=%s  %s"
                         % (i.get("type"), i.get("status"),
                            i.get("ipv4") or "-", (i.get("desc") or "")[:38]))

        # ③ 决定性的一步：真实扫描能不能认出物理网卡与出口
        try:
            res = mod.do_scan()
        except Exception as e:              # noqa: BLE001
            fail("真实跑一次扫描", "%s: %s" % (type(e).__name__, e))
            res = None
        if isinstance(res, dict) and not res.get("error"):
            phys = res.get("phys_iface") or ""
            if phys:
                ok("扫描认出物理网卡", "%s（网关 %s）"
                   % (phys, res.get("phys_gw") or "?"))
            else:
                fail("扫描认出物理网卡",
                     "phys_iface 是空的 —— 界面上「本机直连 / 隧道接管」会判不准")
            outs = [o["name"] for o in (res.get("outlets") or [])]
            if len(outs) > 1:
                ok("出口探测", "、".join(outs))
            else:
                info("出口探测",
                     "只列出「物理直连」—— 本机没装 / 没跑隧道客户端时属正常")
            n_if = len(res.get("interfaces") or [])
            if n_if:
                ok("接口清单", "%d 个" % n_if)
            else:
                fail("接口清单", "一个接口都没列出来（原始输出见报告末尾）")

    # ④ 采集原始输出
    dump = []
    for label, argv in RAW_DUMPS:
        try:
            p = subprocess.run(argv, capture_output=True, text=True,
                               timeout=90, errors="replace",
                               creationflags=NO_WINDOW)
            body = (p.stdout or "").strip()
            tail = (p.stderr or "").strip()
            rc = p.returncode
        except Exception as e:              # noqa: BLE001
            body, tail, rc = "", "%s: %s" % (type(e).__name__, e), "ERR"
        dump.append("===== %s   (rc=%s) =====" % (label, rc))
        if tail:
            dump.append("  [stderr] " + tail.replace("\n", "\n  "))
        if body:
            lines = body.splitlines()
            dump.append("\n".join("  " + l for l in lines[:45]))
            if len(lines) > 45:
                dump.append("  …（共 %d 行，此处截取前 45 行）" % len(lines))
        else:
            dump.append("  (无输出)")
        dump.append("")
    EXTRA_DUMP = dump


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
               check_app_real, check_clients, check_outlets, check_win_env,
               check_rules, check_api):
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
