#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""make_win_pkg.py — 生成 Windows 免安装包（内置 Python 运行时）

为什么要有这个包
----------------
Windows 用户经常没装 Python，而 **macOS 上无法交叉编译出 .exe**
（PyInstaller / Nuitka 都只能在目标平台上构建）。所以改用
「内嵌 Windows embeddable Python + 双击 .bat」的绿色包，效果等同：
对方不需要安装任何东西，解压双击即可。

用法
----
    python3 make_win_pkg.py

首次运行会自动下载 python-3.13.12-embed-amd64.zip（约 11 MB）并缓存到
dist/_winbuild/（可随时删除，只会导致下次重新下载）。

产物
----
    dist/TunnelManager-Windows-x64.zip        约 10.3 MB
      └─ TunnelManager-Windows-x64/
           START-双击启动.bat      ← 用户双击这个
           STOP-停止服务.bat
           使用说明.txt
           app/tunnel-manager.py   ← dist 里的单文件版
           runtime/                ← 嵌入式 Python（30+ 个文件）

三条必须遵守的细节（都是实测踩出来的，别改）
--------------------------------------------
1. bat 必须存成 **GBK**：cmd.exe 按当前代码页（中文系统 cp936）解析批处理，
   存 UTF-8 会让中文提示变乱码，而且 `chcp 65001` 救不了 —— 它执行在解析之后。
   配套的说明 .txt 用 **utf-8-sig**（BOM 让记事本正确识别中文）。
2. 启动必须带 **-X utf8**：embeddable 因为有 `._pth` 处于 isolated 模式，
   `PYTHONIOENCODING` / `PYTHONUTF8` 这类环境变量**全部被忽略**；而日志重定向到
   文件后 stdout 会退回系统 locale 编码，英文版 Windows（cp1252）下中文 print
   会直接抛 UnicodeEncodeError。只有命令行开关不受 isolated 限制。
3. 打包必须用 Python 的 zipfile：它会给非 ASCII 文件名自动打 **UTF-8 flag（bit 11）**，
   Win10+ 资源管理器才能正确解出中文名；命令行 `zip` 不保证。
"""

import os
import shutil
import sys
import urllib.request
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
DIST = os.path.join(HERE, "dist")
CACHE = os.path.join(DIST, "_winbuild")
RUNTIME = os.path.join(CACHE, "runtime")

PY_VER = "3.13.12"
EMBED_URL = f"https://www.python.org/ftp/python/{PY_VER}/python-{PY_VER}-embed-amd64.zip"
EMBED_ZIP = os.path.join(CACHE, f"python-{PY_VER}-embed-amd64.zip")

TOP = "TunnelManager-Windows-x64"
OUT_ZIP = os.path.join(DIST, "TunnelManager-Windows-x64.zip")
SRC_PY = os.path.join(DIST, "tunnel-manager.py")

# runtime 里不需要打包的（签名目录 / 许可，省体积且无用）
SKIP = {"python.cat", "LICENSE.txt"}

START_BAT = r"""@echo off
title Universal Tunnel Manager

rem ---------------------------------------------------------------
rem 用 pushd 而不是 cd /d：
rem 如果程序被放在 UNC 路径下（典型场景：在 Windows 虚拟机里通过 Parallels
rem 的 \\Mac\Home\... 访问宿主机的文件夹），cd /d 会直接失败并打印
rem "UNC 路径不受支持"，后果是后面所有相对路径检查全部落空。
rem pushd 会把 UNC 自动映射成临时盘符，相对路径就正常了。
rem ---------------------------------------------------------------
pushd "%~dp0" 2>nul || goto baddir

if not exist "app\tunnel-manager.py" goto baddir
if not exist "runtime\python.exe"     goto baddir
if not exist "runtime\python313.dll"  goto baddir

rem ---------------------------------------------------------------
rem 已经在跑就不要再起一个（否则端口顺延到 7532，出现两个界面）
rem 用 .NET TcpClient 探 7531，比 Test-NetConnection 快得多
rem ---------------------------------------------------------------
powershell -NoProfile -ExecutionPolicy Bypass -Command "try { $c = New-Object Net.Sockets.TcpClient; $c.Connect('127.0.0.1', 7531); $c.Close(); exit 0 } catch { exit 1 }"
if %errorlevel%==0 (
  echo.
  echo   服务已经在运行，直接打开界面 ...
  start "" http://127.0.0.1:7531
  timeout /t 3 /nobreak >nul
  exit /b 0
)

echo.
echo   通用隧道管理 · 正在启动 ...
echo   ------------------------------------------------
echo   浏览器会在几秒内自动打开： http://127.0.0.1:7531
echo   若没自动打开，请手动在浏览器输入上面这个网址。
echo.
echo   停止服务：双击 STOP-停止服务.bat
echo   运行日志：本文件夹下的 tunnel-manager.log
echo.

rem 启动用 %~dp0 绝对路径，不依赖当前盘符 —— 这样即使 pushd 的临时映射
rem 被回收，进程依然能找到自己的文件。
rem -X utf8 是必须的：日志被重定向到文件时，stdout 会退回系统 locale 编码，
rem 在英文版 Windows（cp1252）下中文 print 会直接抛 UnicodeEncodeError。
rem 注意 embeddable 因有 ._pth 处于 isolated 模式，PYTHONIOENCODING 之类的
rem 环境变量会被忽略，只有命令行开关才管用，所以必须写在这里。
start "TunnelManager" /min cmd /c ""%~dp0runtime\python.exe" -X utf8 "%~dp0app\tunnel-manager.py" 1> "%~dp0tunnel-manager.log" 2>&1"

echo   已启动（服务在本机后台运行，关掉本窗口不影响）。
timeout /t 6 /nobreak >nul
exit /b 0

:baddir
echo.
echo   [错误] 启动失败。请按顺序确认：
echo     1) 解压时保留了完整目录结构（应有 app\ 和 runtime\ 两个文件夹）
echo     2) 不要在压缩包里直接双击，要先解压
echo     3) 不要放在网络共享 / 虚拟机的 UNC 路径下运行
echo   当前目录： %CD%
echo.
pause
exit /b 1
"""

STOP_BAT = r"""@echo off
title Stop Tunnel Manager
echo.
echo   正在停止「通用隧道管理」 ...
powershell -NoProfile -ExecutionPolicy Bypass -Command "$p = Get-CimInstance Win32_Process -Filter \"Name='python.exe'\" | Where-Object { $_.CommandLine -like '*tunnel-manager*' }; if ($p) { $p | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }; Write-Host ('  stopped ' + @($p).Count + ' process(es)') } else { Write-Host '  not running' }"
echo.
timeout /t 4 /nobreak >nul
exit /b 0
"""

README_TXT = """通用隧道管理 · Windows 免安装版
========================================

【怎么用】
  1. 先把压缩包完整解压出来（不要在压缩包里直接双击！）
  2. 双击  START-双击启动.bat
  3. 浏览器会自动打开 http://127.0.0.1:7531

【不需要安装 Python】
  本包已经内置了精简版 Python 运行时（runtime 文件夹），
  你的电脑上不需要装任何东西。

【怎么停止】
  双击  STOP-停止服务.bat
  或者直接关掉那个最小化的黑窗口。

【启动不了 / 想先体检一下】
  双击  检查运行.bat  —— 它会自己做一遍全面检查，
  并生成「检查报告.txt」。把那个文件发回给我，就能定位问题。
  这个检查是只读的：不改路由、不动 DNS、不装东西。

【会弹防火墙吗】
  服务只监听 127.0.0.1（本机回环），同一局域网里的其他人访问不到。
  如果 Windows 弹出防火墙提示，选“允许”即可（它不会对外暴露端口）。

【出问题怎么查】
  启动后本文件夹会出现 tunnel-manager.log，里面是服务的输出，
  把它连同「检查报告.txt」一起发回来就能定位问题。

【已知限制（重要）】
  · 「一键切换出口」目前只支持 macOS。
  · Windows 分支的代码没有在真机上完整测试过，能启动、界面能用，
    但网络扫描/改路由这类功能是否完全正常，需要在你的机器上验证。

【卸载】
  直接删除整个文件夹即可 —— 不写注册表、不装系统服务、不设开机自启。
  配置与记忆在：%USERPROFILE%\\.tunnel-manager
  （想彻底清干净就连它一起删）

【版本】
  内置 Python {pyver} (embeddable, amd64 / 64 位 Windows)
  如果是 32 位系统或 ARM 版 Windows，请另说，需要换对应运行时。
"""


# 自检脚本的启动器。注意：bat 会被以 GBK 写出（见文件头"三条必须遵守的细节"）
SELFTEST_BAT = r"""@echo off
title Universal Tunnel Manager - Run Check

rem pushd 而不是 cd /d —— 支持 UNC 路径（虚拟机里 \\Mac\Home\... 这种），
rem cd /d 对 UNC 会失败并让后面所有相对路径检查落空
pushd "%~dp0" 2>nul || goto nocwd

if not exist "selftest.py" goto noself

set PY=
if exist "runtime\python.exe" set PY=runtime\python.exe
if not defined PY if exist "..\runtime\python.exe" set PY=..\runtime\python.exe
if not defined PY ( where python >nul 2>&1 && set PY=python )
if not defined PY goto nopy

echo.
echo   通用隧道管理 · 运行环境自检
echo   正在检查，大约 10 到 40 秒，请稍等 ...
echo.

rem -X utf8 必须带：详见 make_win_pkg.py 文件头的说明
"%PY%" -X utf8 selftest.py

echo.
echo   ------------------------------------------------------------
echo   如果上面提示"报告已保存"，请把「检查报告.txt」发回来。
echo   本检查是只读的：不改路由、不动 DNS、不装任何东西。
echo   ------------------------------------------------------------
echo.
pause
exit /b 0

:noself
echo.
echo   [错误] 找不到 selftest.py
echo   请把它和本文件放在同一个文件夹里，再双击本文件。
echo.
pause
exit /b 1

:nopy
echo.
echo   [错误] 找不到 Python 运行时。
echo.
echo   正确用法：把「selftest.py」和本文件一起放进**解压后**的
echo   TunnelManager-Windows-x64 文件夹（和 START-双击启动.bat 同级），
echo   然后再双击本文件。
echo.
pause
exit /b 1

:nocwd
echo.
echo   [错误] 无法进入脚本所在目录。
echo   请不要在压缩包里直接双击，也不要在网络共享路径下运行；
echo   先把整个文件夹解压到本地磁盘，再双击本文件。
echo   当前目录： %CD%
echo.
pause
exit /b 1
"""

EXTRA_README = """运行检查工具 · 怎么用（macOS / Windows 都有）
========================================

【先看这里】
  如果你还没下载过主程序 —— **不用看这份说明**，直接去下完整包就好，
  检查工具已经在那个包里了。解压后：
    · Windows → 双击 检查运行.bat
    · macOS   → 双击 检查运行.command
  不需要把任何文件搬到别的位置。

  本压缩包是给**已经装好程序、不想重新下 10 MB** 的人用的。

--------（以下是"单独用本包"的说明）--------

这个小工具用来检查「通用隧道管理」在你的电脑上能不能正常跑。
它是只读的：不改路由、不动 DNS、不装任何东西。

【第一步：选对你系统的那个】
  · Windows  → 检查运行.bat
  · macOS    → 检查运行.command

【第二步：放进程序目录再双击】
  解压本压缩包，把里面的 selftest.py 和对应那个启动器，
  复制到程序所在的文件夹，然后双击启动器：
    · Windows：就是有 START-双击启动.bat 的那个文件夹
    · macOS：  就是有 tunnel-manager.py 的 ~/.tunnel-manager 目录

【macOS 提示「无法验证开发者」怎么办】
  这是从网上下载的文件的正常保护。在文件上右键 →「打开」，
  弹窗里再点一次「打开」，放行一次就行；之后就能直接双击了。

【跑完之后】
  同目录会生成「检查报告.txt」，
  把它发回来就行。报告里只有系统版本、网卡名、路由状态这类信息，
  不含任何隐私内容。
"""


def human(n):
    for u in ("B", "KB", "MB"):
        if n < 1024:
            return f"{n:.0f} {u}"
        n /= 1024
    return f"{n:.1f} GB"


def ensure_runtime():
    """确保 runtime/ 就绪（首次会下载约 11 MB 的官方嵌入式运行时）。"""
    if os.path.isfile(os.path.join(RUNTIME, "python.exe")):
        print(f"  复用已缓存的运行时：{RUNTIME}")
        return
    os.makedirs(CACHE, exist_ok=True)
    if not os.path.isfile(EMBED_ZIP):
        print(f"  下载 {EMBED_URL}")
        print("  （约 11 MB，首次运行需要，之后会缓存）")
        urllib.request.urlretrieve(EMBED_URL, EMBED_ZIP)
    print(f"  解压到 {RUNTIME}")
    os.makedirs(RUNTIME, exist_ok=True)
    with zipfile.ZipFile(EMBED_ZIP) as z:
        z.extractall(RUNTIME)


def main():
    if not os.path.isfile(SRC_PY):
        raise SystemExit("先跑 build.py 生成 dist/tunnel-manager.py")

    print("① 准备 Windows 运行时")
    ensure_runtime()

    print("② 组装目录")
    build_root = os.path.join(CACHE, "pkg")
    pkg = os.path.join(build_root, TOP)
    if os.path.isdir(build_root):
        shutil.rmtree(build_root)
    os.makedirs(os.path.join(pkg, "app"))
    os.makedirs(os.path.join(pkg, "runtime"))

    n = 0
    for fn in sorted(os.listdir(RUNTIME)):
        if fn in SKIP:
            continue
        shutil.copy2(os.path.join(RUNTIME, fn), os.path.join(pkg, "runtime", fn))
        n += 1
    print(f"    runtime: {n} 个文件")

    shutil.copy2(SRC_PY, os.path.join(pkg, "app", "tunnel-manager.py"))
    print(f"    app/tunnel-manager.py: {os.path.getsize(SRC_PY)} 字节")

    # bat 用 GBK；说明用 utf-8-sig（见文件头的"三条必须遵守的细节"）
    with open(os.path.join(pkg, "START-双击启动.bat"), "w",
              encoding="gbk", newline="\r\n") as f:
        f.write(START_BAT)
    with open(os.path.join(pkg, "STOP-停止服务.bat"), "w",
              encoding="gbk", newline="\r\n") as f:
        f.write(STOP_BAT)
    with open(os.path.join(pkg, "使用说明.txt"), "w",
              encoding="utf-8-sig", newline="\r\n") as f:
        f.write(README_TXT.replace("{pyver}", PY_VER))
    print("    bat/txt 已写入（bat=GBK, txt=UTF-8-SIG）")

    # 自检工具：让他跑一遍、把 检查报告.txt 发回来
    # 源统一放在 tools/（两个平台共用同一个 selftest.py，各带一个双击入口）
    selftest_src = os.path.join(HERE, "tools", "selftest.py")
    if not os.path.isfile(selftest_src):
        raise SystemExit("找不到 tools/selftest.py（先跑 python3 make_tools.py 生成）")
    shutil.copy2(selftest_src, os.path.join(pkg, "selftest.py"))
    with open(os.path.join(pkg, "检查运行.bat"), "w",
              encoding="gbk", newline="\r\n") as f:
        f.write(SELFTEST_BAT)
    print("    自检工具已加入：检查运行.bat + selftest.py")

    print("③ 打包")
    with zipfile.ZipFile(OUT_ZIP, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for root, _dirs, files in os.walk(pkg):
            for fn in files:
                full = os.path.join(root, fn)
                arc = os.path.relpath(full, build_root).replace(os.sep, "/")
                z.write(full, arc)      # zipfile 自动给中文名打 UTF-8 flag

    size = os.path.getsize(OUT_ZIP)
    print()
    print(f"完成：{OUT_ZIP}")
    print(f"      {size} 字节 ({human(size)})")

    # 独立小工具包：只想单独发给"已经下过整包"的人时用（几 KB）
    # 双平台：Windows 用 .bat，macOS 用 .command，共用同一个 selftest.py
    mac_cmd_src = os.path.join(HERE, "tools", "检查运行.command")
    extra = os.path.join(DIST, "运行检查工具.zip")
    with zipfile.ZipFile(extra, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        z.write(selftest_src, "selftest.py")
        z.writestr("检查运行.bat", SELFTEST_BAT.encode("gbk"))
        if os.path.isfile(mac_cmd_src):
            z.write(mac_cmd_src, "检查运行.command")   # z.write 会保留可执行位
        z.writestr("说明.txt", EXTRA_README.encode("utf-8-sig"))
    esz = os.path.getsize(extra)
    print(f"附带：{extra}")
    print(f"      {esz} 字节 ({human(esz)}) —— 可单独发，放进解压后的目录里即可")
    print()
    print("交付说明：")
    print("  ① 整包：发给 Windows 用户 → 解压 → 双击 START-双击启动.bat（不用装 Python）")
    print("  ② 体检：让他双击 检查运行.bat（Win）/ 检查运行.command（mac）")
    print("          → 把生成的 检查报告.txt 发回")
    print("  ③ 只发体检：把 运行检查工具.zip 单独发过去（双平台），解压到程序目录再双击")


if __name__ == "__main__":
    main()
