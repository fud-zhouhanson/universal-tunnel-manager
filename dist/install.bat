@echo off
setlocal enabledelayedexpansion

rem tunnel-manager 一键安装（Windows，通用版 —— 需要系统里有 Python 3）
rem
rem 用法（PowerShell 一行命令，别人复制粘贴即可）：
rem   iwr -useb https://你的域名/install.bat | iex
rem
rem 或先下载再双击运行。
rem
rem 【重要】本文件必须存成 GBK(cp936)：cmd 按当前代码页逐行解析批处理，
rem 存成 UTF-8 会让下面所有中文提示变成乱码，而且乱码碎片会被当成命令执行
rem （满屏「'xxx' 不是内部或外部命令」）。chcp 65001 救不了 —— 它执行的
rem 时候这些行早就解码过了。
rem
rem 如果你的电脑上没有 Python，请改用「Windows 免安装版」那个包，
rem 它内置了运行环境，解压后双击 START-双击启动.bat 就行。

set "INSTALL_DIR=%USERPROFILE%\.tunnel-manager"
set "PY_FILE=%INSTALL_DIR%\tunnel-manager.py"
set "DOWNLOAD_URL=https://raw.githubusercontent.com/你的用户名/你的仓库/main/dist/tunnel-manager.py"

rem pushd 而不是 cd /d：cd /d 对 UNC 路径（虚拟机里的 \\Mac\Home\...）会失败
pushd "%~dp0" 2>nul || goto nocwd

echo ========================================
echo   tunnel-manager 一键安装
echo ========================================

rem ---- 找 Python ----
set PY=
where python >nul 2>&1 && set PY=python
if not defined PY where py >nul 2>&1 && set PY=py
if not defined PY goto nopy
echo Python: %PY%

rem ---- 取程序（同目录有现成的就直接用）----
if not exist "%INSTALL_DIR%" mkdir "%INSTALL_DIR%"
if exist "%~dp0tunnel-manager.py" (
  echo 使用同目录下的 tunnel-manager.py
  copy /y "%~dp0tunnel-manager.py" "%PY_FILE%" >nul
) else (
  echo 下载 tunnel-manager.py ...
  powershell -NoProfile -Command "try { Invoke-WebRequest -Uri '%DOWNLOAD_URL%' -OutFile '%PY_FILE%' -UseBasicParsing } catch { Write-Host '下载失败：' $_.Exception.Message; exit 1 }"
)
if not exist "%PY_FILE%" goto nofile
echo 已安装到 %PY_FILE%

rem ---- 桌面快捷方式（这个生成出来的文件全是 ASCII，不受编码影响）----
set "DESKTOP=%USERPROFILE%\Desktop\隧道管理.bat"
(
  echo @echo off
  echo cd /d "%%USERPROFILE%%\.tunnel-manager"
  echo start "" python tunnel-manager.py
) > "%DESKTOP%"
echo 桌面快捷方式：%DESKTOP%

echo.
echo ========================================
echo 安装完成。两种打开方式：
echo   1. 双击桌面上的「隧道管理.bat」
echo   2. 命令行运行：python %%USERPROFILE%%\.tunnel-manager\tunnel-manager.py
echo.
echo 启动后会自动打开浏览器，访问 http://127.0.0.1:7531
echo 卸载：删除 %%USERPROFILE%%\.tunnel-manager 目录和桌面快捷方式
echo ========================================
pause
exit /b 0

:nopy
echo.
echo 错误：未找到 Python。
echo 请先安装：https://www.python.org/downloads/
echo 安装时请勾选 "Add Python to PATH"
echo.
echo 不想装 Python 的话，请改用「Windows 免安装版」那个包：
echo 内置了运行环境，解压后双击 START-双击启动.bat 即可。
echo.
pause
exit /b 1

:nofile
echo.
echo 安装失败：没有拿到 tunnel-manager.py。
echo 请把它放到本脚本同目录，或检查网络。
echo.
pause
exit /b 1

:nocwd
echo.
echo 错误：无法进入脚本所在目录。
echo 请不要在网络共享 / 虚拟机 UNC 路径下运行，先解压到本地磁盘再执行。
echo 当前目录： %CD%
echo.
pause
exit /b 1
