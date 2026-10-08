@echo off
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
