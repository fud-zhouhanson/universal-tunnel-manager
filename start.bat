@echo off
rem 本文件必须存成 GBK(cp936)。
rem 原来那版是「UTF-8 存中文 + chcp 65001」，实测会乱码：cmd 是按当前代码页
rem 逐行解析批处理的，执行到 chcp 时这些行早就解码过了，中文照样是乱码。
title Universal Tunnel Manager

rem 用 pushd 而不是 cd /d —— cd /d 对 UNC 路径（虚拟机里 \\Mac\Home\... 这种）
rem 会失败并打印「UNC 路径不受支持」，之后所有相对路径都会落空
pushd "%~dp0" 2>nul || goto nocwd

set PY=
where python >nul 2>&1 && set PY=python
if not defined PY where py >nul 2>&1 && set PY=py
if not defined PY goto nopy

echo 使用 Python: %PY%
echo 正在启动 Universal Tunnel Manager ...

start /b "" %PY% "%~dp0server.py" > "%~dp0tunnel-manager.log" 2>&1

set URL=
for /l %%i in (1,1,30) do (
  if not defined URL (
    timeout /t 1 /nobreak >nul
    for /f "tokens=*" %%a in ('findstr /r /c:"http://127.0.0.1:[0-9]*" "%~dp0tunnel-manager.log" 2^>nul') do (
      set URL=%%a
      goto goturl
    )
  )
)
:goturl

if defined URL (
  for /f "tokens=1" %%u in ("%URL%") do start "" %%u
) else (
  start "" http://127.0.0.1:7531
)

echo 服务已在后台运行，关闭本窗口不会退出。
echo 如需停止：运行 stop.bat
timeout /t 3 >nul
exit /b 0

:nopy
echo.
echo   [错误] 未找到 Python。
echo   请先到 python.org 安装 Python 3，安装时勾选 "Add Python to PATH"。
echo   （如果不想装 Python，请改用 Windows 免安装版：解压后双击 START-双击启动.bat）
echo.
pause
exit /b 1

:nocwd
echo.
echo   [错误] 无法进入脚本所在目录。
echo   请不要在网络共享 / 虚拟机 UNC 路径下运行，先把文件夹解压到本地磁盘。
echo   当前目录： %CD%
echo.
pause
exit /b 1
