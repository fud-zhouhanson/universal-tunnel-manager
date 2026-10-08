@echo off
rem 本文件必须存成 GBK(cp936)，原因见 start.bat 顶部注释
title Stop Tunnel Manager
echo 正在停止服务 ...
taskkill /f /im python.exe >nul 2>&1
taskkill /f /im py.exe >nul 2>&1
echo 已尝试停止服务
timeout /t 2 >nul
