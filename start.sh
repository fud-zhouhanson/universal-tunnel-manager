#!/bin/bash
# Universal Tunnel Manager — macOS 一键启动
# 双击此文件即可：自动找 Python → 启动服务 → 打开浏览器
# 原理：先探测可用 python3，后台拉起 server.py，等端口起来后打开链接

set -u
DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"

# 按优先级找 Python（系统自带优先，没有就退到常见安装路径）
PY=""
for c in /usr/bin/python3 /usr/local/bin/python3 /opt/homebrew/bin/python3 python3; do
  if command -v "$c" >/dev/null 2>&1; then PY="$c"; break; fi
done
if [ -z "$PY" ]; then
  osascript -e 'display dialog "未找到 python3，请先从 python.org 或 App Store 安装 Python 3。" with title "无法启动" buttons {"好"} default 1' 2>/dev/null
  exit 1
fi

echo "使用 Python: $PY"
echo "启动 Universal Tunnel Manager..."

# 后台启动服务，记录日志
LOG="$DIR/tunnel-manager.log"
"$PY" "$DIR/server.py" > "$LOG" 2>&1 &
SRV_PID=$!

# 等服务起来（最多 15 秒），从输出里抓链接
URL=""
for i in $(seq 1 30); do
  sleep 0.5
  [ -f "$LOG" ] && URL=$(grep -oE 'http://127\.0\.0\.1:[0-9]+' "$LOG" 2>/dev/null | head -1)
  [ -n "$URL" ] && break
  # 服务可能已退出
  if ! kill -0 "$SRV_PID" 2>/dev/null; then
    echo "服务启动失败，日志："; cat "$LOG"
    osascript -e "display dialog \"服务启动失败，请查看日志：$LOG\" with title \"启动失败\" buttons {\"好\"} default 1" 2>/dev/null
    exit 1
  fi
done

if [ -n "$URL" ]; then
  echo "已就绪：$URL"
  open "$URL"
else
  echo "等待超时，打开服务地址兜底"
  open "http://127.0.0.1:7531"
fi

# 前台保持，关掉终端窗口即退出服务
wait "$SRV_PID"
