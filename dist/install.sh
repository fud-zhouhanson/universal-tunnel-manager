#!/bin/bash
# tunnel-manager 一键安装（macOS）
#
# 用法（一行命令，别人复制粘贴即可）：
#   curl -fsSL https://你的域名/tunnel-manager.sh | bash
#
# 或先下载再跑：
#   bash tunnel-manager.sh          # 安装
#   bash tunnel-manager.sh run      # 安装并立即启动
#
# 做的事：
#   1. 下载单文件 tunnel-manager.py 到 ~/.tunnel-manager/
#   2. 加可执行权限
#   3. 在桌面放一个「隧道管理.command」双击即用
#   4. 打印启动说明

set -u

INSTALL_DIR="$HOME/.tunnel-manager"
PY_FILE="$INSTALL_DIR/tunnel-manager.py"
DESKTOP_APP="$HOME/Desktop/隧道管理.command"

# ↓↓↓ 发布时改成你自己的下载地址（https 优先）↓↓↓
DOWNLOAD_URL="${TM_URL:-https://raw.githubusercontent.com/你的用户名/你的仓库/main/dist/tunnel-manager.py}"

err() { echo "错误：$*" >&2; }

# ---- 找 Python ----
PY=""
for c in /usr/bin/python3 /usr/local/bin/python3 /opt/homebrew/bin/python3 python3; do
  if command -v "$c" >/dev/null 2>&1; then PY="$c"; break; fi
done
if [ -z "$PY" ]; then
  err "未找到 python3。请先安装 Python 3：https://www.python.org/downloads/"
  exit 1
fi
echo "Python: $($PY --version 2>&1)"

# ---- 下载（同目录有现成的就直接用）----
mkdir -p "$INSTALL_DIR"
SCRIPT_DIR="$(cd "$(dirname "$0")" >/dev/null 2>&1 && pwd)"
if [ -f "$SCRIPT_DIR/tunnel-manager.py" ]; then
  echo "使用同目录下的 tunnel-manager.py"
  cp "$SCRIPT_DIR/tunnel-manager.py" "$PY_FILE"
elif command -v curl >/dev/null 2>&1; then
  echo "下载 tunnel-manager.py ..."
  if ! curl -fsSL "$DOWNLOAD_URL" -o "$PY_FILE"; then
    err "下载失败：$DOWNLOAD_URL"
    exit 1
  fi
elif command -v wget >/dev/null 2>&1; then
  echo "下载 tunnel-manager.py ..."
  if ! wget -qO "$PY_FILE" "$DOWNLOAD_URL"; then
    err "下载失败：$DOWNLOAD_URL"
    exit 1
  fi
else
  err "需要 curl 或 wget 来下载（或把 tunnel-manager.py 放到本脚本同目录）"
  exit 1
fi
chmod +x "$PY_FILE"
echo "已安装到 $PY_FILE"

# ---- 桌面快捷方式（双击即用）----
mkdir -p "$(dirname "$DESKTOP_APP")"
cat > "$DESKTOP_APP" <<'APP_EOF'
#!/bin/bash
# 隧道管理 —— 双击启动
# ⚠ 本文件由 dist/install.sh 生成。要改请改 install.sh 里的同名模板，
#   否则下次跑 install.sh 会被覆盖回去。
DIR="$HOME/.tunnel-manager"
APP="$DIR/tunnel-manager.py"
for c in /usr/bin/python3 /usr/local/bin/python3 /opt/homebrew/bin/python3 python3; do
  if command -v "$c" >/dev/null 2>&1; then PY="$c"; break; fi
done
if [ -z "$PY" ]; then
  osascript -e 'display dialog "未找到 python3\n请先安装：https://www.python.org/downloads/" buttons {"好"}' 2>/dev/null
  exit 1
fi
if [ ! -f "$APP" ]; then
  osascript -e 'display dialog "找不到 ~/.tunnel-manager/tunnel-manager.py\n请重新运行安装脚本。" buttons {"好"}' 2>/dev/null
  exit 1
fi
# 启动前先交代「跑的是哪一版」——本项目踩过两次「以为改了、其实跑的是旧版」的坑
SIZE=$(wc -c < "$APP" | tr -d ' ')
BUILT=$(stat -f '%Sm' -t '%Y-%m-%d %H:%M' "$APP" 2>/dev/null)
echo "隧道管理 · $APP"
echo "  版本：$SIZE 字节 · 构建于 $BUILT"
if grep -q "八·八、Steam 体检" "$APP" 2>/dev/null; then
  echo "  Steam 体检模块：已包含 ✓"
else
  echo "  Steam 体检模块：缺失 —— 这是旧版，请在项目目录执行 bash dist/install.sh"
fi
echo "  注：若 7531 已被别的实例占用，服务会顺延到 7532/7533 —— 以本窗口输出的网址为准。"
echo "------------------------------------------------------------"
"$PY" "$APP"
CODE=$?
if [ "$CODE" -ne 0 ] && [ "$CODE" -ne 130 ]; then
  echo
  echo "启动失败（退出码 $CODE）—— 上面是错误信息，按回车关闭本窗口。"
  read -r _
fi
APP_EOF
chmod +x "$DESKTOP_APP"
echo "桌面快捷方式：$DESKTOP_APP"

# ---- 顺便装一份自检工具（不往桌面加图标，免得占地方）----
# 解压目录随时可能被删，所以把体检工具也放一份到安装目录，以后随时能跑。
if [ -f "$SCRIPT_DIR/selftest.py" ]; then
  cp "$SCRIPT_DIR/selftest.py" "$INSTALL_DIR/" 2>/dev/null
  cp "$SCRIPT_DIR/检查运行.command" "$INSTALL_DIR/" 2>/dev/null
  chmod +x "$INSTALL_DIR/检查运行.command" 2>/dev/null
fi

# ---- 立即启动？----
if [ "${1:-}" = "run" ]; then
  echo "启动中..."
  exec "$PY" "$PY_FILE"
fi

cat <<EOF

安装完成。两种打开方式：
  1. 双击桌面上的「隧道管理.command」
  2. 终端运行：  python3 ~/.tunnel-manager/tunnel-manager.py

启动后会自动打开浏览器，访问 http://127.0.0.1:7531
（只绑 127.0.0.1，只有你自己能访问）

随时体检（只读，不改路由/不改 DNS）：bash ~/.tunnel-manager/检查运行.command

卸载： rm -rf ~/.tunnel-manager ~/Desktop/隧道管理.command
EOF
