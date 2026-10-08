#!/bin/bash
# 通用隧道管理器 · 运行环境自检（macOS）
#
# 双击本文件即可。也可以在终端里跑：
#     cd "<本文件所在目录>" && bash 检查运行.command
#
# 本脚本是只读的：不改路由、不动 DNS、不装任何东西。

cd "$(dirname "$0")" 2>/dev/null || {
  echo "[错误] 无法进入本文件所在目录。"
  read -r -p "按回车关闭本窗口 ..."
  exit 1
}

if [ ! -f "selftest.py" ]; then
  echo "[错误] 同目录下找不到 selftest.py。"
  echo "       请把它和本文件放在同一个文件夹里，再双击本文件。"
  read -r -p "按回车关闭本窗口 ..."
  exit 1
fi

PY=""
if command -v python3 >/dev/null 2>&1; then
  PY="python3"
fi
if [ -z "$PY" ]; then
  echo "[错误] 找不到 python3。"
  echo "       macOS 一般自带 python3；若确实没有，可以："
  echo "         · 在终端运行  xcode-select --install"
  echo "         · 或到 https://www.python.org/downloads/ 安装"
  read -r -p "按回车关闭本窗口 ..."
  exit 1
fi

echo
echo "  通用隧道管理 · 运行环境自检"
echo "  正在检查，大约 10-40 秒，请稍等 ..."
echo

"$PY" -X utf8 selftest.py

echo
echo "  ------------------------------------------------------------"
echo "  若上面提示「报告已保存」，请把「检查报告.txt」发回来。"
echo "  本检查是只读的：不改路由、不动 DNS、不装任何东西。"
echo "  ------------------------------------------------------------"
read -r -p "按回车关闭本窗口 ..."
