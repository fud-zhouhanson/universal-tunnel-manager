#!/usr/bin/env bash
# ============================================================
# scripts/build.sh —— 一键构建全部发布产物 + 校验和
#
#   bash scripts/build.sh
#
# 产物（都在 dist/，均已被 .gitignore 排除）：
#   dist/tunnel-manager.py              单文件程序（内嵌前端）
#   dist/tunnel-manager.zip             macOS / Linux 通用包
#   dist/TunnelManager-Windows-x64.zip   Windows 免安装包（内置 Python 运行时）
#   dist/RunCheck-tool.zip              备用体检小包（ASCII 名，供 Release / Pages 直链）
#   dist/运行检查工具.zip                 同上（中文名，供本地分发给中文用户）
#   dist/download.html                  分享落地页（zip 以 base64 内嵌，本地生成下载）
#   dist/SHA256SUMS                     以上产物的校验和
#   docs/index.html                     GitHub Pages 落地页（下载指向 GitHub Releases）
#
# 环境变量：
#   PYTHON=python3.13   指定解释器（默认 python3）
#   SKIP_WIN=1          跳过 Windows 免安装包（它首次需要联网下载 ~11 MB 运行时）
# ============================================================
set -euo pipefail

# 切到仓库根（脚本可能从任意目录被调用）
cd "$(dirname "$0")/.."

PY="${PYTHON:-python3}"
DIST="dist"
DOCS="docs"

echo "==> 解释器：$($PY -V 2>&1)"
mkdir -p "$DIST" "$DOCS"

# ------------------------------------------------------------
# 1) 生成平台启动器（tools/检查运行.bat / .command）
#    必须最先跑：build.py 会把它们打进 zip，
#    且 .command 的可执行位由这一步写入。
# ------------------------------------------------------------
echo "==> [1/4] 生成自检工具启动器"
"$PY" make_tools.py

# ------------------------------------------------------------
# 2) 单文件程序 + 通用包
# ------------------------------------------------------------
echo "==> [2/4] 打包单文件程序与通用包"
"$PY" build.py

# ------------------------------------------------------------
# 3) Windows 免安装包（内置 Python 运行时）+ 体检小包
# ------------------------------------------------------------
if [ "${SKIP_WIN:-0}" = "1" ]; then
  echo "==> [3/4] 跳过 Windows 包（SKIP_WIN=1）"
else
  echo "==> [3/4] 打包 Windows 免安装版"
  "$PY" make_win_pkg.py
fi

# ------------------------------------------------------------
# 4) 落地页：dist/download.html（分享用）+ docs/index.html（GitHub Pages 用）
# ------------------------------------------------------------
echo "==> [4/4] 生成落地页"
"$PY" make_download_page.py

# 中文名的体检包再复制一份 ASCII 名 —— gh CLI 上传中文名附件时会被改成 default.zip，
# GitHub Pages / Release 直链用 ASCII 名最稳。
if [ -f "$DIST/运行检查工具.zip" ]; then
  cp -f "$DIST/运行检查工具.zip" "$DIST/RunCheck-tool.zip"
fi

# ------------------------------------------------------------
# 校验和
# ------------------------------------------------------------
echo "==> 计算 SHA256"
if command -v shasum >/dev/null 2>&1; then
  HASH="shasum -a 256"
else
  HASH="sha256sum"
fi
( cd "$DIST" && rm -f SHA256SUMS && \
  for f in *.zip *.py; do
    [ -f "$f" ] || continue
    case "$f" in SHA256SUMS) continue;; esac
    $HASH "$f"
  done > SHA256SUMS )

echo
echo "=========== 完成 ==========="
ls -la "$DIST"/*.zip "$DIST"/tunnel-manager.py 2>/dev/null || true
echo "--- SHA256SUMS ---"
cat "$DIST/SHA256SUMS"
echo "--- docs/index.html ---"
ls -la "$DOCS/index.html" 2>/dev/null || echo "（未生成）"
