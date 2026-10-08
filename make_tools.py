#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""把自检工具整理成跨平台，并生成两个平台的双击启动器。

产出（都在 tools/ 下）：
  tools/selftest.py         自检主体（跨平台，UTF-8）
  tools/检查运行.bat         Windows 启动器（**必须 GBK**，见下面的说明）
  tools/检查运行.command     macOS 启动器（UTF-8，带可执行位）

为什么 bat 要单独以 GBK 落地、而不是让使用者临时转码：
cmd.exe 是按**当前代码页**逐行解析批处理的，含中文的 .bat 存成 UTF-8 会乱码，
而且乱码碎片会被当成命令逐行执行（满屏「'xxx' 不是内部或外部命令」）。
所以这个文件必须**在仓库里就是 GBK**，谁打包都直接拿来用。
"""
import os
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
TOOLS = os.path.join(HERE, "tools")
OLD = os.path.join(HERE, "win-tools")

MAC_CMD = r"""#!/bin/bash
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
"""


def main():
    # 1) win-tools/ -> tools/（自检脚本现在两个平台共用，名字别再叫 win-）
    os.makedirs(TOOLS, exist_ok=True)
    src_py = os.path.join(OLD, "selftest.py")
    dst_py = os.path.join(TOOLS, "selftest.py")
    if os.path.isfile(src_py):
        shutil.move(src_py, dst_py)
        print(f"  已迁移 selftest.py → tools/")
    if os.path.isdir(OLD) and not os.listdir(OLD):
        os.rmdir(OLD)
        print("  已删除空的 win-tools/")

    # 2) Windows 启动器：从 make_win_pkg 的常量取出，以 GBK 落地
    sys.path.insert(0, HERE)
    from make_win_pkg import SELFTEST_BAT        # noqa: E402
    dst_bat = os.path.join(TOOLS, "检查运行.bat")
    with open(dst_bat, "w", encoding="gbk", newline="\r\n") as f:
        f.write(SELFTEST_BAT)
    raw = open(dst_bat, "rb").read()
    try:
        raw.decode("gbk")
        gbk_ok = "GBK 校验 OK"
    except UnicodeDecodeError as e:
        gbk_ok = "GBK 校验失败！%s" % e
    print(f"  tools/检查运行.bat      {len(raw):>5} 字节  {gbk_ok}")

    # 3) macOS 启动器
    dst_cmd = os.path.join(TOOLS, "检查运行.command")
    with open(dst_cmd, "w", encoding="utf-8", newline="\n") as f:
        f.write(MAC_CMD)
    os.chmod(dst_cmd, 0o755)
    print(f"  tools/检查运行.command  {os.path.getsize(dst_cmd):>5} 字节  可执行位已设")
    print(f"  tools/selftest.py       {os.path.getsize(dst_py):>5} 字节")
    print()
    print("  完成。注意：.command 从**网上下载的 zip** 里解压出来会带 quarantine 属性，")
    print("  双击可能提示「无法验证开发者」—— 右键 → 打开，放行一次即可。")


if __name__ == "__main__":
    main()
