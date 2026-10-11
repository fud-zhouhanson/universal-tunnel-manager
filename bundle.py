#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""bundle.py — 把 tunnel_manager/ 拼成单文件分发版 dist/tunnel-manager.py

单文件是本项目的产品特性（用户双击 .bat / .command 就跑它），所以源码拆包后必须在
构建期拼回去。拼接逻辑与开发期入口共用 tunnel_manager/_slices.py，不搞两套实现。

用法：
    python3 bundle.py                       # 生成 dist/tunnel-manager.py
    python3 bundle.py --verify <参照文件>    # 额外校验：拼回结果必须与参照文件逐字节一致
                                            # （P1 搬家时的证明手段，平时用不到）
"""

import base64
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from tunnel_manager._slices import assemble  # noqa: E402

DIST = os.path.join(HERE, "dist")
HTML = os.path.join(HERE, "index.html")
OUT_PY = os.path.join(DIST, "tunnel-manager.py")

# 单文件分发版靠这个占位符把 index.html 内嵌进去
MARKER = "EMBEDDED_HTML = None"


def build_into(out_py=OUT_PY, verify_against=None):
    """拼装切片 → 内嵌 HTML → 落盘。返回产物路径。"""
    src = assemble()

    if verify_against:
        if not os.path.isfile(verify_against):
            sys.exit(f"找不到参照文件：{verify_against}")
        with open(verify_against, encoding="utf-8") as f:
            orig = f.read()
        if src != orig:
            sys.exit(f"★ 拼回结果与 {verify_against} 不一致 —— 搬家过程改了内容，拒绝产出")

    if MARKER not in src:
        sys.exit(f"源码里找不到占位符：{MARKER}")

    with open(HTML, encoding="utf-8") as f:
        html = f.read()
    # base64 存储，避免 HTML 里的引号 / 反斜杠 / 三引号与 Python 源码冲突
    b64 = base64.b64encode(html.encode("utf-8")).decode("ascii")
    out = src.replace(
        MARKER,
        'EMBEDDED_HTML = __import__("base64").b64decode(' + f'"{b64}").decode("utf-8")',
        1,
    )

    os.makedirs(os.path.dirname(out_py), exist_ok=True)
    with open(out_py, "w", encoding="utf-8") as f:
        f.write(out)
    os.chmod(out_py, 0o755)
    return out_py


def main():
    args = sys.argv[1:]
    verify = None
    if "--verify" in args:
        i = args.index("--verify")
        verify = args[i + 1] if i + 1 < len(args) else None
    path = build_into(verify_against=verify)
    print(f"bundle 完成：{path}  ({os.path.getsize(path) / 1024:.0f} KB)")


if __name__ == "__main__":
    main()
