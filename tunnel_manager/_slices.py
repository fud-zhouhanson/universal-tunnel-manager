# -*- coding: utf-8 -*-
"""tunnel_manager._slices — 切片清单与拼装（开发期入口与构建脚本共用这一份实现）

为什么需要它：
  本项目对外只交付**单文件** `tunnel-manager.py`（用户双击即用，这是产品卖点）。
  源码侧按章节拆成若干切片，但切片之间是**单一扁平命名空间**里的互相调用，不是 import
  关系（471 处跨切片引用里存在 10 组循环依赖，硬拆 import 会直接 ImportError）。
  所以「怎么跑」和「怎么打包」归结为同一件事：按 SLICES 顺序把各切片正文用换行拼起来。

  · 开发期：`python -m tunnel_manager.main` → 拼起来 exec 进一个命名空间执行
  · 构建期：`python bundle.py`              → 拼起来写成 dist/tunnel-manager.py（纯源码，无 exec）
"""

import os

PKG_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(PKG_DIR)

# 切片头部与正文的分界标记（bundle / main 都从这里往后取正文）
SLICE_MARK = ">>>SLICE_BODY<<<"

# 顺序 = 迁移前 server.py 的书写顺序，不可随意调整：
# 顶层既有定义也有依赖，顺序变了行为就可能变。_base 放最前（shebang/docstring/import/全局常量）。
SLICES = (
    "_base",
    "consts",
    "util",
    "detect/process",
    "detect/iface",
    "detect/route",
    "config",
    "detect/judge",
    "outlet/scene",
    "outlet/manager",
    "win/native",
    "health/flow",
    "steam/diagnose",
    "health/flowrate",
    "detect/scan",
    "outlet/routes",
    "web/httpd",
    "entry",
)


def slice_path(mod, root=None):
    return os.path.join(root or PKG_DIR, *mod.split("/")) + ".py"


def read_slice(mod, root=None):
    """取一个切片的正文（剥掉仅供人读的头部）。_base 无标记，逐字返回。"""
    with open(slice_path(mod, root), encoding="utf-8") as f:
        text = f.read()
    if mod == "_base":
        return text[:-1] if text.endswith("\n") else text
    if SLICE_MARK not in text:
        raise ValueError(f"{mod}.py 缺少切片标记 {SLICE_MARK}")
    body = text.split(SLICE_MARK, 1)[1]
    if body.startswith("\n"):
        body = body[1:]
    if body.endswith("\n"):
        body = body[:-1]
    return body


def assemble(root=None):
    """把所有切片拼成一份源码（内容等价于迁移前的 server.py）。"""
    return "\n".join(read_slice(m, root) for m in SLICES)
