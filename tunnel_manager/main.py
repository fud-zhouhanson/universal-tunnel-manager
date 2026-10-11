# -*- coding: utf-8 -*-
"""tunnel_manager.main — 开发期入口

用法：

    python3 -m tunnel_manager.main

行为与单文件产物一致。唯一差别：这里的 index.html 在**仓库根目录**（单文件版在程序
自己所在目录），所以加载后把 BASE_DIR 指回仓库根 —— 这样开发期「改完 HTML 刷新浏览器
即生效」照样可用（get_html() 优先读 BASE_DIR 下的 index.html）。
"""

import os

from ._slices import PKG_DIR, ROOT_DIR, assemble


def run():
    ns = {
        "__name__": "__tm_app__",  # 不设 __main__，避免 entry 切片里的守卫重复触发
        "__file__": os.path.join(PKG_DIR, "_base.py"),
        "__package__": None,
    }
    exec(compile(assemble(), "<tunnel_manager>", "exec"), ns)
    ns["BASE_DIR"] = ROOT_DIR  # 见模块 docstring
    ns["main"]()


if __name__ == "__main__":
    run()
