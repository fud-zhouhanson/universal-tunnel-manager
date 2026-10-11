#!/usr/bin/env python3
"""
build.py — 把 tunnel_manager/ 包 + index.html 打包成单文件分发版

用法：
    python3 build.py

产物：
    dist/tunnel-manager.py   单文件版，不再依赖外部 index.html
    dist/tunnel-manager.zip  压缩包，方便下载

单文件组装本身在 bundle.py（它与开发期入口共用 tunnel_manager/_slices.py，
不搞两套实现）；本脚本只负责「组装 + 补上随包分发的辅助文件 + 打 zip」。
"""

import os
import sys
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
PKG = os.path.join(HERE, "tunnel_manager")
HTML = os.path.join(HERE, "index.html")
DIST = os.path.join(HERE, "dist")
OUT_PY = os.path.join(DIST, "tunnel-manager.py")
OUT_ZIP = os.path.join(DIST, "tunnel-manager.zip")

sys.path.insert(0, HERE)
import bundle  # noqa: E402


def main():
    if not os.path.isdir(PKG):
        sys.exit("找不到 tunnel_manager/ 包")
    if not os.path.isfile(HTML):
        sys.exit("找不到 index.html")

    bundle.build_into(OUT_PY)

    # zip 包：主程序 + 双平台安装脚本 + 双平台自检工具 + 说明
    extras = {
        "install.sh": os.path.join(DIST, "install.sh"),
        "install.bat": os.path.join(DIST, "install.bat"),
        # 自检工具：两个平台各一个「双击就行」的入口，共用同一个 selftest.py。
        # 注意 检查运行.bat 在仓库里就是 GBK —— cmd 按当前代码页解析批处理，
        # 存 UTF-8 会让中文提示变乱码（详见 tools/ 的说明）。
        "selftest.py": os.path.join(HERE, "tools", "selftest.py"),
        "检查运行.command": os.path.join(HERE, "tools", "检查运行.command"),
        "检查运行.bat": os.path.join(HERE, "tools", "检查运行.bat"),
    }
    readme = (
        "通用隧道管理 · Universal Tunnel Manager\n"
        "=====================================\n\n"
        "一个本机网页，自动识别并切换本机所有 VPN / 加速器 / 代理(梯子) /\n"
        "覆盖网络隧道。macOS、Windows 通用。\n\n"
        "【安装】\n"
        "  macOS：  双击 install.sh（或终端 bash install.sh）\n"
        "  Windows：双击 install.bat（需要系统里有 Python 3）\n"
        "           如果没装 Python，请改用「Windows 免安装版」那个包\n"
        "  装完桌面会出现「隧道管理」快捷方式，双击即用。\n\n"
        "【跑不起来 / 想先体检一下】\n"
        "  macOS：  双击 检查运行.command\n"
        "  Windows：双击 检查运行.bat\n"
        "  它会做一遍全面自检并生成「检查报告.txt」，把那个文件发回来就能定位问题。\n"
        "  检查是只读的：不改路由、不动 DNS、不装任何东西。\n"
        "  （macOS 上如果提示「无法验证开发者」，右键 →「打开」，放行一次即可）\n\n"
        "【启动后】\n"
        "  自动打开浏览器 http://127.0.0.1:7531 （只绑本机，别人访问不了）\n\n"
        "【卸载】\n"
        "  macOS：  rm -rf ~/.tunnel-manager ~/Desktop/隧道管理.command\n"
        "  Windows：删除 %USERPROFILE%\\.tunnel-manager 和桌面快捷方式\n"
    )
    with zipfile.ZipFile(OUT_ZIP, "w", zipfile.ZIP_DEFLATED) as z:
        z.write(OUT_PY, arcname="tunnel-manager.py")
        for name, path in extras.items():
            if os.path.isfile(path):
                z.write(path, arcname=name)
            else:
                print(f"  [警告] 缺少 {path}，跳过")
        z.writestr("README.txt", readme)

    print("构建完成：")
    print(f"  {OUT_PY}  ({os.path.getsize(OUT_PY) / 1024:.0f} KB)")
    print(f"  {OUT_ZIP} ({os.path.getsize(OUT_ZIP) / 1024:.0f} KB)")


if __name__ == "__main__":
    main()
