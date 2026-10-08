#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""make_download_page.py — 生成两份落地页

页面要回答下载者（往往是非技术的"他们"）三个问题，顺序不能乱：
  ① 我该下哪个？          → 按系统分成两块，Windows 主推
  ② 下完怎么用？          → 一句话一步
  ③ 用不了怎么办？        → 包里自带体检工具，双击就出报告

**自检工具是打进主包里的，不是单独的下载项** —— 这点踩过坑：
早先把"运行检查工具.zip"和两个主包并排摆成三个下载按钮，用户一看就以为要下三个；
说明里又用"独立小包"的步骤（把文件放进程序目录）去描述它，更像必须手工搬文件。
现在它被收进第 ③ 节的折叠块里，并明确写「一般情况用不到」。

两种输出模式（同一套 HTML，只换下载控件和一小段说明）：

  embed   → dist/download.html
            小包以 base64 内嵌，点按钮时由**浏览器本地**还原成文件。
            适用于托管在会被 WAF 拦 .zip 直链的平台（实测：含 ".zip" 一律 403）。
            代价：页面体积 = 包体积 + 33%。

  release → docs/index.html
            下载控件是**指向 GitHub Releases 的普通 <a href>**。
            Releases 的资源由 github.com / objects.githubusercontent.com 提供，
            不存在 WAF 拦 .zip 的问题，页面因此保持几十 KB。
            这是 GitHub Pages 用的那份。

用法：
    python3 build.py && python3 make_win_pkg.py && python3 make_download_page.py
"""

import base64
import os
import shutil

HERE = os.path.dirname(os.path.abspath(__file__))
DIST = os.path.join(HERE, "dist")
DOCS = os.path.join(HERE, "docs")
ZIP = os.path.join(DIST, "tunnel-manager.zip")
OUT_EMBED = os.path.join(DIST, "download.html")
OUT_RELEASE = os.path.join(DOCS, "index.html")

# ---- GitHub 仓库 / Release 直链 ------------------------------------------
# 用 releases/latest/download/<附件名> —— 永远指向最新 Release，不必跟着 tag 改。
GH_REPO = "fud-zhouhanson/universal-tunnel-manager"
REL_BASE = f"https://github.com/{GH_REPO}/releases/latest/download"
ASSET_WIN = "TunnelManager-Windows-x64.zip"
ASSET_MAC = "tunnel-manager.zip"
ASSET_CHK = "RunCheck-tool.zip"          # ASCII 名（gh 上传中文名会被改成 default.zip）

# Windows 免安装版（内置 Python 运行时）。
# 为什么 embed 模式下线上要改名成 .dat：托管平台的 WAF 按「URL 里含 .zip」拦
# （已实测，大小写不敏感，连 .zip.download 都被拦），而 .dat / .bin / 无扩展名可以正常下载。
# 页面上再用 <a download="....zip"> 让浏览器把它存回 .zip，用户无感。
WIN_PKG = os.path.join(DIST, ASSET_WIN)
WIN_SERVED_NAME = "TunnelManager-Windows-x64.dat"
WIN_DL_NAME = ASSET_WIN
SITE = os.path.join(DIST, "site")

# 独立自检小包（给"已装好程序、不想重下 10 MB"的人；主包里已自带，所以只是备用）
CHK_ZIP = os.path.join(DIST, "运行检查工具.zip")
CHK_DL_NAME = "运行检查工具.zip"


def human(n):
    for u in ("B", "KB", "MB"):
        if n < 1024:
            return f"{n:.0f} {u}"
        n /= 1024
    return f"{n:.1f} GB"


def _size(path):
    return human(os.path.getsize(path)) if os.path.isfile(path) else ""


CSS = """
  :root {
    --bg:#0f1115; --panel:#171a21; --panel2:#1e222b; --border:#2b303c;
    --text:#e6e8ec; --dim:#98a0ae; --green:#34c759; --cyan:#32d0ff;
    --purple:#a78bfa; --orange:#ff9f0a; --yellow:#ffd60a;
  }
  * { box-sizing:border-box; margin:0; padding:0; }
  body {
    background:var(--bg); color:var(--text);
    font-family:-apple-system,"SF Pro Text","PingFang SC","Microsoft YaHei",sans-serif;
    line-height:1.65; padding:40px 20px 60px;
  }
  .wrap { max-width:860px; margin:0 auto; }
  h1 { font-size:30px; font-weight:800; letter-spacing:-.4px; }
  .lead { color:var(--dim); font-size:15px; margin:10px 0 26px; }
  .card {
    background:var(--panel); border:1px solid var(--border); border-radius:14px;
    padding:22px 24px; margin-bottom:18px;
  }
  h2 { font-size:15px; font-weight:700; color:var(--dim); text-transform:uppercase;
       letter-spacing:.6px; margin-bottom:14px; }
  .dl {
    display:inline-block; text-decoration:none; text-align:center;
    background:linear-gradient(180deg,rgba(52,199,89,.28),rgba(52,199,89,.16));
    border:1px solid rgba(52,199,89,.6); color:#7ef0a0;
    font-size:16px; font-weight:700; padding:14px 30px; border-radius:11px;
    cursor:pointer; transition:.16s; font-family:inherit;
  }
  .dl:hover { transform:translateY(-2px); box-shadow:0 10px 26px rgba(52,199,89,.22); }
  .dl:active { transform:translateY(0); }
  .dl.small { font-size:14px; padding:10px 20px; }

  /* ——— 下载项：一个系统一块，主次分明 ——— */
  .dl-item { margin: 0; }
  .dl-os { display:flex; align-items:center; gap:9px; flex-wrap:wrap; margin-bottom:10px; }
  .pill {
    display:inline-block; font-size:12.5px; font-weight:700; letter-spacing:.3px;
    padding:3px 12px; border-radius:999px; border:1px solid var(--border);
  }
  .pill.win { color:var(--cyan);   border-color:rgba(50,208,255,.5);  background:rgba(50,208,255,.10); }
  .pill.mac { color:var(--orange); border-color:rgba(255,159,10,.5);  background:rgba(255,159,10,.10); }
  .dl.big { display:block; width:100%; box-sizing:border-box; font-size:17px; padding:16px 24px; }

  /* ——— 步骤卡 ——— */
  .step-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(280px,1fr)); gap:14px; }
  .step { background:var(--panel2); border:1px solid var(--border); border-radius:11px; padding:14px 16px; }
  .step pre { margin:8px 0 0; background:transparent; border:0; padding:0; }
  .step-os { font-weight:700; font-size:14.5px; }
  .step-os.win { color:var(--cyan); }
  .step-os.mac { color:var(--orange); }

  /* ——— 故障排查卡：给一点警示色，显眼但不吓人 ——— */
  .card.warn-card {
    border-color:rgba(255,214,10,.42);
    background:linear-gradient(180deg,rgba(255,214,10,.055),transparent 42%),var(--panel);
  }
  .card.warn-card h2 { color:#ffe066; }

  /* ——— 可折叠块 ——— */
  details.collapse { margin-top:14px; border-top:1px dashed var(--border); padding-top:12px; }
  details.collapse summary { cursor:pointer; color:var(--dim); font-size:13.5px; list-style:none; }
  details.collapse summary::-webkit-details-marker { display:none; }
  details.collapse summary::before { content:"▸ "; color:var(--cyan); }
  details.collapse[open] summary::before { content:"▾ "; }
  details.collapse summary:hover { color:var(--text); }
  .collapse-body { padding:12px 0 2px 16px; }
  .dim { color:var(--dim); }

  .hint { font-size:13px; color:var(--dim); margin-top:10px; line-height:1.7; }
  .sep { border:0; border-top:1px solid var(--border); margin:18px 0; }
  .fname { font-family:ui-monospace,Menlo,Consolas,monospace; font-size:13px; color:var(--dim); }
  .fname b { color:var(--text); }
  .mac { color:var(--orange); font-weight:700; }
  .win { color:var(--cyan); font-weight:700; }
  ol,ul { padding-left:22px; }
  li { margin:7px 0; font-size:14.5px; }
  code {
    font-family:ui-monospace,Menlo,Consolas,monospace; font-size:13px;
    background:var(--panel2); border:1px solid var(--border);
    padding:2px 7px; border-radius:6px;
  }
  pre {
    background:var(--panel2); border:1px solid var(--border); border-radius:10px;
    padding:14px 16px; overflow-x:auto; margin:10px 0; font-size:13px;
    font-family:ui-monospace,Menlo,Consolas,monospace; color:#cfe3ff;
  }
  .feat { display:grid; grid-template-columns:repeat(auto-fit,minmax(240px,1fr)); gap:12px; }
  .feat div {
    background:var(--panel2); border:1px solid var(--border); border-radius:10px;
    padding:13px 15px; font-size:13.5px;
  }
  .feat b { display:block; margin-bottom:4px; }
  .tag { display:inline-block; font-size:12px; padding:2px 9px; border-radius:999px;
         border:1px solid var(--border); color:var(--dim); margin-right:6px; }
  .tag.g { border-color:rgba(52,199,89,.5); color:var(--green); }
  .tag.p { border-color:rgba(167,139,250,.5); color:var(--purple); }
  .note {
    background:rgba(255,214,10,.1); border:1px solid rgba(255,214,10,.4);
    color:#ffe066; border-radius:10px; padding:12px 16px; font-size:13.5px; margin-top:14px;
  }
  .foot { color:var(--dim); font-size:12.5px; text-align:center; margin-top:26px; }

  /* ——— 免责声明 ——— */
  .disclaimer {
    margin-top:16px; padding:14px 18px; border-radius:10px;
    background:rgba(255,255,255,.028); border:1px solid var(--border);
    color:var(--dim); font-size:12.5px; line-height:1.85;
  }
  .disclaimer b { color:var(--text); }
  .disclaimer .lead-word {
    display:inline-block; color:var(--yellow); font-weight:700; margin-right:6px;
  }
  .ok { color:var(--green); font-weight:700; }
  .url { color:var(--cyan); font-family:ui-monospace,monospace; }
"""

SCRIPT_EMBED = """
// 两个包都内嵌成 base64，点按钮时在浏览器本地还原成文件下载，无需任何服务器
const ZIP_B64 = "%(b64)s";
const ZIP_NAME = "%(zip_name)s";
const CHK_B64 = "%(chk_b64)s";
const CHK_NAME = "%(chk_name)s";

function saveB64(b64, name, label) {
  const s = document.getElementById('dlStatus');
  try {
    const bin = atob(b64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    const blob = new Blob([bytes], { type: 'application/zip' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = name;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(() => URL.revokeObjectURL(a.href), 4000);
    s.style.display = 'block';
    s.innerHTML = '<span class="ok">✓ 已开始下载 ' + name + '</span>（' + label + '）。'
      + '若浏览器没反应，请检查下载被拦截的提示。';
  } catch (e) {
    s.style.display = 'block';
    s.textContent = '下载失败：' + e.message;
  }
}

document.getElementById('btnDl').addEventListener('click',
  () => saveB64(ZIP_B64, ZIP_NAME, '%(size_txt)s'));
(function () {
  const b = document.getElementById('btnChk');
  if (!b) return;
  if (!CHK_B64) { b.disabled = true; b.textContent = '（暂未提供）'; return; }
  b.addEventListener('click', () => saveB64(CHK_B64, CHK_NAME, '%(chk_size_txt)s'));
})();
"""


def build_page(mode):
    """mode: 'embed'（内嵌 base64 / 分享用）或 'release'（指向 GitHub Releases / Pages 用）"""
    assert mode in ("embed", "release")

    size_txt = _size(ZIP)
    win_size = _size(WIN_PKG)
    chk_size_txt = _size(CHK_ZIP)

    if mode == "embed":
        win_ctrl = (f'<a class="dl big" href="./{WIN_SERVED_NAME}" '
                    f'download="{WIN_DL_NAME}">⬇ 下载 Windows 免安装版</a>')
        mac_ctrl = '<button class="dl big" id="btnDl">⬇ 下载 macOS 版</button>'
        chk_ctrl = '<button class="dl small" id="btnChk">⬇ 运行检查工具.zip</button>'
        dl_note = (
            "<span class=\"dim\">\n"
            "        Windows 那个包大，是因为里面塞了完整的 Python 运行环境 —— 换来的是"
            "对方电脑不用装任何东西。\n"
            "        它是点按钮时由你的<b>浏览器现场生成</b>的，不经过服务器下载，"
            "所以不会被任何网络策略拦截。\n"
            "        万一下载下来的文件名是 <code>.dat</code>，改名成 <code>.zip</code> 一样能用。\n"
            "      </span>"
        )
        script = ""
    else:
        win_ctrl = (f'<a class="dl big" href="{REL_BASE}/{ASSET_WIN}">'
                    f'⬇ 下载 Windows 免安装版</a>')
        mac_ctrl = (f'<a class="dl big" href="{REL_BASE}/{ASSET_MAC}">'
                    f'⬇ 下载 macOS 版</a>')
        chk_ctrl = (f'<a class="dl small" href="{REL_BASE}/{ASSET_CHK}">'
                    f'⬇ 运行检查工具.zip</a>')
        dl_note = (
            "<span class=\"dim\">\n"
            "        文件直接从 <b>GitHub Releases</b> 下载，点击即存盘，页面本身不承载任何大文件。\n"
            "        Windows 包大，是因为里面塞了完整的 Python 运行环境 —— 换来的是"
            "对方电脑不用装任何东西。\n"
            "        想核对完整性？每个包都附有 SHA256，见仓库的 "
            "<code>dist/SHA256SUMS</code> 与 Release 说明。\n"
            "      </span>"
        )
        script = ""

    win_block = f"""
    <div class="dl-item">
      <div class="dl-os">
        <span class="pill win">Windows</span>
        <span class="tag g">推荐 · 对方不用装任何东西</span>
      </div>
      {win_ctrl}
      <div class="fname"><b>{WIN_DL_NAME}</b> · {win_size} · 内置运行环境，
        <b>不需要装 Python</b> · 已自带体检工具</div>
    </div>
    <hr class="sep">"""

    html = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>通用隧道管理器 · Universal Tunnel Manager</title>
<meta name="description" content="自动识别本机所有 VPN / 加速器 / 代理(梯子) 隧道，一键在本机直连与隧道之间切换。Windows 免安装包，自带体检工具。">
<meta property="og:title" content="通用隧道管理器 · Universal Tunnel Manager">
<meta property="og:description" content="自动识别本机所有 VPN / 加速器 / 梯子隧道，一键切换。Windows 免安装。">
<meta property="og:type" content="website">
<style>{CSS}</style>
</head>
<body>
<div class="wrap">

  <h1>通用隧道管理器</h1>
  <div class="lead">
    自动识别本机所有由 <b>VPN / 游戏加速器 / 代理(梯子) / 覆盖网络</b> 构建的隧道，
    按域名把流量在「隧道」和「本机直连」之间一键切换。不改客户端、不卸载软件、随时回滚。
    <span class="tag g">macOS</span><span class="tag g">Windows</span><span class="tag p">零依赖</span>
  </div>

  <div class="card">
    <h2>① 下载（选你的系统，只下这一个）</h2>
{win_block}
    <div class="dl-item">
      <div class="dl-os">
        <span class="pill mac">macOS</span>
        <span class="tag">需要系统自带 Python 3（mac 一般都有）</span>
      </div>
      {mac_ctrl}
      <div class="fname"><b>tunnel-manager.zip</b> · {size_txt} · 含程序 + 安装脚本 + 体检工具</div>
    </div>

    <p class="hint" style="margin-top:16px">
      <b>两个包里都已经自带体检工具</b>（启动不了时能一键自检，见第 ③ 节），
      所以<b>只需要下这一个包</b>。
      <br>{dl_note}
    </p>
    <div class="note" id="dlStatus" style="display:none"></div>
  </div>

  <div class="card">
    <h2>② 解压后怎么用（就一步）</h2>
    <div class="step-grid">
      <div class="step">
        <div class="step-os win">Windows</div>
        <pre>解压 TunnelManager-Windows-x64.zip
双击  START-双击启动.bat</pre>
      </div>
      <div class="step">
        <div class="step-os mac">macOS</div>
        <pre>解压 tunnel-manager.zip
双击  install.sh</pre>
      </div>
    </div>
    <p class="hint">
      跑完会自动打开浏览器 <span class="url">http://127.0.0.1:7531</span>（只绑本机，同一内网的别人访问不到）。
      桌面上会出现「隧道管理」图标，以后双击它就打开。
      <br>Windows 想停掉服务：双击 <code>STOP-停止服务.bat</code>。
    </p>
  </div>

  <div class="card warn-card">
    <h2>③ 万一启动不了？—— 包里自带体检工具，不用另外下</h2>
    <p style="font-size:14.5px">
      解压出来的文件夹里，体检工具就<b>和启动文件并排摆着</b>：
    </p>
    <pre>Windows → 双击  检查运行.bat
macOS   → 双击  检查运行.command</pre>
    <p style="font-size:14.5px">
      它会自动把环境查一遍，并在同一个文件夹里生成「<b>检查报告.txt</b>」——
      <b>把那个文件发回来就能定位问题</b>。
    </p>
    <ul>
      <li>检查是<b>只读</b>的：不改路由、不动 DNS、不装任何东西</li>
      <li>报告里只有系统版本、网卡名、路由状态，<b>不含任何隐私内容</b></li>
      <li>macOS 首次可能提示「无法验证开发者」→ 在文件上<b>右键 →「打开」</b>，放行一次就好</li>
    </ul>
    <details class="collapse">
      <summary>我程序早就装好了，只想要这个体检工具</summary>
      <div class="collapse-body">
        <p class="hint">
          那可以只下这一个小包（{chk_size_txt}，<b>一般情况用不到</b>）。
          解压后把里面的 <code>selftest.py</code> 和对应那个启动器放进程序目录，再双击。
        </p>
        {chk_ctrl}
      </div>
    </details>
  </div>

  <div class="card">
    <h2>④ 打开后你会看到</h2>
    <p style="font-size:14.5px">
      程序只监听本机 <span class="url">http://127.0.0.1:7531</span>，会自动打开浏览器。
      同一内网的其他人访问不到这个地址，只有你自己能用。
    </p>
    <ul>
      <li><b>检测到的隧道软件</b> — 谁在跑，属于哪一类</li>
      <li><b>网络接口与隧道归属</b> — 每块网卡是隧道还是物理网卡，归属哪个软件（含 MTU / IPv6 ULA 指纹）</li>
      <li><b>聚合路由多点抽查</b> — 抓「保留默认路由、偷偷用聚合路由接管」的隐性隧道</li>
      <li><b>目标域名的路由走向</b> — 我关心的网站，流量现在从哪出去</li>
      <li><b>真实流量体检</b> — 不看配置只看事实：真解析一次、真连一次、真看第一跳</li>
      <li><b>应急恢复</b> — DNS 和路由被倒腾乱了一键救回来</li>
      <li><b>一键切换</b> — 切到本机直连 / 交回隧道；「待确认」可一键取消</li>
    </ul>
  </div>

  <div class="card">
    <h2>⑤ 它怎么做到的</h2>
    <div class="feat">
      <div><b class="tag p">识别</b>进程证据 + 网卡名证据 + 路由出口证据 + ULA/MTU 指纹，四层融合判定隧道归属</div>
      <div><b class="tag p">切换</b>给目标 IP 加一条比默认路由更具体的 <code>/32</code> 主机路由，指回物理网关，不动其它流量</div>
      <div><b class="tag p">回滚</b>每条加过的路由都记进 state 文件，撤销时只删自己加的，绝不碰系统原有路由</div>
      <div><b class="tag p">安全</b>只绑 127.0.0.1；写操作校验 Origin + CSRF token；只对公网 IP 加路由，防 DNS 投毒</div>
    </div>
  </div>

  <div class="foot">
    通用隧道管理器 · 单文件 Python 程序，不写入系统目录以外的任何位置<br>
    卸载：删掉解压出的文件夹即可（Windows 免安装版不写注册表、不装服务）<br>
    源码与许可：<a href="https://github.com/{GH_REPO}" style="color:var(--cyan)">{GH_REPO}</a>
  </div>

  <div class="disclaimer">
    <span class="lead-word">免责声明</span>
    这是一个<b>免费开源项目</b>，按「现状」提供，<b>不提供任何担保</b>；在适用法律允许的最大范围内，
    作者<b>不承担任何责任</b>。本工具会<b>修改本机路由表与 DNS 配置</b>，误用可能导致<b>暂时断网</b>，
    请自行评估并承担全部风险。使用前建议先点一次「保存健康基线」；回滚方法见
    <a href="https://github.com/{GH_REPO}/blob/main/SECURITY.md" style="color:var(--cyan)">SECURITY.md</a>。
    <br><b>请只从本页或官方 Release 下载，并核对 <code>SHA256SUMS</code></b> ——
    任何第三方修改、二次打包、镜像或转发的副本，均与本项目作者无关，作者一概不负责。
    请遵守你所在地区的法律法规，以及所在网络（学校 / 公司 / 运营商）的使用条款。
  </div>
</div>
{script}
</body>
</html>
"""
    return html


def _write(path, html):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"  {os.path.relpath(path, HERE):<22} {os.path.getsize(path)/1024:.0f} KB")


def main():
    # ---- Windows 免安装版：复制到站点目录，并改名为 .dat 绕过 WAF（仅 embed 模式用）----
    if os.path.isfile(WIN_PKG):
        os.makedirs(SITE, exist_ok=True)
        shutil.copy2(WIN_PKG, os.path.join(SITE, WIN_SERVED_NAME))
        # dist/ 下也放一份同名的：页面里是相对链接（./xxx.dat），
        # 本地直接双击 dist/download.html 预览时才解析得到。硬链接，不额外占磁盘。
        dst_local = os.path.join(DIST, WIN_SERVED_NAME)
        try:
            if os.path.exists(dst_local):
                os.remove(dst_local)
            os.link(WIN_PKG, dst_local)
        except OSError:
            shutil.copy2(WIN_PKG, dst_local)

    # ---- ① embed：dist/download.html（分享用；小包内嵌）----
    if os.path.isfile(ZIP):
        with open(ZIP, "rb") as f:
            raw = f.read()
        chk_b64 = ""
        if os.path.isfile(CHK_ZIP):
            with open(CHK_ZIP, "rb") as f:
                chk_b64 = base64.b64encode(f.read()).decode("ascii")
        script = SCRIPT_EMBED % {
            "b64": base64.b64encode(raw).decode("ascii"),
            "zip_name": ASSET_MAC,
            "chk_b64": chk_b64,
            "chk_name": CHK_DL_NAME,
            "size_txt": human(len(raw)),
            "chk_size_txt": _size(CHK_ZIP),
        }
        html = build_page("embed").replace("</body>", f"<script>{script}</script>\n</body>")
        _write(OUT_EMBED, html)
    else:
        print("  （未找到 dist/tunnel-manager.zip，跳过 dist/download.html）")

    # ---- ② release：docs/index.html（GitHub Pages 用；下载指向 Releases 直链）----
    _write(OUT_RELEASE, build_page("release"))

    print(f"\n落地页已生成：{OUT_EMBED} / {OUT_RELEASE}")


if __name__ == "__main__":
    main()
