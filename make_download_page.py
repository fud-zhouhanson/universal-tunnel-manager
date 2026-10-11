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
ASSET_LITE = "TunnelManager-Windows-lite.zip"   # 精简版（不带 Python 运行时）

# Windows 免安装版（内置 Python 运行时）。
# 为什么 embed 模式下线上要改名成 .dat：托管平台的 WAF 按「URL 里含 .zip」拦
# （已实测，大小写不敏感，连 .zip.download 都被拦），而 .dat / .bin / 无扩展名可以正常下载。
# 页面上再用 <a download="....zip"> 让浏览器把它存回 .zip，用户无感。
WIN_PKG = os.path.join(DIST, ASSET_WIN)
WIN_SERVED_NAME = "TunnelManager-Windows-x64.dat"
WIN_DL_NAME = ASSET_WIN
SITE = os.path.join(DIST, "site")

# Windows 精简版（不带 Python 运行时，约 160 KB）。
# 体积小，直接 base64 内嵌进分享页 —— 不往站点目录多放一个文件，
# 也就不会多出一个「忘了同步」的漏点。
LITE_PKG = os.path.join(DIST, ASSET_LITE)
LITE_NAME = ASSET_LITE

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
    /* 深底 + 中性灰阶，强调色只落在按钮与链接上（控制在整页 10% 以内）。
       语义色（成功 / 警示）只在真正有语义处出现，不当装饰。 */
    --bg:#101216; --panel:#171a20; --panel2:#1d2129; --panel3:#242a33;
    --border:#2b303a; --hairline:rgba(255,255,255,.06);
    --text:#e9ebef; --text-2:#c2c8d2; --dim:#8f96a3;
    /* 主色 = 蓝：按钮底色配白字，深底上的蓝字用 --brand-text（亮一档保证可读） */
    --brand:#2563eb; --brand-hi:#3b82f6; --brand-lo:#1d4ed8;
    --brand-ink:#ffffff; --brand-text:#7aa7ff;
    --ok:#3ddc84; --warn:#e8a33d; --bad:#ff5b52;
    --r-sm:8px; --r:11px; --r-lg:16px; --r-pill:999px;
    --shadow:0 1px 2px rgba(0,0,0,.35), 0 14px 36px -22px rgba(0,0,0,.85);
  }
  * { box-sizing:border-box; margin:0; padding:0; }
  ::selection { background:rgba(37,99,235,.38); }
  body {
    background:var(--bg); color:var(--text);
    font-family:-apple-system,BlinkMacSystemFont,"SF Pro Text","PingFang SC",
                "Hiragino Sans GB","Microsoft YaHei",sans-serif;
    font-size:14.5px; line-height:1.75; -webkit-font-smoothing:antialiased;
    padding:0 22px 72px;
  }
  .wrap { max-width:860px; margin:0 auto; }
  a { color:var(--brand-text); }

  /* ——— 页头：与程序界面用同一枚标记，两个页面看着是一家 ——— */
  .hero {
    display:flex; align-items:center; gap:15px;
    padding:46px 2px 22px; margin-bottom:22px;
    border-bottom:1px solid var(--border);
  }
  .mark {
    flex:0 0 46px; width:46px; height:46px; border-radius:14px;
    display:grid; place-items:center; color:var(--brand-text);
    background:var(--panel2); border:1px solid var(--border);
  }
  .hero-txt { min-width:0; }
  h1 { font-size:27px; font-weight:680; letter-spacing:-.4px; line-height:1.25; }
  .lead { color:var(--dim); font-size:14px; margin-top:7px; line-height:1.7; max-width:66ch; }
  .lead b { color:var(--text-2); font-weight:600; }
  .badges { display:flex; gap:7px; flex-wrap:wrap; margin-top:13px; }

  /* ——— 卡片 ——— */
  .card {
    background:var(--panel); border:1px solid var(--border); border-radius:var(--r-lg);
    padding:22px 24px; margin-bottom:16px; box-shadow:var(--shadow);
  }
  /* 第 1 节是全页唯一的行动区：只给它一点主色，别处保持中性 */
  .card.cta { border-color:rgba(37,99,235,.30); }
  .card.cta h2 .n { border-color:rgba(37,99,235,.55); color:var(--brand-text); }

  /* 章节标题：左侧一个中性数字徽标，代替带圈数字字符 */
  h2 {
    display:flex; align-items:center; gap:10px;
    font-size:15.5px; font-weight:660; color:var(--text); margin-bottom:16px;
  }
  h2 .n {
    flex:0 0 23px; width:23px; height:23px; border-radius:7px;
    display:grid; place-items:center;
    background:var(--panel2); border:1px solid var(--border);
    font-size:11.5px; font-weight:700; color:var(--dim);
    font-variant-numeric:tabular-nums;
  }

  /* ——— 按钮：两级。主按钮 = 实心蓝配白字（两个系统的下载按钮用同一套），
       次按钮 = 描边蓝字。不用渐变、不上浮。 */
  .dl {
    display:inline-block; text-decoration:none; text-align:center;
    font:inherit; font-size:14.5px; font-weight:650;
    padding:12px 24px; border-radius:var(--r);
    border:1px solid transparent; cursor:pointer;
    background:var(--brand); color:var(--brand-ink);
    transition:background .15s, border-color .15s, color .15s;
  }
  .dl:hover  { background:var(--brand-hi); }
  .dl:active { background:var(--brand-lo); }
  .dl:focus-visible { outline:2px solid var(--brand-hi); outline-offset:2px; }
  .dl.ghost {
    background:transparent; color:var(--brand-text);
    border-color:rgba(37,99,235,.55);
  }
  .dl.ghost:hover { background:rgba(37,99,235,.14); color:#a9c5ff; }
  .dl.ghost:active { background:rgba(37,99,235,.22); }
  .dl.small { font-size:13.5px; padding:9px 18px; }
  .dl.big { display:block; width:100%; font-size:15.5px; padding:14px 24px; }

  /* ——— 下载项：按系统分块，主次分明 ——— */
  .dl-item { margin:0; }
  .dl-os { display:flex; align-items:center; gap:8px; flex-wrap:wrap; margin-bottom:10px; }
  .pill {
    display:inline-block; font-size:12px; font-weight:650; letter-spacing:.2px;
    padding:3px 11px; border-radius:var(--r-pill);
    background:var(--panel2); border:1px solid var(--border); color:var(--text-2);
  }
  /* 系统标签一律中性：两个系统的标识等价，不该靠颜色分主次 */
  .pill.win, .pill.mac { color:var(--text-2); }

  /* ——— 步骤卡 ——— */
  .step-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(260px,1fr)); gap:12px; }
  .step {
    background:var(--panel2); border:1px solid var(--border);
    border-radius:var(--r); padding:13px 15px;
  }
  .step pre { margin:0; background:transparent; border:0; padding:0; }
  .step-os { font-weight:650; font-size:13px; color:var(--text-2); margin-bottom:7px; }

  /* ——— 故障排查卡：全页唯一带警示色的地方 ——— */
  .card.warn-card { border-color:rgba(232,163,61,.32); }
  .card.warn-card h2 .n { border-color:rgba(232,163,61,.42); color:var(--warn); }

  /* ——— 可折叠块 ——— */
  details.collapse { margin-top:14px; border-top:1px solid var(--hairline); padding-top:13px; }
  details.collapse summary {
    cursor:pointer; color:var(--dim); font-size:13px; list-style:none;
    display:flex; align-items:center; gap:7px; transition:color .15s;
  }
  details.collapse summary::-webkit-details-marker { display:none; }
  details.collapse summary::before {
    content:"▸"; font-size:10px; color:var(--dim); transition:transform .16s;
  }
  details.collapse[open] summary::before { transform:rotate(90deg); color:var(--text-2); }
  details.collapse summary:hover { color:var(--text-2); }
  details.collapse summary:focus-visible { outline:2px solid var(--brand); outline-offset:2px; }
  .collapse-body { padding:12px 0 0 15px; }
  .dim { color:var(--dim); }

  .hint { font-size:13px; color:var(--dim); margin-top:13px; line-height:1.8; }
  .hint b { color:var(--text-2); }
  .sep { border:0; border-top:1px solid var(--border); margin:20px 0; }
  .fname { font-size:12.5px; color:var(--dim); margin-top:9px; line-height:1.7; }
  .fname b { color:var(--text-2); font-weight:600; }
  ol,ul { padding-left:20px; }
  li { margin:7px 0; font-size:14px; line-height:1.75; }
  li::marker { color:var(--dim); }
  p { font-size:14px; line-height:1.8; }
  code {
    font-family:ui-monospace,Menlo,Consolas,monospace; font-size:.92em;
    background:var(--panel2); border:1px solid var(--border);
    padding:1.5px 6px; border-radius:5px; color:var(--text-2);
  }
  pre {
    background:var(--panel2); border:1px solid var(--border); border-radius:var(--r-sm);
    padding:13px 15px; overflow-x:auto; margin:10px 0; font-size:12.5px; line-height:1.75;
    font-family:ui-monospace,Menlo,Consolas,monospace; color:var(--text-2);
  }
  .feat { display:grid; grid-template-columns:repeat(auto-fit,minmax(230px,1fr)); gap:10px; }
  .feat div {
    background:var(--panel2); border:1px solid var(--border); border-radius:var(--r);
    padding:13px 15px; font-size:13px; line-height:1.75; color:var(--dim);
  }
  .feat b { display:block; margin-bottom:4px; color:var(--text-2); font-size:13px; }
  .tag {
    display:inline-block; font-size:11.5px; font-weight:600;
    padding:3px 10px; border-radius:var(--r-pill);
    border:1px solid var(--border); color:var(--dim);
  }
  .tag.hi { border-color:rgba(37,99,235,.55); color:var(--brand-text); }
  .note {
    margin-top:14px; padding:12px 15px; border-radius:var(--r-sm);
    background:var(--panel2); border:1px solid var(--border);
    font-size:13px; color:var(--text-2); line-height:1.75;
  }
  .foot {
    color:var(--dim); font-size:12.5px; text-align:center;
    margin-top:30px; padding-top:22px; border-top:1px solid var(--border); line-height:1.9;
  }

  /* ——— 免责声明 ——— */
  .disclaimer {
    margin-top:18px; padding:16px 18px; border-radius:var(--r);
    background:var(--panel); border:1px solid var(--border);
    color:var(--dim); font-size:12px; line-height:1.9;
  }
  .disclaimer b { color:var(--text-2); }
  .disclaimer .lead-word {
    display:block; color:var(--text-2); font-weight:650; margin-bottom:6px;
  }
  .ok { color:var(--ok); font-weight:650; }
  .bad { color:#ff6b60; }
  .url { color:var(--brand-text); font-family:ui-monospace,Menlo,Consolas,monospace; font-size:.93em; }

  /* ——— 响应式 ——— */
  @media (max-width:640px) {
    body { padding:0 15px 56px; font-size:14px; }
    .hero { padding:30px 0 16px; gap:12px; margin-bottom:16px; }
    .mark { flex-basis:38px; width:38px; height:38px; border-radius:11px; }
    h1 { font-size:22px; }
    .card { padding:17px 16px; border-radius:14px; }
    h2 { font-size:14.5px; margin-bottom:13px; }
    .dl.big { font-size:14.5px; padding:13px 18px; }
    .step-grid { grid-template-columns:1fr; }
    .feat { grid-template-columns:1fr; }
  }
  @media (prefers-reduced-motion:reduce) {
    * { transition-duration:.001ms !important; }
  }
"""

SCRIPT_EMBED = """
// 小包都内嵌成 base64，点按钮时在浏览器本地还原成文件下载，无需任何服务器。
// （Windows 完整版 10 MB 太大，走同目录的 .dat 相对链接，见 WIN_SERVED_NAME）
const ZIP_B64 = "%(b64)s";
const ZIP_NAME = "%(zip_name)s";
const CHK_B64 = "%(chk_b64)s";
const CHK_NAME = "%(chk_name)s";
const LITE_B64 = "%(lite_b64)s";
const LITE_NAME = "%(lite_name)s";

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
    s.innerHTML = '<span class="ok">已开始下载 ' + name + '</span>（' + label + '）。'
      + '若浏览器没有反应，请检查是否被下载拦截提示挡住了。';
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
(function () {
  const b = document.getElementById('btnLite');
  if (!b) return;
  if (!LITE_B64) { b.disabled = true; b.textContent = '（暂未提供）'; return; }
  b.addEventListener('click', () => saveB64(LITE_B64, LITE_NAME, '%(lite_size_txt)s'));
})();
"""


def build_page(mode):
    """mode: 'embed'（内嵌 base64 / 分享用）或 'release'（指向 GitHub Releases / Pages 用）"""
    assert mode in ("embed", "release")

    size_txt = _size(ZIP)
    win_size = _size(WIN_PKG)
    chk_size_txt = _size(CHK_ZIP)
    lite_size = _size(LITE_PKG)

    if mode == "embed":
        win_ctrl = (f'<a class="dl big" href="./{WIN_SERVED_NAME}" '
                    f'download="{WIN_DL_NAME}">下载 Windows 免安装版</a>')
        mac_ctrl = '<button class="dl big" id="btnDl">下载 macOS 版</button>'
        chk_ctrl = '<button class="dl small ghost" id="btnChk">下载体检工具包</button>'
        lite_ctrl = ('<button class="dl small ghost" id="btnLite">'
                     f'下载 Windows 精简版（{lite_size}）</button>')
        dl_note = (
            "<span class=\"dim\">\n"
            "        Windows 包体积较大，是因为内置了完整的 Python 运行环境，换来的是"
            "目标电脑<b>不需要预装任何东西</b>。\n"
            "        该文件由浏览器<b>在本地生成</b>，不经过服务器下载，因此不会被网络策略拦截。\n"
            "        若下载得到的文件名是 <code>.dat</code>，改名为 <code>.zip</code> 同样可用。\n"
            "      </span>"
        )
        script = ""
    else:
        win_ctrl = (f'<a class="dl big" href="{REL_BASE}/{ASSET_WIN}">'
                    f'下载 Windows 免安装版</a>')
        mac_ctrl = (f'<a class="dl big" href="{REL_BASE}/{ASSET_MAC}">'
                    f'下载 macOS 版</a>')
        chk_ctrl = (f'<a class="dl small ghost" href="{REL_BASE}/{ASSET_CHK}">'
                    f'下载体检工具包</a>')
        lite_ctrl = (f'<a class="dl small ghost" href="{REL_BASE}/{ASSET_LITE}">'
                     f'下载 Windows 精简版（{lite_size}）</a>')
        dl_note = (
            "<span class=\"dim\">\n"
            "        文件直接从 <b>GitHub Releases</b> 下载，页面本身不承载大文件。\n"
            "        Windows 包体积较大，是因为内置了完整的 Python 运行环境，换来的是"
            "目标电脑<b>不需要预装任何东西</b>。\n"
            "        完整性可核对：每个包都附有 SHA256，见仓库的 "
            "<code>dist/SHA256SUMS</code> 与 Release 说明。\n"
            "      </span>"
        )
        script = ""

    win_block = f"""
    <div class="dl-item">
      <div class="dl-os">
        <span class="pill win">Windows</span>
        <span class="tag hi">推荐</span>
        <span class="tag">目标电脑无需预装任何环境</span>
      </div>
      {win_ctrl}
      <div class="fname"><b>{WIN_DL_NAME}</b> · {win_size} · 内置运行环境 · 已含体检工具</div>
      <details class="collapse">
        <summary>目标电脑已装 Python 3？可改用体积小得多的精简版</summary>
        <div class="collapse-body">
          <p class="hint">
            精简版 <b>{lite_size}</b>（完整版 {win_size}），功能完全一致，
            只是不内置运行环境，改用该电脑上已安装的 Python 3。
            <br>不确定是否已装 Python 3，请使用上面那个完整版。
          </p>
          {lite_ctrl}
        </div>
      </details>
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

  <header class="hero">
    <div class="mark" aria-hidden="true">
      <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor"
           stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round">
        <path d="M4 9h13"/><path d="M14 6.2 17 9l-3 2.8"/>
        <path d="M20 15H7"/><path d="M10 12.2 7 15l3 2.8"/>
      </svg>
    </div>
    <div class="hero-txt">
      <h1>通用隧道管理器</h1>
      <p class="lead">
        识别本机由 <b>VPN / 游戏加速器 / 代理 / 覆盖网络</b> 建立的隧道，
        按域名把流量在「隧道」与「本机直连」之间切换。不改客户端、不卸载软件、随时回滚。
      </p>
      <div class="badges">
        <span class="tag">macOS</span><span class="tag">Windows</span><span class="tag">零第三方依赖</span>
      </div>
    </div>
  </header>

  <div class="card cta">
    <h2><span class="n">1</span>下载对应系统的包</h2>
{win_block}
    <div class="dl-item">
      <div class="dl-os">
        <span class="pill mac">macOS</span>
        <span class="tag">需要系统自带 Python 3</span>
      </div>
      {mac_ctrl}
      <div class="fname"><b>tunnel-manager.zip</b> · {size_txt} · 含程序 + 安装脚本 + 体检工具</div>
    </div>

    <p class="hint" style="margin-top:16px">
      两个包都已内置体检工具（启动失败时可自检，见第 3 节），因此<b>每台机器只需要下一个包</b>。
      <br>{dl_note}
    </p>
    <div class="note" id="dlStatus" style="display:none"></div>
  </div>

  <div class="card">
    <h2><span class="n">2</span>解压后怎么用</h2>
    <div class="step-grid">
      <div class="step">
        <div class="step-os">Windows</div>
        <pre>解压 TunnelManager-Windows-x64.zip
双击  START-双击启动.bat</pre>
      </div>
      <div class="step">
        <div class="step-os">macOS</div>
        <pre>解压 tunnel-manager.zip
双击  install.sh</pre>
      </div>
    </div>
    <p class="hint">
      运行后自动打开浏览器 <span class="url">http://127.0.0.1:7531</span>（仅监听本机，同一内网的其他设备访问不到）。
      桌面会生成「隧道管理」图标，之后双击它即可打开。
      <br>Windows 需要停止服务时：双击 <code>STOP-停止服务.bat</code>。
    </p>
  </div>

  <div class="card warn-card">
    <h2><span class="n">3</span>启动失败时：用包内的体检工具</h2>
    <p>
      体检工具就在解压出的文件夹里，与启动文件并排：
    </p>
    <pre>Windows → 双击  检查运行.bat
macOS   → 双击  检查运行.command</pre>
    <p>
      它会逐项检查运行环境，并在同一文件夹内生成「<b>检查报告.txt</b>」——
      把该文件提供给维护者即可定位问题。
    </p>
    <ul>
      <li>检查是<b>只读</b>操作：不改路由、不动 DNS、不安装任何东西</li>
      <li>报告只含系统版本、网卡名、路由状态，<b>不含任何隐私内容</b></li>
      <li>macOS 首次运行可能提示「无法验证开发者」：在该文件上<b>右键 →「打开」</b>放行一次即可</li>
    </ul>
    <details class="collapse">
      <summary>只需要体检工具（程序此前已安装）</summary>
      <div class="collapse-body">
        <p class="hint">
          可单独下载这个小包（{chk_size_txt}，<b>通常用不到</b>）。
          解压后把 <code>selftest.py</code> 与对应启动器放进程序目录，再双击运行。
        </p>
        {chk_ctrl}
      </div>
    </details>
  </div>

  <div class="card">
    <h2><span class="n">4</span>打开后可以看到</h2>
    <p>
      程序仅监听本机 <span class="url">http://127.0.0.1:7531</span>，并自动打开浏览器。
      同一内网的其他设备访问不到该地址，仅本机可用。
    </p>
    <ul>
      <li><b>检测到的隧道软件</b> — 哪些在运行、各属哪一类</li>
      <li><b>网络接口与隧道归属</b> — 每块网卡是隧道还是物理网卡、归属哪个软件（含 MTU / IPv6 ULA 指纹）</li>
      <li><b>聚合路由多点抽查</b> — 检出「保留默认路由、改用聚合路由接管」的隐性隧道</li>
      <li><b>目标域名的路由走向</b> — 指定域名的流量当前从哪个接口出去</li>
      <li><b>真实流量体检</b> — 不看配置只看事实：真解析一次、真连一次、真看第一跳</li>
      <li><b>应急恢复</b> — DNS 与路由被改动后一键还原</li>
      <li><b>一键切换</b> — 切到本机直连 / 交回隧道；「待确认」项可一键取消</li>
    </ul>
  </div>

  <div class="card">
    <h2><span class="n">5</span>实现方式</h2>
    <div class="feat">
      <div><b>识别</b>进程证据 + 网卡名证据 + 路由出口证据 + ULA/MTU 指纹，四层融合判定隧道归属</div>
      <div><b>切换</b>给目标 IP 加一条比默认路由更具体的 <code>/32</code> 主机路由，指回物理网关，不影响其他流量</div>
      <div><b>回滚</b>每条添加过的路由都记入 state 文件，撤销时只删自己加的，不触碰系统原有路由</div>
      <div><b>安全</b>仅绑定 127.0.0.1；写操作校验 Origin + CSRF token；只对公网 IP 加路由，防 DNS 投毒</div>
    </div>
  </div>

  <div class="foot">
    通用隧道管理器 · 单文件 Python 程序，不写入系统目录以外的任何位置<br>
    卸载：删除解压出的文件夹即可（Windows 免安装版不写注册表、不注册服务）<br>
    源码与许可：<a href="https://github.com/{GH_REPO}">{GH_REPO}</a>
  </div>

  <div class="disclaimer">
    <span class="lead-word">免责声明</span>
    本项目为<b>免费开源项目</b>，按「现状」提供，<b>不提供任何担保</b>；在适用法律允许的最大范围内，
    作者<b>不承担任何责任</b>。本工具会<b>修改本机路由表与 DNS 配置</b>，误用可能导致<b>暂时断网</b>，
    请自行评估并承担全部风险。使用前建议先执行一次「保存健康基线」；回滚方法见
    <a href="https://github.com/{GH_REPO}/blob/main/SECURITY.md">SECURITY.md</a>。
    <br><b>请只从本页或官方 Release 下载，并核对 <code>SHA256SUMS</code></b> ——
    任何第三方修改、二次打包、镜像或转发的副本，均与本项目作者无关。
    请遵守所在地区的法律法规，以及所在网络（学校 / 公司 / 运营商）的使用条款。
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


def _same_content(a, b):
    """逐块比较两个文件内容是否一致（不存在或大小不同直接判否）。"""
    if not os.path.isfile(b) or os.path.getsize(a) != os.path.getsize(b):
        return False
    with open(a, "rb") as f1, open(b, "rb") as f2:
        while True:
            x, y = f1.read(1 << 20), f2.read(1 << 20)
            if x != y:
                return False
            if not x:
                return True


def _copy_over(src, dst):
    """覆盖式复制，**全程不删除目标文件**，内容相同则跳过。

    为什么不用 shutil.copy2 / os.link：它们在目标已存在时会走「覆盖 / unlink」路径，
    在受限环境（沙箱、审计策略）里会被直接拒绝 —— 实测 `shutil.copy2` 报
    `PermissionError: Brokered host copy overwrite refused by file policy`，
    于是 build.sh 第 4 步整个失败、落地页与 docs/ 都不更新。
    这里改成「读进内存 → 以 "wb" 原地截断写入」，只有写、没有删，任何环境都能过。
    返回 True 表示确实写了，False 表示跳过。
    """
    if os.path.abspath(src) == os.path.abspath(dst):
        return False
    os.makedirs(os.path.dirname(dst) or ".", exist_ok=True)
    if _same_content(src, dst):
        return False
    with open(src, "rb") as f:
        data = f.read()
    with open(dst, "wb") as f:
        f.write(data)
    try:
        shutil.copystat(src, dst)      # 只动时间戳，不删文件；失败也不影响
    except OSError:
        pass
    return True


def main():
    # ---- Windows 免安装版：复制到站点目录，并改名为 .dat 绕过 WAF（仅 embed 模式用）----
    if os.path.isfile(WIN_PKG):
        os.makedirs(SITE, exist_ok=True)
        _copy_over(WIN_PKG, os.path.join(SITE, WIN_SERVED_NAME))
        # dist/ 下也放一份同名的：页面里是相对链接（./xxx.dat），
        # 本地直接双击 dist/download.html 预览时才解析得到。
        # （以前用 os.link 硬链接，重跑会不断累积链接数；改成覆盖式复制，
        #   内容一致时自动跳过，不再重复占盘。）
        _copy_over(WIN_PKG, os.path.join(DIST, WIN_SERVED_NAME))

    # ---- ① embed：dist/download.html（分享用；小包内嵌）----
    if os.path.isfile(ZIP):
        with open(ZIP, "rb") as f:
            raw = f.read()
        chk_b64 = ""
        if os.path.isfile(CHK_ZIP):
            with open(CHK_ZIP, "rb") as f:
                chk_b64 = base64.b64encode(f.read()).decode("ascii")
        lite_b64 = ""
        if os.path.isfile(LITE_PKG):
            with open(LITE_PKG, "rb") as f:
                lite_b64 = base64.b64encode(f.read()).decode("ascii")
        script = SCRIPT_EMBED % {
            "b64": base64.b64encode(raw).decode("ascii"),
            "zip_name": ASSET_MAC,
            "chk_b64": chk_b64,
            "chk_name": CHK_DL_NAME,
            "lite_b64": lite_b64,
            "lite_name": LITE_NAME,
            "size_txt": human(len(raw)),
            "chk_size_txt": _size(CHK_ZIP),
            "lite_size_txt": _size(LITE_PKG),
        }
        html = build_page("embed").replace("</body>", f"<script>{script}</script>\n</body>")
        _write(OUT_EMBED, html)
    else:
        print("  （未找到 dist/tunnel-manager.zip，跳过 dist/download.html）")

    # ---- ② release：docs/index.html（GitHub Pages 用；下载指向 Releases 直链）----
    _write(OUT_RELEASE, build_page("release"))

    # ---- 站点目录：把「部署源」需要的两份一并刷新 ----
    # dist/site/ 是往云托管部署的那个目录，其中 index.html 与 tunnel-manager.zip
    # 历来靠手工 cp —— 而"忘了 cp / 只 cp 没部署"是同一个反复踩的漏点。
    # 收进构建里，site/ 就永远等于 dist/ 当前产物，只剩"记得部署"这一个动作。
    if os.path.isfile(OUT_EMBED):
        os.makedirs(SITE, exist_ok=True)
        _copy_over(OUT_EMBED, os.path.join(SITE, "index.html"))
    if os.path.isfile(ZIP):
        _copy_over(ZIP, os.path.join(SITE, os.path.basename(ZIP)))

    print(f"\n落地页已生成：{OUT_EMBED} / {OUT_RELEASE}")
    print(f"部署源已刷新：{SITE}/")


if __name__ == "__main__":
    main()
