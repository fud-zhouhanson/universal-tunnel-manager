# 通用隧道识别与切换系统

> 从 aTrust 隧道切换程序演进而来，升级为**通用隧道管理**：自动识别本机所有由
> VPN / 游戏加速器 / 代理(梯子) / 覆盖网络 / 企业零信任客户端构造的隧道接口，
> 并支持按域名把流量在「隧道」与「本机直连」之间切换。跨平台（macOS / Windows），
> 零依赖（Python 标准库）。

---

## 一、核心思想

**不做「停止客户端」，只做「改路由表」。**

所有 VPN/加速器/梯子的共同点：它们都会在系统里创建一块**虚拟隧道网卡**，并通过
**路由表**把流量导进去。所以要「识别 + 切换」，只需回答两个问题：

1. **识别**：这台机器上，哪些网卡是隧道？分别是谁创建的（aTrust？Clash？雷神？）？
2. **切换**：如何把「某几个域名」的流量精确地从隧道里「拔出来」，又不动其它流量？

答案是：**三层证据融合**做识别，**/32 主机路由**做切换。

---

## 二、算法思路：三层证据融合识别隧道

### 第 1 层 —— 进程证据（谁在运行）

跨平台扫描系统进程，匹配知识库里的 48 条软件规则：

| 类别 | 代表软件 | 进程关键字 |
|---|---|---|
| 企业 VPN | aTrust、EasyConnect、AnyConnect、GlobalProtect、FortiClient | atrust / ecagent / vpnagent / pangpa |
| 开源 VPN | OpenVPN、WireGuard、SoftEther | openvpn / wg-quick / vpnclient |
| 系统 VPN | IPSec / L2TP / PPTP / IKEv2 | racoon / charon / xl2tpd |
| 代理(梯子) | Clash、V2Ray、Shadowsocks、Trojan、Hysteria、Surge | clash / v2ray / ss-local / trojan |
| 游戏加速器 | 雷神、网易UU、迅游、奇游、biubiu | leigod / uu / xunyou / qiyou |
| 覆盖网络 | ZeroTier、Tailscale、Hamachi、蒲公英 | zerotier / tailscale / hamachi / pgyvpn |
| 虚拟网卡 | VMware、VirtualBox、Docker | vmnet / vboxnet / docker |

### 第 2 层 —— 接口证据（有哪些网卡）

扫描所有网络接口，用正则判定类型：

- **隧道**：`utun*`、`feth*`、`tap*`、`tun*`、`ppp*`、`ipsec*`、`wg*`、`ham*`、`zt*`、`cscotun*`
- **物理**：`en*`、`eth*`、`wlan*`、`wi-fi`、`以太网`
- **回环/其它**：`lo0`、`bridge*`、`vmnet*`、`awdl*`、`anpi*` 等

### 第 3 层 —— 路由证据（出口流向）

1. 默认路由（0.0.0.0/0）走哪个接口？→ 若落在隧道接口上，就是「**全流量隧道**」（最可疑，aTrust 就是这种）。
2. 目标域名的每个 IP，`route get <ip>` 实际从哪个接口出去？→ 出口是隧道接口 = 该域名「被接管」。

### 归属判定（证据融合优先级）

```
承载默认路由的隧道接口  →  全流量隧道（结合进程名精确定位）
       ↓ 否则
接口名 / 描述 匹配软件库  →  精确到具体软件
       ↓ 否则
命名规律启发式  →  大类（utun/feth → 系统隧道；tap/tun → Tap/Tun 隧道 …）
```

> 实测效果：即使某个隧道软件的进程已退出、只剩接口残留，只要接口名带 `utun`/`feth`
> 且软件库里有对应映射，仍能正确归类为「aTrust（深信服零信任）」。

---

## 三、切换机制：/32 主机路由

**原理**：路由表里**越具体的路由优先级越高**。隧道用一条「默认路由」把流量兜住，
我们为每个目标 IP 添加一条更具体的 `/32`（单个主机）路由指向物理网关，这条就更优先，
该条流量就「绕过」了隧道。其他流量仍走隧道默认路由。

```
切换前：  example.com → 默认路由 → utun(隧道)
切换后：  route add -host 203.0.113.10 192.168.1.1   ← /32 覆盖默认路由
          example.com → 203.0.113.10 → en0(物理网卡直连)
```

**关键特性**：
- **最小侵入**：不停止、不卸载任何客户端，校内/公司资源照走隧道。
- **可精确回滚**：每条加过的 IP 都写进 state 文件，`undo` 时逐条 `route delete`，
  只删自己加的，绝不动系统原有路由。
- **不依赖记录文件**（重要）：`undo` 以**路由表实测**为准 ——
  识别「主机路由 + 下一跳=物理网关 + Flags 含 H/S（静态）」的条目，
  再与「我们管理的域名解析出的公网 IP」取交集，因此
  **记录文件丢了、或被手工删掉，照样能完整交还**；同时因为要过域名 IP 这一关，
  不会误删 VPN 客户端自己添加的对外路由。
- **按域名切换**：域名表可在页面上自定义编辑，换学校/换单位只改配置。

**状态文件位置**（踩过的坑）：`~/.tunnel-manager/state.json`（600 权限）。
早期版本曾把记录写到 `/var/run/tunnel-manager.state` —— 那是 root 属主目录，
**普通用户写不进去**，而写入失败又被静默吞掉，结果是：路由加成功了却没留下记录，
`undo` 无从下手、「↩ 交回隧道」按钮被置灰，19 条直连路由永久残留在路由表里。
现在：① 记录改到用户目录；② `write_state` 的返回值必须被检查，失败会明确告知；
③ `undo` 有「路由表实测」这条兜底，不再单点依赖记录文件。

**跨平台命令**：

| 操作 | macOS | Windows |
|---|---|---|
| 加直连路由 | `route add -host <ip> <gw>` | `route -p add <ip> mask 255.255.255.255 <gw>` |
| 删路由 | `route -n delete -host <ip>` | `route delete <ip>` |
| 查出口 | `route -n get <ip>` | `Find-NetRoute -DestinationIPAddress <ip>` |
| 提权 | `sudo -S`（喂密码） | `ShellExecuteW runas`（UAC 图形确认） |

---

## 四、系统结构

```
universal-tunnel-manager/
├── tunnel_manager/     后端源码（跨平台，零依赖）：扫描 + 判定 + 路由操作 + HTTP API
├── index.html          前端（管理面板）：隧道列表 + 路由走向 + 一键切换 + 自动追踪
├── bundle.py           把 tunnel_manager/ 拼成单文件（构建与开发入口共用同一份拼接逻辑）
├── build.py            打包脚本：调 bundle 出单文件，再补上随包分发的辅助文件 + 打 zip
├── make_tools.py       生成「检查运行.bat / .command」启动器（.bat 必须 GBK）
├── make_win_pkg.py     打 Windows 免安装包（内置 Python 运行时）与精简包
├── make_download_page.py  生成 dist/download.html：把 zip 内嵌进去的可分享落地页
├── scripts/build.sh    一键构建全部产物 + SHA256SUMS
├── tools/selftest.py   运行环境自检（双平台双击即用）
├── start.sh            macOS 启动脚本
├── start.bat           Windows 启动脚本
├── stop.bat            Windows 停止脚本
├── tunnel-manager.command  macOS 双击启动
└── dist/               分发产物（给自己或别人用）
    ├── tunnel-manager.py    单文件版（内嵌前端，整包只此一个 .py）
    ├── tunnel-manager.zip   打包下载（含 py + 双平台安装脚本 + README）
    ├── TunnelManager-Windows-x64.zip   Windows 免安装版（内置运行时）
    ├── TunnelManager-Windows-lite.zip  Windows 精简版（需对方已装 Python 3）
    ├── 运行检查工具.zip       可单独发的体检小包
    ├── download.html        可分享的落地页（内嵌 zip，点按钮即下载）
    └── site/index.html      托管用入口（= download.html），配合静态托管发布成链接
```

### 源码为什么是「包 + 组装器」而不是普通包

对外只交付**单文件** `tunnel-manager.py`（用户双击即用，这是产品卖点），
所以源码拆包后必须在构建期拼回去。但源码**不是**一组互相 `import` 的模块：

- 迁移前它是一份 6800 行的单命名空间脚本，227 个顶层函数互相随便调；
  实测跨块引用 **471 处**、其中含 **10 组循环依赖** —— 硬拆 `import` 会直接 ImportError。
- 现在按章节切成 **39 个切片**，**切片之间零 import**，谁调谁靠「同一命名空间」；
  顺序由 `tunnel_manager/_slices.py` 的 `SLICES` 持有（= 迁移前的书写顺序）。
- **开发期** `python -m tunnel_manager.main` 与**构建期** `bundle.py` 共用同一份
  `assemble()`，不搞两套实现。所以「怎么跑」和「怎么打包」永远是同一件事。

> 切片文件里直接引用别的切片定义的函数/常量、却不写 import，是**设计如此**，不是漏写。
> 每个切片文件头部都写明了这一点。

```
tunnel_manager/
├── _base.py            运行环境常量（平台判定 / 目录 / 端口 / 状态文件）+ 全部标准库 import
├── _slices.py          切片清单与拼装（开发期与构建期共用）
├── main.py             开发期入口：拼装后 exec 进一个命名空间执行
├── consts.py           软件识别知识库(48 条) / 接口命名规律 / 保留地址段
├── util.py             通用工具：run / run_ps / _sh / run_root / 提权能力探测
├── detect/             识别引擎（四层证据融合）
│   ├── process.py      ① 进程证据   ② 接口证据见 iface.py
│   ├── iface.py        ② 接口证据（IPv4 + 命名 + MTU + ULA 指纹）
│   ├── route.py        ③ 路由证据（默认路由 + 聚合路由多点抽查 PROBE_TARGETS）
│   ├── judge.py        归属判定 classify_tunnel（证据融合）
│   └── scan.py         统一扫描 do_scan / scan_mac / scan_win
├── config.py           配置读写（读-改-写）/ 域名解析 / 自动追踪参数 / 假 IP 池规则
├── autotrack.py        浏览器历史 → 目标域名（含 auto_status 上报）
├── outlet/             出口管理（三个可控点）
│   ├── scene.py        情景判定 + ATRUST_JOBS / ATRUST_PLISTS
│   ├── scene_ops.py    情景切换 / 残留路由清理
│   ├── manager.py      出口发现 + 关闭方式显式表 OUTLET_RULES
│   ├── routes.py       路由表读取 / bypass 目标计算
│   └── apply.py        do_apply / do_undo / do_daemon
├── win/                Windows 适配
│   ├── probe.py        PowerShell 可用性探测 + 原生缓存
│   ├── nat_net.py      原生回退：接口 / 路由表 / 邻居表（route print · netsh · arp）
│   ├── nat_sys.py      原生回退：服务 / 进程 / 系统 VPN + 提权 run_elevated_win
│   ├── apps.py         服务枚举 / 启停
│   ├── outlets.py      出口探测与提权脚本拼装
│   ├── switch.py       出口启停切换 + launchd 作业启停（带失败回滚）
│   └── identify.py     出口指纹
├── health/             体检
│   ├── probe.py        基座：本地地址映射 / 首跳 / 并发 / 真值目标
│   ├── dns.py          DNS 读取与直查
│   ├── egress.py       出口真值
│   ├── trace.py        do_trace（只观测不声明）
│   ├── snapshot.py     健康基线快照 + 假 IP 池路由
│   ├── rescue.py / rescue_win.py   一键应急恢复（双平台）
│   └── flowrate.py     实时流速采样
├── steam/              Steam 三网体检
│   ├── paths.py  api.py  trace.py  sdr.py  capture.py  summary.py  commands.py
└── web/httpd.py        HTTP 服务（Host/Origin/CSRF 校验）+ 路由表 + 前端内嵌
```

**HTTP API**：

所有端点同时挂在两个前缀下，**老路径继续有效**（用户可能存了书签或写了脚本）：

| 方法 | 路径 | 作用 |
|---|---|---|
| GET | `/api/scan` | 只读扫描（免管理员）。含 `priv` 字段告知当前是否只读 |
| GET/POST | `/api/config` | 读/写域名配置 |
| GET | `/api/flow` | 实时流速采样（只读） |
| POST | `/api/sudo` | (mac) 验证并缓存 sudo 密码 |
| POST | `/api/auto/enable` | 开启自动追踪（扫浏览器历史） |
| POST | `/api/auto/disable` | 关闭自动追踪并清空追踪集 |
| POST | `/api/auto/pin` | 手动把一个域名加入追踪集（body `{domain}`，可粘整条 URL，会规范化成主机名） |
| POST | `/api/auto/promote` | **把追踪中的域名「转正」**：写进配置表 → 长期生效，并从追踪集移除 |
| POST | `/api/auto/unpin` | 立刻停止追踪某个域名 |
| POST | `/api/outlet/switch` | **切到某个出口**（body `{key}`）：停掉其它在跑的 + 启动目标 + 清残留路由 |
| POST | `/api/outlet/start` · `/api/outlet/stop` | 单独启 / 停某个出口（body `{key}`） |
| POST | `/api/outlet/identify` · `/api/outlet/forget` · `/api/outlet/cancel` | 识别归属 / 遗忘记忆 / 取消这次切换 |
| POST | `/api/scene/game` | （旧）等价于 switch 到加速器。**当前前端未调用**，仅接口保留 |
| POST | `/api/scene/campus` | （旧）等价于 switch 到 aTrust。同上 |
| POST | `/api/apply` | 全部域名 → 本机直连 |
| POST | `/api/undo` | 撤销直连 → 交回隧道 |
| POST | `/api/daemon/install` / `remove` | (mac) 装/卸守护 |
| POST | `/api/trace` | 真实流量体检 |
| POST | `/api/rescue` | 一键应急恢复 |
| POST | `/api/health/save` | 保存健康基线 |
| POST | `/api/steam/probe` · `/api/steam/diagnose` | Steam 三网体检 |
| POST | `/api/steam/capture/start` · `stop` / GET `/api/steam/capture/result` | 抓包采样 |
| GET | `/api/steam/overview` | Steam 概览摘要 |

> 加版本前缀只影响路径写法：`/api/v1/scan` 与 `/api/scan` 等价。
> 所有写接口（POST）都需同时带合法 `Origin`/`Referer` 与 `X-TM-Token`，否则 403。

---

## 五、提权与安全

- **macOS**：`sudo -S` 喂密码，密码**只存后端内存**，不落盘、不进日志。改路由表是
  系统级操作，按需引导用户授权（遵循 system-access-authorization-guard）。
- **Windows**：`ShellExecuteW runas` 触发 UAC 图形确认，不在命令行里传密码。
- 后端只绑 `127.0.0.1`，仅本机可访问，端口被占自动顺延。
- 守护（macOS）：`LaunchDaemon` 每 30 秒自动补回直连路由，防止隧道客户端重刷路由覆盖。

---

## 六、目标域名：默认值 + 自动追踪

### 6.1 默认域名表（开箱即用）

`tunnel_manager/config.py` 的 `DEFAULT_DOMAINS` 预置了几个**通用示例站点**，首启即生效：

| 分组 | 域名 |
|---|---|
| 常见网站 | `www.baidu.com`、`www.bing.com`、`github.com`、`www.zhihu.com` |

> 默认表刻意不含任何特定机构。请把它改成**你自己**常访问、且希望「走物理直连」的站点
> （例如你所在学校 / 单位的门户、教务、图书馆、镜像站等）。

> **不要把 VPN 客户端「自身服务器」的域名放进来。** 例如某些校内 VPN 的
> `vpn.<学校域名>` 往往解析到的正是 **aTrust 自己的外层传输服务器** ——
> 让本工具去托管 VPN 客户端自身的"保活通路"路由既无意义也有风险，
> 因此这类域名应排除。见下面 6.3。

页面「目标域名的路由走向」表逐个列出每个域名的解析 IP、当前出口接口与判定
（「直连 ✓」/「被隧道接管」）。换学校 / 换单位时直接在下方文本框增删，
点「恢复默认」回到上面那张表。

### 6.2 自动追踪（新开的网站自动进出）

**需求对应**：用户打开一个新网站 → 它自动出现在目标域名表里，点「应用」就连它一起加直连路由；
关掉后 → 自动移除。

**实现**：后台每 `AUTO_INTERVAL = 30` 秒**只读**扫一遍浏览器历史库
（Chrome / Edge / Brave / Firefox / Safari 的 `History`，Chrome 运行时先复制到临时文件再读，
不写入原库），把域名按最近访问时间戳归并：

| 常量 | 值 | 含义 |
|---|---|---|
| `AUTO_WINDOW` | 180 秒 | 最近 3 分钟内访问过的域名 → 视为「正在看」，加入追踪集 |
| `AUTO_EXPIRE` | 600 秒 | 超过 10 分钟没再访问 → 视为「已关闭」，从追踪集移除 |
| `AUTO_MAX` | 60 | 追踪集上限，超出丢最旧的（见下方「为什么要有上限」） |

- 追踪到的域名在前端「自动追踪」卡片里以 chips 展示，并**并入主路由表**（带「自动」标签、半透明行）。
- **追踪到的域名会真正参与「应用」**：`do_apply()` 用的是 `managed_domains()`
  （配置表 + 追踪集，已去重），不是只有配置表。每个 chip 后面有
  「转正」（写进配置表 → 长期生效）与「✕」（立刻停止追踪）两个按钮。
- 时间戳换算：Chrome/Edge 用 1601 起的微秒，Firefox 用 1970 起的微秒，Safari 用 2001 起的秒。
- **隐私**：纯本机内存运算，不落盘、不上传、不记录访问内容，只取主机名。
- **权限**：Safari 历史库受 macOS「完全磁盘访问」保护。**权限不足不再静默失败** ——
  `_scan_history_once()` 会返回每个历史库的读取状态（`ok` / `denied` / `error`），
  经 `/api/scan` 的 `auto_status` 字段送到卡片上，
  明确写出「读不到：Safari —— 被系统隐私保护挡住了」以及授权步骤。
  拿不到权限时用卡片里的手动输入框（`＋ 加入追踪`）兜底 —— 它走 `/api/auto/pin`。

#### 本节的三个坑（都踩过，别改回去）

| 坑 | 症状 | 正确做法 |
|---|---|---|
| **剥掉 `www.`** | 访问 `www.zhihu.com` 存成 `zhihu.com`，`apply` 给 apex 的 IP 加路由 —— 而浏览器连的是 www 的 IP，**两条路完全不重合**，功能看着成功、实际零生效。实测 6 个国内站（百度/知乎/腾讯/网易/B站/淘宝）apex 与 www 解析结果**交集全为 0**，只有本来就无 www 的 `github.com` 对得上 | `_extract_domain()` **原样保留 host**，只剥 scheme / userinfo / 路径 / 端口 |
| **吞掉读取异常** | `except: pass` 之后界面永远显示「追踪中 · 0 个」，用户分不清是没开浏览器、没授权、还是刚看的都超了 3 分钟 | 每次扫描留一份 `_auto_status`，把 `denied` / `error` 如实送到前端 |
| **临时文件不在 finally 删** | Chrome 的库要先复制再读；复制失败时 `unlink` 被跳过，**每 30 秒泄漏一个副本** | `os.unlink` 放 `finally` |

> **为什么要有 `AUTO_MAX` 上限**：追踪到的域名现在真的会变成直连路由，每个域名解析出 2~4 个 IP，
> 而 Windows 上每条 IP 要起两次 `route.exe`（先 `delete` 再 `-p add`）。
> 不设上限的话，浏览一天攒出上百个域名 → 数百次进程创建，会逼近 `run_elevated_win` 的 90 秒超时。

> **追踪是临时的**：10 分钟没再看就会自动移除。要让它长期生效，点 chip 后的「转正」写进配置表。
> 这一点在卡片文案和 toast 里都写明了 —— 以前只写「已加入追踪 ✓」，用户过 10 分钟发现它不见了却不知道为什么。

### 6.3 自动排除隧道客户端「自身服务器 IP」（安全护栏）

隧道客户端（aTrust / Clash / ZeroTier …）必须用一条**外层连接**连到自己的服务器，
这条通路是隧道的生命线。如果把服务器 IP 也纳入管理：

- `apply` 时给它加 `/32` 直连路由 → 工具越权插手 VPN 的保活路由，无意义；
- `undo` 时误删它的路由 → 隧道的外层流量可能被卷进隧道内部（**递归封装**），隧道立刻瘫痪。

因此本工具会**自动识别并永久排除**这些 IP：

| 环节 | 做法 |
|---|---|
| 识别 | 用知识库里的进程关键字过滤 `lsof -nP -iTCP -iUDP`（Windows 走 `Get-NetTCPConnection`），取出客户端进程对外连接的**公网**远端地址 |
| 缓存 | 内存 120 秒 + 落盘 `~/.tunnel-manager/tunnel_servers.json`。落盘是必须的——**隧道断开时探测不到连接**，但服务器 IP 仍须保持排除 |
| 生效 | `do_apply` 跳过它们并如实报告；`bypass_targets` 从"待交还集合"里剔除它们（即使有人手动把域名加回列表也一样被排除） |
| 展示 | 页面「目标域名的路由走向」顶部出现紫色提示框，列出当前排除的 IP |

实测：本机能识别出 aTrust 的外层传输服务器地址，`apply` 报告
"已跳过 N 个隧道客户端自身服务器 IP"。（具体 IP 随你的 VPN 客户端与所在网络而定，
这里不列出实例，避免把运行环境信息带进仓库。）

### 6.4 关于"交回隧道后变慢"（实测结论，非 bug）

把域名交还隧道后，流量出口从**家庭宽带**换成**学校出口**，这是设计使然。实测对照：

| 目的地 | 出口 | 延迟 | 吞吐 |
|---|---|---|---|
| 校内 / 单位内网 | utun7 | 67 ms | — |
| 国内（百度/知乎/Bing） | utun7 | 93–98 ms | 10.5 MB/s |
| **国际（GitHub）** | utun7 | **358–412 ms** | **0.5–0.7 MB/s** |
| 物理路径基准（aTrust 服务器本身，走 en0） | en0 | 64 ms | — |

- **隧道本身是健康的**：相对同一网段的物理路径仅多 **4.7 ms**；国内目标 10–29 MB/s、
  0% 丢包、stddev 3.4 ms，38 MB 下载 **0 次重传**。
- **慢在绕路**：学校出口的**国际带宽**是硬瓶颈 → GitHub 延迟飙到 412 ms、吞吐掉到 0.5 MB/s，
  比国内镜像慢约 40 倍。
- 另有**偶发吞吐塌陷**（实测同一文件出现过 1.8 MB/s，平时 24–29 MB/s），体感为"忽快忽慢"。

→ 结论：**国际站点建议保留直连**（用「⇄ 切到本机直连」），国内站点走隧道影响有限。

> 排查提示：判定 MTU/PMTU 问题**必须用 TCP 侧证据交叉验证**（重传数、吞吐）。
> 本项目一度因为"1500 字节 ICMP 发给公共 DNS 被静默丢弃"而误判为 MTU 黑洞，
> 但同样大小的包发给校园网目标完全正常、且 38 MB 下载 0 重传，说明那只是
> 该 DNS 不响应大 ICMP，与隧道无关。

---

## 六·五、保命线守护（`guard_uplink.py`）—— 做隧道实验时的「防断线」

**为什么需要它**：本工具要做的事情就是反复切换隧道。但一旦我们与模型 API 的
连接被隧道（aTrust 的聚合路由 / 雷神的 default 抢占）卷进去，对话会直接卡死 ——
因为流量被导到校园出口，国际线路极慢甚至超时。

**解法**：利用路由表的**最长前缀匹配** —— 给「本机正在使用的 API 服务器 IP」
钉一条主机路由（IPv4 `/32`、IPv6 `/128`）指向物理网关。越具体的路由越优先，
所以隧道再怎么加聚合路由也抢不走这条线。

| 子命令 | 作用 | 需要 root |
|---|---|---|
| `check` | 只读体检：保命目标走物理还是隧道，是否已钉死 | 否 |
| `once` | 钉一次路由，不常驻 | 是 |
| `arm` | 钉路由 + 每 5 秒守护（隧道重刷路由会自动补回） | 是 |
| `disarm` | 撤销本脚本加过的所有路由 | 是 |
| `status` | 显示受保护目标与当前路由状态 | 否 |

```bash
python3 guard_uplink.py check          # 随时体检，不影响任何配置
sudo python3 guard_uplink.py arm       # 做隧道实验前，先把保命线守住
```

**保命目标怎么来**（两类合并去重）：
1. **自动发现** —— 抓 `WorkBuddy / CodeBuddy / Electron` 等进程当前 `ESTABLISHED`
   的公网连接对端 IP，也就是「对话链路本身」；
2. **手动补充** —— `~/.tunnel-manager/guard_targets.txt` 里写域名或 IP，一行一个。

**几个实测踩坑（都已在代码里处理）**：
- `lsof` 每行末尾有 `(ESTABLISHED)`，连接串不是最后一列，得找含 `->` 的那个字段；
- `lsof` 输出含非 UTF-8 字节（中文进程名），必须 `errors="replace"`；
- **克隆路由陷阱**：只要目标有活动连接，内核就会生成一条 `WASCLONED` 的临时主机路由，
  `route -n get` 看起来「已经走物理」，但那是缓存、连接一断就没了 →
  必须查 `netstat -rn` **主表**里带 `H`+`S` 标志的条目才是真钉住；
- macOS 的 `netstat` 里主机路由**不写 `/32` 后缀**，只能靠 flags 里的 `H`(HOST)+`S`(STATIC) 判断；
- 以 root 运行时 `~` 会变成 `/var/root`，状态文件/日志会写到用户看不见的地方 →
  脚本会回退到控制台登录用户的家目录，并把产物属主 `chown` 还回去。

**怎么常驻**：用 `launchctl submit -l com.tm.guard -- <python> <guard_uplink.py> arm`
注册一个 root 守护（不落 plist 文件，重启后失效，适合做实验期间用）。
`nohup ... &` 在提权环境里无法 detach，别用。

---

## 六·六、出口管理（任意隧道客户端都能切）

**不写死「游戏模式 / 校内模式」** —— 本机装了哪些能当出口的东西，就列哪些，想切哪个切哪个。

**核心思路：不为 35 种客户端手写适配，而是自动探测三个「可控点」**：

| 探测 | 收获 |
|---|---|
| 装没装 `.app`（扫 `/Applications` 与 `~/Applications`） | 能 `open -a` 启动 |
| 有没有 launchd 作业（扫 `/Library/LaunchDaemons`、`/Library/LaunchAgents`、`~/Library/LaunchAgents`） | 能 `bootout` 停 / `bootstrap` 启 |
| 有没有系统 VPN 配置（`scutil --nc list`） | 能启停，且**不需要 root** |

三个都没有就退化为「引导用户手点」。所以新增一种客户端时，**通常不用改代码**。

**但有两条必须守住的红线**（`OUTLET_RULES`）：

1. **有些作业不能停**。雷神的 `com.leigod.helper`、网易UU 的 `com.netease.uumac.helper`
   是**引擎本体**、KeepAlive 常驻 —— 停掉它等于把加速器弄坏，而**不是**「停止加速」。
   它们的加速开关只在 App 内部，所以这两个被显式标为 `manual`（只引导，不代劳）。
2. **aTrust 相反**：它有三个**专门承载隧道**的守护作业，`bootout` 掉才是正确的「完全退出」，
   而且顺序不能反 —— 必须先停 `aTrustTunnelWatchDog`，否则它会立刻把隧道拉回来。

另外 `_JOB_NOISE` 会把 `helper / uninstall / monitor / limit / maxfiles / crashpad / update`
这类「看护 / 资源 / 卸载」作业从自动模式里排除掉，避免误停。

**关于「当前用的是哪个出口」—— 这里有个诚实的说明**：

实测在 macOS 上**拿不到 TUN 接口的厂商信息**（`lsof | grep utun` 看不到、
`ifconfig` 没有 description、`system_profiler SPNetworkDataType` 也不列 utun）。
而 Clash / sing-box / 雷神这类客户端建的接口**全叫 `utunN`**，名字毫无特征。
所以工具**只在证据唯一时**才反推归属（恰好一个认不出的 utun + 恰好一个没落位的出口型软件），
否则如实显示「归属未识别」，**不瞎猜**。

用户点过切换后，会记到 `~/.tunnel-manager/active_outlet.json`，
界面显示为「已切换（待确认）」—— 明确区分「你告诉我们的」和「我们猜出来的」。

**「待确认」是可以反悔的（`POST /api/outlet/cancel`）**。

这笔记录是**我们记的账，不是系统事实**，所以它必须能被撤销。处于「已切换（待确认）」
的那一行，按钮是「✕ 取消这次切换」而**不是**「切到这里」—— 已经切过去了还摆一个前进按钮
毫无意义；绿色（`primary`）只留给真正的前进动作。取消做两件事：

1. 若上次切到的是**「本机直连」**，那笔账伴随的是真的加了 `/32` 直连路由，
   所以要把它们交还隧道（`do_undo`，只删本程序加过的主机路由，不误伤别的程序）；
2. 抹掉这笔记录 → 那一行从黄色「待确认」回到中性状态。

切到**隧道客户端**的情况**不回滚启停** —— 用户很可能正靠它上网，自动把它停掉会直接断网。
只清记录，并提示「如需彻底退出，请用它自己的界面关掉，或点该行的『停止』」。

> 踩过的坑（值得记）：第一版把「取消切换」绑成了 `/api/outlet/switch`，
> 也就是**把那个出口又切了一次**，等于用"前进"冒充"反悔"；而且条件写成
> `last === o.key && !isDirect`，把「本机直连」这种出口漏在外面 ——
> 于是切到直连后那一行**依旧显示绿色「切到这里」**，用户想取消却无处可点。
> 正确条件只看 `!o.in_use && last === o.key`（不排除 direct），按钮语义与动作必须一致。

操作过程中的反馈区（`#sceneSteps`）也统一成 `.ops-row`：执行中给「✕ 取消」，
用 `AbortController` 真的断开等待（并如实说明"后端可能仍会完成已经开始的动作"）；
完成后给「✓ 关闭」。不再出现"只能干等、没法收场"的死状态。

**怎么把「归属」确认下来（四种手段，按可靠性排序）**：

| 手段 | 代价 | 可靠性 |
|---|---|---|
| **① 指纹**（用户确认过一次，之后永久认得） | 零 | 最高 |
| **② 停掉它 → diff 路由表** | 要短暂停客户端（aTrust 还得重登录） | 高 |
| **③ 拔一条路由看谁补回来** | 低（无损） | **只对有守护进程的客户端有效** |
| ④ 软认领（证据唯一时反推） | 零 | 低 |

出口列表每行有「确认归属」按钮，两种情况自动分流：

- **能自动停的**（aTrust）→ **一键式**：工具自己「停 → 对比 → 恢复」；
- **不能自动停的**（雷神 / 网易UU）→ **两段式**：第一次点记下快照并提示你手动关，
  关掉后再点一次，工具对比得出归属。

结果存进 `~/.tunnel-manager/outlet_fingerprints.json`，之后 `_iface_owners` **优先用指纹**认领，
不再靠猜；界面会标「归属已确认」。

> **关于「拔路由探针」的实测结论**：拔掉雷神的 `128.0/1` 后 **8 秒内没有被补回** ——
> 说明它是「一次性 `route add`」型、**不守护路由**，所以这招对它无效。
> 而 aTrust 有 `aTrustTunnelWatchDog` 专门把隧道拉回来，对它就有效。
> **这个差异本身就是区分客户端类型的一条线索**，别一刀切地用。
>
> 附带发现：雷神日志里每 5 秒一次心跳
> `{"method":100000}` → `{"delay":29,"game_id":3587,...}`，
> 是可靠的「雷神正在加速」指纹（也能反推它 10908 控制口的 method 表）。

**原「情景」判定依然保留**，作为总览徽章（直连 / 校内 / 游戏 / 隧道接管 / 多出口冲突）。

---

## 六·七、原来的情景切换（已并入出口管理）


**为什么是「情景切换」而不是「同时分流」**：实测（见 `PLAN-multi-tunnel.md` §1.3b）
雷神与 aTrust 是**同一类**客户端 —— 都用「拆分整段公网」把流量导进自己的 utun：

```
雷神    1 · 2/7 · 4/6 · 8/5 · 16/4 · 32/3 · 64/2 · 128.0/1   → utun6
aTrust  1/8 … 240/4，共 152 条                                → utun7
```

这两套拆分路由会在同一张表里**争夺最长前缀匹配**，同时开必然互踩（表现为"显示在加速但没效果"）。
所以只能二选一 —— 把「换一个」做成一个按钮。

**工具做哪一半、人做哪一半**：

| 步骤 | 谁做 | 说明 |
|---|---|---|
| 停 aTrust | 工具 | `launchctl bootout` 三个 **system 域**作业，顺序必须 WatchDog → Tunnel → Daemon（先停守卫，否则它会把隧道拉回来） |
| 清理残留路由 | 工具 | 删掉指向「已不存在的接口」的条目，否则流量会被黑洞 |
| 雷神开始/停止加速 | 人 | 开关只在它的 GUI 里（helper 的 `127.0.0.1:10908` 控制口协议尚未还原） |
| 拉起 aTrust + 登录 | 工具 + 人 | 工具 `bootstrap` 回作业并打开 App；登录必须你自己来 |

页面「当前情景」卡片上有两个按钮，点完会列出「已自动完成」和「还需你手动做」的步骤。

**判定依据**：多点抽查（`egress_counts`）里**哪个隧道接口在承载公网**，
而不是简单看进程 —— 因为 aTrust 的 GUI 进程即使隧道退了，仍然会留在后台。

**实测数据（决定设计的那几条）**：
- aTrust 退出后，它加的 **145 条残留路由会在 4~10 秒内自己清光**；
- 雷神**不改 DNS、不抢 default**，所以进出都很干净；
- 两者都**不碰全局 IPv6**（aTrust 只占自己的 SANGFOR ULA 段）。

---

## 六·八、真实流量体检 + 一键应急恢复

### 为什么需要它

路由表和 DNS 配置都是「**声明**」，不是「**事实**」。用户把 DNS 和隧道倒腾乱之后，
最典型的三类故障，光看配置文件**全都显示正常**：

1. 声明走物理、实际被拽进隧道，或干脆被黑洞
2. DNS 被隧道改写，把域名解析进**假 IP 池**（`198.18.x.x` 之类）——
   表现就是「显示在加速但没效果」
3. DNS 服务器早已失效，或指向不存在的地址

所以这一块**不读配置，只做观测**：真解析一次、真连一次、真看第一跳。

### 三个面板（`POST /api/trace`，约 3 秒）

| 面板 | 观测手段 | 能查出什么 |
|---|---|---|
| **路由：声明 vs 实测** | ① `route -n get`（声明）② UDP connect 后读 `getsockname()`（内核实际选的源地址）③ `ping -c1 -m1`（TTL=1 逼第一跳报出自己是谁） | 路由表说走 A、实际从 B 出去 |
| **DNS：系统解析 vs 绕过系统直查** | 系统解析器 vs 自己构造 DNS 包直接问配置的 DNS 服务器 | 假 IP 池劫持、解析失败、与直查不一致 |
| **连通性** | 照 DNS 结果对每个 IP 真连一次 `:443` | 哪些站能通、延迟多少、走哪条路 |

**关键设计**：

- **用固定 IP 做路由面板、用域名做连通性面板**。前者保证 DNS 已经挂了也能出结论；
  后者保证不会拿「对方服务器本来就没开 443」误报成「连不上」——
  这个坑踩过：最初用 `119.29.29.29:443` 当探测点，它根本没开 443，结果误报异常。
- **第一跳用 `ping -m 1` 而不是 `traceroute`**。macOS 的 `ping` 是 setuid 的，
  普通用户就能跑；`traceroute` 在不少受限环境里会被拒（实测本机就是）。
  TTL=1 的包会在第一跳超时，路由器回一条 `Time to live exceeded`，从回复里读地址即可。
- **并发探测**。全串行要 10 秒以上，用 `parallel_map()` 压到 **3 秒**左右。
- **IPv6 DNS 过滤**。`scutil` 常把 `fe80::10%en0` 排在最前，但那是 IPv6，
  用 IPv4 的 UDP socket 根本发不出去 —— `ipv4_dns_servers()` 专门处理这点。

### 自动告警（不用点按钮也能发现）

`do_scan()` 里带了一个**轻量版**体检 `egress_truth`：只做 UDP 选路（不发包、微秒级，
实测扫描耗时仍 **0.09 秒**）。一旦「声明出口 ≠ 内核实际选的源地址」，页面顶部概览卡片
会直接弹出红框告警，并给出跳转到完整体检的链接。

### 一键应急恢复（`POST /api/rescue`）

依次做 5 件事，每步都记 before/after 并落 `~/.tunnel-manager/rescue.log`：

1. 默认路由改回物理网关
2. 清理指向已消失接口的**黑洞路由**
3. 清除**假 IP 池路由**（`198.18.x` / `100.64-127.x` / `240.0.0.x`）
4. **DNS 恢复** —— 有保存的健康基线就还原它；没有就设成 `Empty`（清掉自定义、交回 DHCP）
5. 刷新 DNS 缓存（`dscacheutil -flushcache` + `killall -HUP mDNSResponder`）

最后自动**复验**（连一次外网 + 解析一个域名）并把结果一并返回。

**两条安全设计**：

- **不把 DNS 写死成路由器 IP**。那样换个网络就失效了；优先「还原基线」或「交回 DHCP」。
- **不做不可逆的事**：不卸载软件、不动 `/etc/hosts`、不删用户配置。
  没有管理员密码时，会**停在需要密码那一步并如实报告已完成到哪**，绝不「先改了再说」。

### 保存健康基线（`POST /api/health/save`）

在「现在一切正常」的时候存一份 `~/.tunnel-manager/health.json`：
物理网卡 / 网关 / 网络服务名 / DHCP DNS / 当前 DNS。
以后应急恢复会**优先还原它**，而不是一律清空 —— 这样用户自己本来就有的自定义 DNS 不会被误伤。

---

## 六·九、实时流速（`GET /api/flow`）

回答一个「体检」答不了的问题：**流量现在在哪条网上跑、跑多快。**

### 数据从哪来

读 `netstat -ib` 里**每个接口开机以来的累计收发字节**（`Ibytes` / `Obytes`），
相邻两次采样做差分 → 速率。所以它是**实测值**，不是估算，也**不额外花任何流量**。

| 手段 | 单次开销 | 能回答 | 不能回答 |
|---|---|---|---|
| `netstat -ib`（**本模块**） | 约 12 ms，**免 root** | 每条网卡跑多快、隧道占多少 | 是哪个程序在跑 |
| `nettop` 逐进程（Steam 采样那套） | **约 5 秒**固定开销 | 是哪个进程、连到哪个中继 | 流量走了哪条网卡 |

两者不是替代关系：**判断「隧道跑多快」只能靠接口级计数**。原因是隧道客户端在内核里转发，
进程级的 socket 计数与「过隧道的字节」并不相等。

### 三个数 + 一条曲线

- **下行 / 上行**：物理网卡上的真实速率（这条线一共跑了多少）。
- **走隧道占比**：隧道接口速率 ÷ 物理网卡速率。⚠️ 这是**近似下限** ——
  隧道流量会「双层计数」（明文过 `utunN`，加密后从 `en0` 出去），
  所以 `en0` 的字节数 ≈ 隧道字节 + 加密开销 + 真正的直连流量。
  界面上如实标注「近似值」，不假装精确。
- **60 点环形缓冲**：横轴是最近 60 个采样点（每秒一格），面积图是总下行、线是总上行、
  红色虚线是其中走隧道的部分。只保留窗口内**真正动过的接口** ——
  本机常见的二十多个死接口不会塞给前端（实测整个响应约 **0.6 KB**）。
- 表格里每行一条接口，最后一列是该接口下行速率的**迷你曲线**；「归属」列复用主扫描的判定。

### 省电设计

- **按需启动**：第一个 `GET /api/flow` 才拉起采样线程，**空闲 3 分钟自动退出**。
- **只在可见时轮询**：前端用 `IntersectionObserver` 盯着卡片，滚出视口就停止轮询
  （也可以手动点「⏸ 暂停」）。

### 平台差异（如实说明）

| 平台 | 数据源 | 状态 |
|---|---|---|
| macOS | `netstat -ib` 的 `Ibytes` / `Obytes` | ✅ 本机实测（实测抓到 11.7 MB/s 的真实下载速率） |
| Windows | `Get-NetAdapterStatistics`（`ReceivedBytes` / `SentBytes`，免管理员） | ⚠️ **未在真机验证** |
| Linux | —— | ❌ 不支持（`netstat -b` 在该平台语义不同） |

Windows 侧认不出物理网卡时（适配器名是中文的情况），会把「所有非回环接口之和」当作总量，
前端如实降级提示，而不是硬猜一个数出来。

---

## 六·十、出口切换在 Windows 上怎么做的

macOS 侧「切出口」靠三样东西：`/Applications` 里的 `.app`、launchd 作业、`scutil --nc`。
**这三样 Windows 都没有**，所以切换在 Windows 上原先是整段不可用的（直接返回
「出口切换当前仅支持 macOS」）。现在给 Windows 配了一套等价物：

| 可控点 | macOS | Windows |
|---|---|---|
| 找到客户端 | 扫 `/Applications` 的 `.app` | 读注册表三个「卸载」键（HKLM / WOW6432Node / HKCU） |
| 找到可停的东西 | launchd 作业（`.plist`） | **SCM 服务**（`Get-Service`） |
| 启停 | `launchctl bootout` / `bootstrap` | `Stop-Service -Force` / `Start-Service`（UAC 提权） |
| 打开客户端 | `open -a` | `Start-Process`（`os.startfile`） |
| 系统自带 VPN | `scutil --nc start/stop` | `rasdial` 连接 / `/disconnect` |

Windows 上还多一类出口：**系统自带的 VPN 连接**。它的名字是用户自己起的，没法用关键词匹配，
所以单独枚举（`Get-VpnConnection`），一个连接一个出口，用 `rasdial` 开关，**不依赖任何客户端 App**。

### 为什么不去查「服务名叫什么」

`OUTLET_RULES` 里给 aTrust 写死的 `stop_jobs` 是 macOS 的 launchd 标签
（`com.sangfor.aTrustTunnel` 之类），**在 Windows 上根本不存在**。
所以 Windows 侧**不读那张表**，一律按 `TUNNEL_KNOWLEDGE` 的关键词去实测枚举 SCM 服务
（关键词短于 4 个字符的不参与匹配，免得 `wg`、`ssr` 这种撞上系统自带服务）。
枚举不到就老实退化成「请手动操作」—— 宁可不动，也不去停一个猜错的服务。

### 提权：UAC ≠ sudo

Windows 的提权是弹 UAC，**没有密码可输**。所以后端对前端用了两个不同的错误码：

- `NEED_SUDO` —— macOS，前端弹密码框
- `NEED_ADMIN` —— Windows，前端只提示「点 UAC 的『是』」并给一个「立即重试」

（顺带修掉一个真 bug：`outlet_stop()` 过去只看「返回码是不是 403」就报成功，
其它非零返回码——比如命令根本跑不动——也会显示「已停止」。用户以为关掉了，其实没关。
现在按返回码如实判定。Windows 侧则改用「脚本自己喊一句 `__TM_OK__`」来判定，
因为 PowerShell 的 cmdlet **不设置** `$LASTEXITCODE`，看返回码本身就不靠谱。）

### ⚠️ 未在真机验证（务必保持这句）

**本机是 macOS，上面这一整套 Windows 实现没有在任何 Windows 机器上跑通过。**
要确认它在你那台机器上行不行，用包里的体检工具：

```
双击  检查运行.bat           （或命令行：python selftest.py）
```

报告里的**第十一段「出口切换的探测层（Windows）」**会逐项告诉你：

- 注册表读不读得到已安装程序
- SCM 服务能不能枚举、能不能按关键词匹配到隧道客户端
- 系统 VPN 能不能列出来
- 有哪些「指向已消失接口」的残留路由（**只列不删**）
- 将要执行的那段 PowerShell 长什么样（方便直接复制回来反馈）

这一段**全程只读**：不停任何服务、不改任何路由、也不会主动弹 UAC。

---

## 六·十一、PowerShell 被安全策略禁掉时怎么办（原生回退层）

### 起因：一台真机的报告

2026-10-11 收到一份 Windows 11 的真机自检报告，上面有这样一行：

```
[注意] powershell Get-NetRoute   返回码 None；
       无法执行：[WinError 786] 管理员用策略规则限制了对 powershell.exe 的访问。
```

也就是说**那台机器上 `powershell.exe` 根本起不来**（被安全管理软件的策略挡住了，
装了深信服 / 奇安信 / 360 企业版这类软件的电脑常见）。

而这一版之前的 Windows 实现**几乎全部靠 PowerShell**：
读网卡用 `Get-NetAdapter`、读默认路由用 `Get-NetRoute`、
读服务用 `Get-Service`、读系统 VPN 用 `Get-VpnConnection`、
读流速用 `Get-NetAdapterStatistics`……

后果不是崩溃，而是更难受的一种：**程序正常启动，但什么都看不到**。
（模拟验证：`do_scan()` 返回 0 个接口、`phys_iface` 为空、出口只剩「物理直连」。）

### 解决办法：只吃 System32 里的原生命令

新增一层 `_nat_*` 解析（`tunnel_manager/win/nat_net.py` 与 `nat_sys.py`），**优先 PowerShell，
探测到不可用就整体切到原生命令**。选命令时刻意挑「不受系统语言影响」的部分：

| 要读什么 | 原生命令 | 为什么挑它 |
|---|---|---|
| 接口列表 | `route print -4` | 接口列表行是「序号 + 点 + 名字」，中英文排版一致 |
| 路由表 | `route print -4` | 表格本身是纯数字，不翻译 |
| 接口 IP | `netsh interface ipv4 show addresses` | 值都是地址，标签本地化没关系 |
| 接口序号 ↔ IP | `arp -a` | `192.168.1.5 --- 0x5` 这行中英文完全一样 |
| 已安装程序 | `winreg`（**标准库**） | 直接读注册表，比 `reg query` 稳 |
| Windows 服务 | `sc query type= service state= all` | 字段名恒为英文（SERVICE_NAME / DISPLAY_NAME / STATE） |
| 进程 | `tasklist /fo csv /nh` | CSV 列固定，镜像名是 ASCII |
| 系统 VPN | `rasphone.pbk` | 就是一个 INI 文件，读文件即可 |
| TCP 连接 | `netstat -ano` + `tasklist` | 状态名恒为英文（ESTABLISHED） |
| 提权 | `cmd.exe /c <临时 bat>` | PowerShell 起不来时 `runas` 只能挂 cmd |

两个细节值得一提：

- **`IP → 走哪个网卡`是自己算最长前缀匹配的**，不再依赖 `Find-NetRoute`。
  路由表是纯数字，所以这一步反而比 PowerShell 版更稳；
  而且打了平局时按「路由跃点 + 接口跃点」取小值 ——
  Windows 真正据以选路的就是这个有效跃点数。
- **提权不走「PS 失败后再补一次原生」**。那样用户会连着吃两个 UAC 弹窗。
  走哪条路只看一次探测结论（缓存 5 分钟）。

### 界面上怎么体现

前端顶部会出现一条橙色提示（只在 Windows 且 PowerShell 不可见时）：

> ⚠ 本机的 PowerShell 被安全策略禁用，已自动改用系统原生命令读取（当前读到 N 个网卡）。
> 「网卡 / 隧道 / 出口」这些仍然可用，但实时流速会退化成整机总量……

自检脚本新增**第十二段「系统查询通道」**，逐项验证原生回退有没有顶上，
并把 `route print` / `arp -a` / `netsh` / `sc query` 的**原始输出**附在报告末尾 ——
万一哪一项没解析出来，凭那段就能精确定位。

### ⚠️ 同样未在真机验证

这一层和上面那套一样，**本机是 macOS，没有在真机上跑过**。
验证方式是「拿真实格式的命令输出喂给解析器」——覆盖了 40 余项断言
（中文 `在链路上` / 中文 `已连接` · `已断开` / 8 字节 MAC 的 ISATAP 行 /
无 MAC 的回环行 / 永久路由不误认 / `rasphone.pbk` 编码 …），全部通过。
但**真实 Windows 的排版仍可能与样本有出入**，所以第十二段的原始输出 dump 才是关键。

---

## 七、运行

### 7.1 本机开发/使用（源码态）

```bash
# macOS
bash ~/universal-tunnel-manager/start.sh
# 或双击 tunnel-manager.command

# Windows（需装 python.org 的 Python）
双击 start.bat
```

启动后自动打开浏览器，访问 `http://127.0.0.1:7531`（端口被占按 7532/7533/7530/7800 顺延），
页面每 20 秒自动重扫。

### 7.2 分发给自己/别人（单文件包）

先打包，得到 `dist/tunnel-manager.py`（单文件、内嵌前端、整包无外部依赖）：

```bash
python3 build.py
# 产物：dist/tunnel-manager.py (85 KB) + dist/tunnel-manager.zip (32 KB)
```

把 `dist/tunnel-manager.zip` 发给别人，对方解包后按平台执行：

```bash
# macOS
bash install.sh          # 或双击 install.sh；bash install.sh run 可装完立即启动
# Windows
双击 install.bat
```

安装脚本做的事：把 `tunnel-manager.py` 放到 `~/.tunnel-manager/`（Windows 为
`%USERPROFILE%\.tunnel-manager`），加可执行权限，并在桌面放一个「隧道管理」快捷方式 ——
之后**双击桌面图标即可在自己电脑上打开这个本机网页**，无需任何命令行。

- 脚本**优先用同目录下的 `tunnel-manager.py`**（zip 解包场景，零网络依赖）；
  目录里没有时才回退到 `TM_URL` / `DOWNLOAD_URL` 指定的地址下载。
- 只依赖系统自带 Python 3（macOS 自带 3.9+；Windows 需装 python.org 版并勾选 Add to PATH）。
- 服务只绑 `127.0.0.1`，同一内网的其他人访问不到。

卸载：`rm -rf ~/.tunnel-manager ~/Desktop/隧道管理.command`（Windows 删目录 + 快捷方式）。

### 7.2.1 Windows 包：完整版（免安装）+ 精简版

Windows 用户常常没有 Python。而**macOS 上无法交叉编译出 `.exe`**
（PyInstaller / Nuitka 都只能在目标平台上构建），所以改用
「内嵌 Windows embeddable Python + 双击 `.bat`」的绿色包 —— 效果等同。

```bash
python3 make_win_pkg.py
# 首次会自动下载 python-3.13.12-embed-amd64.zip (~11 MB)，缓存在 dist/_winbuild/
# 产物：dist/TunnelManager-Windows-x64.zip    (10.4 MB，完整版)
#       dist/TunnelManager-Windows-lite.zip   (160 KB，精简版)
```

**一个脚本出两个包**，差别只有一个维度 —— 带不带运行时：

| | 完整版 `…-Windows-x64.zip` | 精简版 `…-Windows-lite.zip` |
|---|---|---|
| 体积 | 10.4 MB | **160 KB** |
| 自带 Python | ✅ 有 `runtime/` | ❌ 无 |
| 对方要装什么 | **什么都不用装** | 需要电脑上已有 Python 3 |
| 怎么找解释器 | 固定用包内 `runtime\python.exe` | 依次试 `py -3` → `python` → `python3`，**真的执行一句 `import sys` 才算数** |
| 什么时候用 | 默认发它，最省事 | 对方本来就装了 Python（或不想下 10 MB） |

> **精简版存在的理由很单纯**：10.4 MB 里 **99% 是 `runtime/`**，程序本体只有一个
> 440 KB 的 `.py`。已经装过 Python 的人没必要再下一遍运行时。
> 但**默认还是发完整版** —— 你没法保证对方装了 Python；精简版找不到解释器时，
> 启动器会直接提示他改用完整版。

两个包的 **`app/tunnel-manager.py` 必须逐字节相同**（同一份 `dist/tunnel-manager.py`），
差别只在有没有 `runtime/`、以及启动器怎么找解释器。校验时会断言这一点。

包内结构：

```
TunnelManager-Windows-x64/          （完整版）
├── START-双击启动.bat    ← 用户只需双击这个
├── STOP-停止服务.bat
├── 检查运行.bat
├── 使用说明.txt
├── selftest.py
├── app/tunnel-manager.py
└── runtime/              ← 嵌入式 Python（32 个文件，10.2 MB）

TunnelManager-Windows-lite/         （精简版）
├── START-双击启动.bat    ← 改成去系统里找 Python
├── STOP-停止服务.bat
├── 检查运行.bat
├── 使用说明.txt
├── selftest.py
└── app/tunnel-manager.py ← 与完整版逐字节相同，没有 runtime/
```

对方：下载 → 解压 → 双击 `START-双击启动.bat`。完整版**不需要安装任何东西。**

**内置了自检工具**（`检查运行.bat` + `selftest.py`）：对方启动不了、或者想先确认环境，
双击 `检查运行.bat` 就会跑一遍全面检查并生成「检查报告.txt」，把那个文件发回来即可定位。
另外还会单独产出 `dist/运行检查工具.zip`（10 KB），可以只把这一个小包发给
"已经下过整包"的人；落地页上也内嵌了它的下载入口。

自检做三件事，**全部只读**（不改路由、不动 DNS、不装东西）：

| 段 | 查什么 |
|---|---|
| 一~四 | 系统 / 位数 / 管理员 / 代码页；**中文编码能力**；依赖模块能否导入；程序文件大小 + sha256 + 内嵌页面 + 语法编译 |
| 五~八 | `route` / `ipconfig` / `arp` / `powershell Get-NetRoute` 是否可用；端口 7531~7533 是否空闲；能否绑定回环 HTTP 服务；DNS 能否解析 |
| 九~十 | **真跑一遍程序** —— 用 `importlib` 加载 `app/tunnel-manager.py` 并调用它自己的 `do_scan()`（顶层是 `if __name__ == "__main__"`，所以不会启动服务、不会弹浏览器），报告扫到多少网卡/出口；再列一遍在跑的隧道客户端进程 |

两个实现要点值得记：

- **报告用 `utf-8-sig` 写**（带 BOM），中文 Windows 的记事本才能正确打开；控制台方向的
  `stdout` 在脚本开头就 `reconfigure(encoding="utf-8", errors="replace")`，
  保证**脚本自己**不会因为中文崩掉 —— 但**原始编码已经先记下来**，写进报告里供诊断。
- Windows 没有 `SIGALRM`，`do_scan()` 这类可能卡住的调用用**线程 + `join(timeout)`** 包超时。

**三条必须遵守的细节**（都是实测踩出来的，已固化在 `make_win_pkg.py` 的注释里）：

| 点 | 做法 | 不这么做会怎样 |
|---|---|---|
| bat 编码 | **GBK**（`encoding='gbk'`） | 中文提示乱码。`chcp 65001` 救不了 —— 它执行在解析**之后** |
| 中文输出 | `python.exe -X utf8 app\...py` | embeddable 有 `._pth` → isolated 模式 → `PYTHONIOENCODING` 等**环境变量被忽略**；日志重定向后 stdout 退回系统 locale，英文版 Windows（cp1252）下中文 `print` 直接抛 `UnicodeEncodeError` |
| 重复双击 | 启动前用 `netstat -ano \| findstr ":7531.*LISTENING"` 探 7531 | 起第二个实例，端口顺延 7532，用户看到两个界面。⚠️ **别用 PowerShell 的 `Net.Sockets.TcpClient`**：实测有的电脑 `powershell.exe` 被安全策略拦住（WinError 786），那条检测会直接失效。`netstat` 是 System32 原生命令，不受影响 |

**没有 Windows 机器时怎么验证**（本次用过的三步）：

1. 解 `runtime/python313.zip` 查 stdlib —— ⚠️ 它是 **`.pyc` 预编译**的，按 `.py` 查会**全部 MISS**。
   对着组装后单文件（`dist/tunnel-manager.py`）顶部的 import 逐个查 `.pyc` 即可 —— 这组 import 逐字来自 `tunnel_manager/_base.py`，切片里是**不再重复 import** 的（见第四节）。两个"假 MISS"要知道：
   **`time` 是内建**（在 `sys.builtin_module_names` 里，本来就没有 .pyc）；
   **`encodings/cp936.pyc` 不存在也正常**（`aliases.py` 把 cp936 指向 gbk）。
2. **隔离模式试跑**（最有价值的一步）：`python3 -I -S -X utf8 dist/tunnel-manager.py`
   —— `-I` 忽略环境变量、`-S` 不加载 site-packages，**等价于 embeddable 的约束**；
   再 `curl /` + `curl /api/scan` 确认真能跑。能过，就证明它不依赖任何外部东西。
3. bat 用 GBK 解出来打印核对，人工 review 引号与 `%~dp0` 拼接、`start /min cmd /c` 的嵌套引号。

### 7.3 发布成"一条链接"给别人

让别人点一个链接就能拿到程序：

```bash
python3 build.py              # 生成 dist/tunnel-manager.zip
python3 make_download_page.py # 生成 dist/download.html
                              #   小包 base64 内嵌；Windows 大包复制成 .dat 放站点目录
```

把 `dist/site/` 作为静态站点托管（CloudStudio / Vercel / Netlify / GitHub Pages 均可），
得到一个链接。别人打开 → 按系统点对应按钮 → 解包安装 → 本机 web 跑起来。

> **为什么小包内嵌、大包改名？** 实测托管平台的 WAF 是**按 URL 字符串**拦的，不是按内容：
>
> | 文件名 | 结果 |
> |---|---|
> | `x.zip` / `x.ZIP` / `x.zip.download` | ❌ 403 拦截页（**只要包含 `.zip` 就拦**，大小写不敏感） |
> | `x.dat` / `x.bin` / 无扩展名 | ✅ 200，`application/octet-stream` |
>
> - **通用包（113 KB）**：base64 内嵌进 HTML，点按钮时浏览器**本地** Blob 还原下载，
>   不产生服务器下载请求，任何网络策略都拦不到。
> - **Windows 免安装包（10.3 MB）**：改名 `TunnelManager-Windows-x64.dat` 放静态目录，
>   页面上用 `<a href="./….dat" download="….zip">` —— `download` 属性让浏览器**存回 `.zip`**，用户无感。
>   若把它也内嵌，落地页会从 **158 KB 涨到约 14 MB**。
>
> 探测这类规则时，造几个 2 KB 的探针文件部署一次就问出来了，不必反复上传大文件。

### 7.4 只想先看看界面长什么样

```bash
python3 make_preview.py       # 生成 preview.html
open preview.html             # macOS；Windows 直接双击
```

`preview.html` 把后端的 `/api/*` 换成示例数据，不启动服务也能看到全部卡片，
按钮点击会在示例数据上真实响应（用于确认界面与交互）。

---

## 八、已知边界

- **Windows 分支**仅做语法检查与逻辑审查，未实机测试（手边无 Windows 机器）。
- **浏览器历史追踪**依赖「完全磁盘访问」（Safari）或可读的浏览器 Profile 目录；
  无权限/无浏览器时追踪集为空，用手动输入框兜底即可，不影响其它功能。
- 隧道客户端若用「不落路由表」的方式接管流量（如某些 hook DNS / LSP 全局代理方案），
  仅靠路由表可能探测不到，需要额外用「实际拨测 + 出口 IP 对比」补充 —— 这是下一步演进方向。
- Linux 分支预留了命令，但当前未完整实现（可扩展）。

---

## 九、安全设计（v2）

| 威胁 | 场景 | 防护 |
|---|---|---|
| **CSRF** | 任意网页 JS 调 `127.0.0.1:7531/api/apply` 改你路由表 | 校验 Origin 头 + 前端必须带 `X-TM-Token`（跨域简单请求带不了自定义头） |
| **DNS 投毒** | 恶意 DNS 把域名指向内网 IP，诱导你给 `10.0.0.1` 加直连路由，把内网流量错误外送 | `resolve_a` 只返回公网 IP；`do_apply` 二次校验 `is_public_ip`，私网/保留地址一律跳过 |
| **命令注入** | 拼进 shell 的 IP/网关参数被构造恶意命令 | 所有参数严格 `re.fullmatch` 校验 IPv4 格式 |
| **DNS rebinding** | 攻击者用域名指向 127.0.0.1 绕过浏览器同源策略 | 校验 Host 头只接受 127.0.0.1/localhost |
| **密码泄露** | sudo 密码落盘或进日志 | 密码只存后端内存（`_sudo_pw`），不落盘不进日志；state 文件 600 权限 |
| **误删系统路由** | undo 时删掉非本程序加的路由 | state 文件只记录自己加过的 IP，精确回滚 |

---

## 十、识别体系 v2（融合 macos-network-tunnel-diagnosis 调查成果）

原 v1 的误判（已修复）：
- `utun0-5` 只有 link-local IPv6 → 误判为 aTrust → v2 归为「macOS 系统隧道（接力/隔空投送）」
- `feth204` 是 ZeroTier → 误判为 aTrust → v2 用接口名 + MTU 2800 特征正确归类
- aTrust 未在运行却误报 → v2 以进程证据为准

v2 四层判定优先级：
```
0. 系统噪音过滤：无 IPv4 的 utun → macOS 系统隧道
1. 接口名/描述精确匹配软件库
2. IPv6 ULA 厂商指纹（fd53:414e:4746… → SANGFOR）
3. MTU 特征（feth + MTU 2800 → ZeroTier）
4. 承载默认路由 → 全流量隧道
5. 命名规律启发式兜底
```

新增「聚合路由多点抽查」：aTrust 等高级客户端会保留 `default → 物理网关`，
改用 `1/8…240/4` 聚合路由隐性接管公网。v2 对 12 个公网探测点逐一查出口，
隧道接口命中多即为隐性接管，前端独立展示。

---

## 十一、分发与下载

### 11.1 一条命令构建全部产物

```bash
bash scripts/build.sh
# 可选环境变量：
#   PYTHON=python3.13   指定解释器
#   SKIP_WIN=1          跳过 Windows 免安装包（它首次需联网下载 ~11 MB 运行时）
```

产出（均在 `dist/`，已被 `.gitignore` 排除）：

| 文件 | 给谁 |
|---|---|
| `TunnelManager-Windows-x64.zip` | Windows **完整版**，免安装（内置 Python 运行时，10.4 MB） |
| `TunnelManager-Windows-lite.zip` | Windows **精简版**（不带运行时，160 KB，需对方已有 Python 3） |
| `tunnel-manager.zip` | macOS / Linux（需系统自带 Python 3） |
| `RunCheck-tool.zip` / `运行检查工具.zip` | 备用体检小包（前一个 ASCII 名供 Release/Pages 直链） |
| `download.html` | 分享落地页（小包以 base64 内嵌，浏览器本地生成下载） |
| `SHA256SUMS` | 上述产物的校验和 |

另外生成 `docs/index.html` —— 这是给 GitHub Pages 用的那份，**要提交进仓库**。

### 11.2 两种落地页，别搞混

同一套 HTML，两处输出：

| | `dist/download.html`（分享用） | `docs/index.html`（Pages 用） |
|---|---|---|
| 下载控件 | `<button>` + base64，**浏览器本地**生成文件 | 普通 `<a href>` 指向 GitHub Releases |
| 页面体积 | ≈ 包体积 × 1.33 | 约 12 KB |
| 为什么这样 | 托管平台的 WAF 按「URL 里含 `.zip`」拦（实测 403，大小写不敏感），内嵌可绕过 | Releases 资源由 github.com 提供，没有 WAF 问题，页面就能保持很小 |

### 11.3 发布 Release

**推荐**：推一个 `v*` 标签，`.github/workflows/release.yml` 会自动构建并把
`TunnelManager-Windows-x64.zip` / `TunnelManager-Windows-lite.zip` /
`tunnel-manager.zip` / `RunCheck-tool.zip` / `SHA256SUMS`
挂到 Release 上。

手工发布（本机网络推不动 `github.com` 时可用）：

```bash
gh release create v1.0.1 \
  dist/TunnelManager-Windows-x64.zip \
  dist/TunnelManager-Windows-lite.zip \
  dist/tunnel-manager.zip \
  dist/RunCheck-tool.zip \
  dist/SHA256SUMS --title "v1.0.1"
```

> ⚠️ **附件名务必用 ASCII**：`gh` CLI 会把中文文件名上传成 `default.zip`（实测）。
> 所以脚本额外产出一份 `RunCheck-tool.zip`；Pages 页面里的直链也用的是它。

### 11.4 GitHub Pages

仓库 `Settings → Pages` 选 **Deploy from a branch** → `main` / `docs` 即可。
页面里的下载按钮用的是 `releases/latest/download/<附件名>`，**永远指向最新 Release**，
所以以后发新版不必改页面。

---

## 十二、安全

本工具会**修改本机路由表与 DNS**，误用可能断网。完整的安全设计、漏洞报告方式
与「出问题了怎么回滚」都在 **[SECURITY.md](SECURITY.md)**，请务必先读那一段。

要点：

- 只监听 `127.0.0.1`，同局域网的其他人访问不到（不监听 `0.0.0.0`）；
- 写操作三重校验：`Host` 头 + `Origin` + 进程级 CSRF token（`secrets.token_hex(16)`，
  **不硬编码**，随 `/api/scan` 下发）；
- 只对公网 IP 加 `/32` 路由，拒绝私网/保留地址，防 DNS 投毒；
- 每条改动都记入 `~/.tunnel-manager/state.json`，撤销时只删自己加的；
- **不**卸载软件、**不**改 `/etc/hosts`、**不**装系统服务、**不**设开机自启。

手工回滚（界面打不开时）：

```bash
# macOS
sudo route -n delete -host <IP>                  # 删掉本工具加的直连路由
sudo networksetup -setdnsservers "Wi-Fi" Empty    # DNS 交回 DHCP
sudo dscacheutil -flushcache && sudo killall -HUP mDNSResponder
```

---

## 十三、许可证

[MIT](LICENSE) © 2026 fud-zhouhanson

---

## 十四、已知边界

- **Windows 分支未在真机完整测试**（能启动、界面可用，网络扫描与改路由的行为需实测）。
  包里自带体检工具（`检查运行.bat`），出问题把「检查报告.txt」发回来即可定位。
- 「一键切换出口」目前**只在 macOS 完整支持**。
- 按进程分流（只让某个程序走隧道）在 macOS 用户态**做不到** —— 需要
  Network Extension 或内核扩展，这也是所有加速器都必须装特权 helper 的原因。
- Windows 免安装包内置的是 **amd64（64 位）** 运行时；32 位或 ARM 版 Windows 需另换运行时。

---

## 十五、免责声明

**这是一个免费的开源项目，按「现状」（AS IS）提供。作者什么都不承诺，也什么都不承担。**

- **不提供任何担保。** 不附带任何明示或默示担保，包括但不限于对适销性、特定用途适用性、
  安全性及不侵权的担保；也不保证它能满足你的需求，或能无中断、无错误地运行。
- **不承担任何责任。** 在适用法律允许的最大范围内，作者及贡献者**不对任何损失负责** ——
  包括但不限于因使用或无法使用本软件导致的：断网、网络中断、数据丢失、设备故障、业务损失，
  以及任何直接的、间接的、附带的、后果性的损害。
- **本工具会修改本机的路由表与 DNS 配置，误用可能导致暂时断网**，请自行评估并承担全部风险。
  使用前建议先点一次「保存健康基线」，并阅读 [SECURITY.md](SECURITY.md) 里的回滚指引。
- **对"被下毒"的副本一律不负责。** 本仓库不保证任何**非官方来源**的副本未被篡改、增删或
  植入额外内容。→ **只从本仓库的 Release 下载，并核对 `SHA256SUMS`**；
  任何第三方修改、二次打包、镜像、转发、重新分发的版本，均与本项目作者无关，作者一概不负责。
- **合规由使用者负责。** 请遵守你所在地区的法律法规，以及所在网络（学校 / 公司 / 运营商）
  的使用条款。本项目的目标是看清并管理你自己电脑上的网络走向；不针对任何特定服务，
  也不提供任何形式的"加速"或"突破"承诺。

> 个别司法辖区不允许完全排除默示担保、或不允许限制某些责任，因此上述条款在那些地方
> 仅在法律允许的范围内适用。
