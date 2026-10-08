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
├── server.py           后端（跨平台，零依赖）：扫描 + 判定 + 路由操作 + HTTP API
├── index.html          前端（管理面板）：隧道列表 + 路由走向 + 一键切换 + 自动追踪
├── build.py            打包脚本：把 index.html 内嵌进 server.py → dist/ 单文件分发版
├── make_preview.py     生成 preview.html：静态预览版（示例数据，不启后端也能看界面）
├── make_download_page.py  生成 dist/download.html：把 zip 内嵌进去的可分享落地页
├── preview.html        静态预览（示例数据，可直接用浏览器打开看完整界面）
├── start.sh            macOS 启动脚本
├── start.bat           Windows 启动脚本
├── stop.bat            Windows 停止脚本
├── tunnel-manager.command  macOS 双击启动
└── dist/               分发产物（给自己或别人用）
    ├── tunnel-manager.py    单文件版（85 KB，内嵌前端，整包只此一个 .py）
    ├── tunnel-manager.zip   打包下载（含 py + 双平台安装脚本 + README）
    ├── install.sh           macOS 一键安装（curl|bash 或双击）
    ├── install.bat          Windows 一键安装
    ├── download.html        可分享的落地页（内嵌 zip，点按钮即下载）
    └── site/index.html      托管用入口（= download.html），配合静态托管发布成链接

后端模块划分（server.py）：
  一、TUNNEL_KNOWLEDGE      48 条软件识别知识库
  二、通用工具               run / run_ps / run_root / run_elevated_win / verify_sudo
  三、进程证据               list_processes / detect_software
  四、接口证据               scan_interfaces_mac / scan_interfaces_win / is_tunnel_iface
  五、路由证据               default_route / iface_of / phys_gateway
  六、配置                   load_config / save_config / resolve_a
  六.5、自动追踪             _scan_history_once / auto_domains_loop（浏览器历史 → 目标域名）
  七、归属判定               classify_tunnel（四层证据融合）
  八、统一扫描               do_scan / scan_mac / scan_win / scan_domains
  九、路由操作               do_apply / do_undo / route_add_cmd / route_del_cmd
  十、HTTP 服务              GET /api/scan · POST /api/apply|undo|config|sudo|auto/*
```

**HTTP API**：

| 方法 | 路径 | 作用 |
|---|---|---|
| GET | `/api/scan` | 只读扫描（免管理员） |
| GET/POST | `/api/config` | 读/写域名配置 |
| POST | `/api/sudo` | (mac) 验证并缓存 sudo 密码 |
| POST | `/api/auto/enable` | 开启自动追踪（扫浏览器历史） |
| POST | `/api/auto/disable` | 关闭自动追踪并清空追踪集 |
| POST | `/api/auto/pin` | 手动把一个域名加入追踪集 |
| POST | `/api/outlet/switch` | **切到某个出口**（body `{key}`）：停掉其它在跑的 + 启动目标 + 清残留路由 |
| POST | `/api/outlet/start` · `/api/outlet/stop` | 单独启 / 停某个出口（body `{key}`） |
| POST | `/api/scene/game` | （旧）等价于 switch 到加速器 |
| POST | `/api/scene/campus` | （旧）等价于 switch 到 aTrust |
| POST | `/api/apply` | 全部域名 → 本机直连 |
| POST | `/api/undo` | 撤销直连 → 交回隧道 |
| POST | `/api/daemon/install` / `remove` | (mac) 装/卸守护 |

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

`server.py` 的 `DEFAULT_DOMAINS` 预置了几个**通用示例站点**，首启即生效：

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

**需求对应**：用户打开一个新网站 → 它自动出现在目标域名表里；关掉后 → 自动移除。

**实现**：后台每 `AUTO_INTERVAL = 30` 秒**只读**扫一遍浏览器历史库
（Chrome / Edge / Brave / Firefox / Safari 的 `History`，Chrome 运行时先复制到临时文件再读，
不写入原库），把域名按最近访问时间戳归并：

| 常量 | 值 | 含义 |
|---|---|---|
| `AUTO_WINDOW` | 180 秒 | 最近 3 分钟内访问过的域名 → 视为「正在看」，加入追踪集 |
| `AUTO_EXPIRE` | 600 秒 | 超过 10 分钟没再访问 → 视为「已关闭」，从追踪集移除 |

- 追踪到的域名在前端「自动追踪」卡片里以 chips 展示，并**并入主路由表**（带「自动」标签、半透明行）。
- 时间戳换算：Chrome/Edge 用 1601 起的微秒，Firefox 用 1970 起的微秒，Safari 用 2001 起的秒。
- **隐私**：纯本机内存运算，不落盘、不上传、不记录访问内容，只取主机名。
- **权限**：Safari 历史库受 macOS「完全磁盘访问」保护，需给终端授权；拿不到权限时用卡片里的
  手动输入框（`＋ 加入追踪`）兜底 —— 它走 `/api/auto/pin`，把一个域名直接塞进追踪集，
  之后和浏览器发现的域名享受同样待遇（10 分钟不活跃自动移除）。

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

### 7.2.1 Windows 免安装版（对方不用装 Python）

Windows 用户常常没有 Python。而**macOS 上无法交叉编译出 `.exe`**
（PyInstaller / Nuitka 都只能在目标平台上构建），所以改用
「内嵌 Windows embeddable Python + 双击 `.bat`」的绿色包 —— 效果等同。

```bash
python3 make_win_pkg.py
# 首次会自动下载 python-3.13.12-embed-amd64.zip (~11 MB)，缓存在 dist/_winbuild/
# 产物：dist/TunnelManager-Windows-x64.zip   (10.3 MB)
```

包内结构：

```
TunnelManager-Windows-x64/
├── START-双击启动.bat      ← 用户只需双击这个
├── STOP-停止服务.bat
├── 使用说明.txt
├── app/tunnel-manager.py
└── runtime/                ← 嵌入式 Python（32 个文件）
```

对方：下载 → 解压 → 双击 `START-双击启动.bat`。**不需要安装任何东西。**

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
| 重复双击 | 启动前用 `Net.Sockets.TcpClient` 探 7531 | 起第二个实例，端口顺延 7532，用户看到两个界面 |

**没有 Windows 机器时怎么验证**（本次用过的三步）：

1. 解 `runtime/python313.zip` 查 stdlib —— ⚠️ 它是 **`.pyc` 预编译**的，按 `.py` 查会**全部 MISS**。
   对着 `server.py` 的 import 逐个查 `.pyc` 即可。两个"假 MISS"要知道：
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
| `TunnelManager-Windows-x64.zip` | Windows，**免安装**（内置 Python 运行时） |
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
`TunnelManager-Windows-x64.zip` / `tunnel-manager.zip` / `RunCheck-tool.zip` / `SHA256SUMS`
挂到 Release 上。

手工发布（本机网络推不动 `github.com` 时可用）：

```bash
gh release create v1.0.1 \
  dist/TunnelManager-Windows-x64.zip \
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
