# Self-Hosted Subscription Converter with Chain Proxy — Implementation Spec

> **Abstract (EN):** A fully self-hosted subscription conversion backend for
> Mihomo (Clash) and sing-box clients. It ingests node lists and subscription
> URLs in four source formats, generates chained-proxy configurations
> (entry hop → exit hop), serves them through opaque short links, and mirrors
> the official rule files (MetaCubeX for Mihomo, SagerNet for sing-box) on the
> same host with scheduled refreshes. No user data ever leaves the operator's
> own server: original subscription URLs are stored only in a server-side
> mapping file, never embedded in generated links, never written to logs.
> This document is an implementation-ready specification: architecture,
> algorithms, parameters, deployment, verification and operations.

# 自托管订阅转换与链式代理后端 · 落地实施文案

本文是一份可直接照着实施的工程规格：目标、架构、核心算法、参数定版、部署
手册、验证手册与运维手册。文中所有域名、端口、路径均为示例值
（`sub.example.com` 等），实施时替换为自己的即可。

> **Implementations / 落地形态**：本仓库含 VPS 落地实现（`deploy/`）。
> Cloudflare Workers 版为独立仓库
> [subscription-chain-converter-cf](https://github.com/dukangalex/subscription-chain-converter-cf)：
> 转换内核与本规格一致，部署与页面借鉴 sublink-worker 的形态
> （仓库根即 Worker 工程、一键部署按钮、快速上手指引）。

## 1. 目标与设计原则

1. **自托管、数据不出门**：转换在自己的服务器上完成，原始订阅地址（含
   token）只保存在服务器本地，不经过任何第三方转换服务。
2. **链式代理是一等公民**：入口（第一跳）× 出口（第二跳）的组合订阅与
   普通转换同等重要，生成的配置开箱即用。
3. **规则只用官方源、自己维护**：规则文件只取官方仓库（Mihomo 侧
   MetaCubeX、sing-box 侧 SagerNet），在本机做镜像并定时更新；规则的
   组织（策略组、规则顺序、DNS 基线）由后端自己的骨架维护，不依赖任何
   第三方覆写脚本。
4. **有效即能用**：只要输入是有效的订阅/节点，生成的配置必须能被内核
   真正启动并跑通流量；仅通过静态检查不算数（见第 7 章验证手册）。
5. **隐私默认拉满**：日志不记链接与内容；映射文件权限 0600；凭据不进
   代码仓库。

## 2. 总体架构

```
客户端 (Mihomo / sing-box App)
        │  HTTPS 拉取短链 / 规则文件
        ▼
公网入口（自有域名的 CDN 隧道或反向代理，按路径分流）
        ├── /            → 页面服务（静态页）
        ├── /chain /conv /sub /version → 页面服务
        ├── /c/<码> /m/<码> /s/<码>    → 页面服务（短链解析后生成）
        ├── /shorten     → 页面服务（POST，创建短链）
        ├── /rules/...   → 页面服务（规则镜像下发）
        └── 其余路径     → 订阅分发/其他自有服务（可选）
        ▼
页面服务 (subpage, 单文件 Python, 仅监听回环)
        ├── 生成：摄入引擎 → 普通转换 / 链式构建器（自有骨架）
        ├── 短链存储 links.json（0600）
        └── 规则镜像 rules_files/（refresh_rules.py 定时刷新）
        ▼
转换引擎 (subconverter, 本地回环端口)
        └── 把任意源格式统一转成目标中间格式
```

组件清单：

| 组件 | 形态 | 职责 |
|---|---|---|
| 页面服务 | 单文件 Python（标准库 http.server） | 静态页、生成入口、短链、规则下发 |
| 转换引擎 | subconverter 二进制（本地部署） | 源格式 → 中间格式的节点级转换 |
| 骨架文件 | skeleton_clash.json / skeleton_singbox.json | 策略组、规则、DNS、嗅探的自有定版 |
| 规则清单 | rules_manifest.json | 官方源 URL → 本地镜像路径的映射表 |
| 刷新脚本 | refresh_rules.py + systemd timer | 定时拉取官方规则、校验、原子替换 |
| 短链存储 | links.json | 短码 → 原始参数映射（0600） |

## 3. 摄入引擎（源格式归一化）

生成前先把用户给的每一项（节点链接或订阅 URL）归一化为节点列表：

- 支持四类源：分享链接（URI，一行一个）、Clash YAML、base64 编码的
  URI 列表、sing-box JSON。混合填写时逐项识别。
- 抓取订阅时按 UA 顺序兜底：客户端 UA → sing-box UA → 浏览器 UA，
  直到拿到可解析内容（不同机场按 UA 返回不同格式）。
- 转换必须保真保留：anytls 等新协议、ECH 相关字段
  （`ech-opts` / `tls.ech`）、 Reality、uTLS 指纹等，不得静默丢弃。
- 节点级转换复用转换引擎：先把入口、出口分别转成目标中间格式
  （Clash 走 YAML、sing-box 走 JSON），再由链式构建器组装。

## 4. 普通转换

- 接口：`GET /conv?target=clash|singbox&url=<urlencoded 源列表，| 分隔>`
  由自研管线生成；其他目标格式（v2ray/surge/loon/quanx）走
  `GET /sub?...` 透传给转换引擎。
- 对外只推荐短链形式（见第 6 章），长链仅作内部兜底保留兼容。

## 5. 链式构建器（核心算法）

输入：入口节点列表 E、出口节点列表 X（已转成目标中间格式）。
输出：一份完整客户端配置。步骤对两种目标同构：

1. **命名**：入口节点名加前缀 `入口-`，出口加 `出口-`。Clash 侧若原名
   以国旗 emoji 开头，前缀插在旗帜之后成为第二个词
   （如 `🇺🇸 出口- 美国 1.2.3.4:443`）；sing-box 侧用朴素前缀。
2. **串联**：每个出口节点设置第二跳经入口组：Clash 用
   `dialer-proxy: ⛓ 入口优选`，sing-box 用 `detour: ⛓ 入口优选`。
3. **分组（策略组定版，两种目标同名同构）**：
   - `⛓ 入口优选`（urltest）：仅入口节点。
   - `⛓ 出口优选`（urltest）：仅出口节点，置于主选择器首位。
   - `默认代理`（select）：[出口优选, 入口优选, 手动选择, 自动选择,
     负载均衡, 故障转移]（Clash）；sing-box 侧为前四项。
   - `手动选择`（select）：全部节点（入口在前、出口在后）。
   - `自动选择` / `负载均衡` / `故障转移`：仅出口节点。
   - 应用分组（FCM、YouTube、Google、Claude、AI、Microsoft、Apple、
     Telegram、Steam、TikTok、Twitter、Meta、Line、Netflix、Emby、
     PikPak、Spotify、Crypto、EHentai、远控工具、AdBlock、漏网之鱼、
     直连 等）：成员为组间引用定版（如
     [默认代理, 手动选择, 自动选择, 负载均衡, 故障转移, 出口优选]），
     不直接装节点。
   - **入口隔离铁律**：入口节点只允许出现在 `⛓ 入口优选` 与
     `手动选择` 中，任何自动组不得直选入口（防止单跳直连出口语义被
     绕过、防止测速选到未串联的路径）。
   - **地区组处理**：按地区聚合的分组若其可达叶子全为出口，整体删除，
     引用与规则目标改指 `⛓ 出口优选`（链式语义下“地区”由出口决定，
     独立地区组纯属重复）；若因此被掏空的组，引用改指主选择器。
4. **自动组参数定版**：测速间隔 3 分钟（Clash `interval: 180`、
   sing-box `"3m"`），切换容差 100ms，已连接不中断
   （`interrupt_exist_connections: false`）。
5. **DNS 基线**：
   - 引导解析（节点域名）只用 DoH/443（如
     `https://223.5.5.5/dns-query#DIRECT`）。**禁用 DoT/853 引导**：
     实测运营商对 TCP 853 存在干扰，曾出现一夜数百次拨号被取消、
     链式连接建立被拖死。
   - 海外域名解析经链路（nameserver 标注主选择器），国内域名走国内
     DoH；fake-ip 模式开启并配过滤名单（STUN 类走规则集）。
   - sing-box 侧 DNS 服务器：fakeip、dns-cn（UDP 直连国内解析）、
     dns-remote（经主选择器）；ECH 专用服务器见第 5.2 节。
6. **防泄漏包**（两目标都要）：
   - WebRTC：STUN/TURN 域名关键字与端口（3478/19302/5349）拒绝。
   - 局域网地址、`.lan/.local/.home.arpa` 直连；公共 DNS 的域名与 IP
     段直连（防解析环路）；DNS 端口 53 的明文外发拒绝。
   - sing-box 侧 DNS 对广告规则集返回拒绝、路由层同步拦截。

### 5.1 Clash 骨架要点

- 顶层：dns（fake-ip、nameserver-policy 按 geosite 分流）、hosts、
  sniffer、tun、profile、geox-url（指向自家镜像，见第 6 章规则镜像；
  geo 自动更新间隔 7 天）。
- rule-providers 全部为官方 `.mrs`（MetaCubeX meta-rules-dat），
  `interval: 86400`，URL 指向自家镜像 `/rules/clash/<文件>`。
- 直连组由 5 个内置 direct 代理构成（双栈 / IPv4 优先 / IPv6 优先 /
  仅 IPv4 / 仅 IPv6）。
- 分组不带图标字段（图标纯装饰、无功能依赖，骨架默认不配）。

### 5.2 sing-box 骨架要点

- 顶层：outbounds（链式双组 + 节点 + direct 变体 + REJECT 占位 +
  全部 selector/urltest 组）、dns、route（final = 漏网之鱼）、
  http_clients、inbounds（tun）、log。
- rule_set 全部为官方 `.srs`（SagerNet sing-geosite / sing-geoip），
  `http_client` 指向一个带 `connect_timeout` 的 direct 客户端，
  URL 指向自家镜像 `/rules/singbox/<文件>`。
- **节点规范化**（组装时对每个叶子节点执行，与社区覆写脚本的既有
  行为对齐）：
  - `domain_resolver` 一律改指骨架内的国内 DNS 标签（如 `dns-cn`）；
    旧式 `domain_strategy` 折叠进 `domain_resolver.strategy` 后删除。
  - 非 endpoint 节点注入 `tcp_keep_alive: "60s"`，
    `tcp_keep_alive_interval` 缺失时补 `"60s"`。
  - 与 tag 不一致的冗余 `name` 字段删除；入口/出口的 detour 由构建器
    统一赋值（先清后设）。
- **ECH 自洽（关键坑，完整 sing-box 配置必须自带）**：机场入口节点常
  带 ECH，其配置列表要在拨号时用 DNS 的 HTTPS 型查询实时拉取；而防
  泄漏 DNS 规则会整体拒绝 HTTPS/SVCB 查询，两者相撞的结果是每条经
  出口的连接报 `fetch ECH config list: REFUSED`、整条链不可用。
  部分客户端只对自拼配置做 ECH 路由修复、对完整的 sing-box 文件
  明确不干预，所以生成端必须自带修复，三件套：
  1. **生成时内嵌**：在服务器侧经 DoH 拉取实时的 ECHConfigList，
     写进各 ECH 出站的 `tls.ech.config`。注意 sing-box 要求 PEM
     装甲且标签必须是 `ECH CONFIGS`（带空格，源码硬校验），写成
     `ECHCONFIG` 会报 `invalid ECH configs pem` 启动失败。
     该 DNS 记录 TTL 只有约 56 秒，靠客户端实时拉取等于几乎每批
     新连接都多一趟查询，内嵌同时也是性能优化。
  2. **专用查询通道兜底**：新增 DNS 服务器 `ech-dns`（AliDNS DoH，
     detour 到一个带 `connect_timeout` 的 direct 出站），并把 ECH
     查询域名（如 `cloudflare-ech.com`）的路由规则插到 DNS 规则
     最前面（必须在 reject 规则之前）。内嵌过期时靠它续命。
  3. **裸 direct 出站陷阱**：被用作 detour 目标的 direct 出站若是
     “空”的（无任何字段），sing-box 1.15 会以
     `detour to an empty direct outbound makes no sense` 拒绝
     启动——务必给它 `connect_timeout`（如 `"8s"`）。
- **远程规则集旧字段陷阱**：老模板里的
  `"download_detour": "DIRECT"` 在 sing-box 1.15 默认被拒，必须改
  用顶层 `http_clients` + 规则集 `http_client` 引用。

## 6. 规则镜像与定时更新

- **清单驱动**：`rules_manifest.json` 每条含官方源 URL 与本地相对
  路径。来源只有官方仓库：
  - Mihomo：`raw.githubusercontent.com/MetaCubeX/meta-rules-dat`
    的 `meta` 分支（`.mrs` 规则）与 `release` 分支（geoip.dat、
    geosite.dat、geoip.metadb、GeoLite2-ASN.mmdb）。
  - sing-box：`raw.githubusercontent.com/SagerNet/sing-geosite` 与
    `SagerNet/sing-geoip` 的 `rule-set` 分支（`.srs`）。
- **生成配置只引用自家镜像**：`https://<你的域名>/rules/clash/...`、
  `.../rules/singbox/...`、客户端按各自间隔（provider 24h、geox 7d）
  自动刷新，节奏由镜像新鲜度决定。
- **刷新脚本**（refresh_rules.py）：逐条下载 → 校验（大小下限、
  二进制文件不得是 HTML 错误页、SVG 须含 `<svg`）→ 写临时文件 →
  `os.replace` 原子替换；任一失败保留旧文件。结果写入
  `rules_status.json`（时间、成功数、失败清单），进程退出码反映失败。
- **定时**：systemd timer 每日凌晨执行一次（见第 8 章单元示例），
  随机延迟数分钟，错过可补跑（Persistent=true）。
- 镜像目录不在代码仓库内，由刷新脚本独占维护；首次部署先手动跑
  一次灌满，再切换骨架引用。

## 7. 短链接

长链接把原始订阅（含 token）明文摊在 URL 里，又长又泄密。短链设计：

- 创建：页面 `POST /shorten`，JSON 体
  `{target, entry, exit}`（链式）或 `{target, url}`（普通转换），
  可选 `code` 自定义后缀。参数走请求体不走 URL，避免落进代理日志。
- 码：随机码 10 位（字母表刻意去掉 0/1/i/l/o 等形近字符，约 57^10
  熵空间）；自定义码 3–32 位，允许字母、数字、`-`、`_`（全字符集，
  不要拿随机字母表去卡用户输入）。
- 语义：同一份内容（入口+出口或转换源相同）重复生成 → 复用已有码
  （幂等）；自定义码被不同内容占用 → HTTP 409 提示换名；被同内容
  占用 → 直接返回。
- 解析：`GET /m/<码>` 出 Mihomo 配置、`GET /s/<码>` 出 sing-box
  配置、`GET /c/<码>` 按创建时格式出。**格式由路径字母决定，与码
  无关**——同一对入口出口只需一个码，改字母即切换客户端格式。
- 存储：`links.json` 与服务同目录，权限 0600，写时临时文件 +
  原子替换，加进程内锁防并发写坏。
- 页面行为：两个表单各有一个“自定义后缀”可选输入；生成走短链，
  短链服务不可用时前端自动回退到长链格式（保证页面永不死）。

## 8. 部署手册

目录布局（示例 `/opt/subconv/`）：

```
/opt/subconv/
├── landing_server.py        # 页面服务（含生成、短链、规则下发）
├── skeleton_clash.json      # 自有骨架
├── skeleton_singbox.json
├── rules_manifest.json      # 规则清单（76 条量级）
├── refresh_rules.py         # 规则刷新
├── rules_files/             # 镜像（clash/ singbox/ 子目录）
├── rules_status.json        # 刷新状态（运行时生成）
├── links.json               # 短链映射（0600，运行时生成）
├── templates/               # 转换引擎模板（回退路径用）
└── subconverter/            # 转换引擎本体（回环监听）
```

systemd 单元示例：

```ini
# subpage.service
[Unit]
Description=Subscription converter page service
After=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/subconv/landing_server.py
WorkingDirectory=/opt/subconv
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target

# rules-refresh.service
[Unit]
Description=Refresh self-hosted rule mirror from official sources
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /opt/subconv/refresh_rules.py

# rules-refresh.timer
[Unit]
Description=Daily rule mirror refresh

[Timer]
OnCalendar=*-*-* 04:35:00
RandomizedDelaySec=900
Persistent=true

[Install]
WantedBy=timers.target
```

公网入口分流（以隧道 ingress 为例，其他反代等价改写）：

```yaml
ingress:
  - hostname: sub.example.com
    path: ^/$
    service: http://127.0.0.1:<页面端口>
  - hostname: sub.example.com
    path: ^/chain$
    service: http://127.0.0.1:<页面端口>
  - hostname: sub.example.com
    path: ^/conv$
    service: http://127.0.0.1:<页面端口>
  - hostname: sub.example.com
    path: ^/sub$
    service: http://127.0.0.1:<页面端口>
  - hostname: sub.example.com
    path: ^/version$
    service: http://127.0.0.1:<页面端口>
  - hostname: sub.example.com
    path: ^/c/
    service: http://127.0.0.1:<页面端口>
  - hostname: sub.example.com
    path: ^/m/
    service: http://127.0.0.1:<页面端口>
  - hostname: sub.example.com
    path: ^/s/
    service: http://127.0.0.1:<页面端口>
  - hostname: sub.example.com
    path: ^/shorten$
    service: http://127.0.0.1:<页面端口>
  - hostname: sub.example.com
    path: ^/rules/
    service: http://127.0.0.1:<页面端口>
  - service: http_status:404
```

部署顺序（每步验证后再下一步）：

1. 部署转换引擎并确认回环可达、本机转换一份样例成功。
2. 部署页面服务与骨架、清单，先跑 `refresh_rules.py` 灌满镜像，
   本机 `curl` 任选一个规则文件确认 200 且大小合理。
3. 配好公网分流，先验 `/version` 与首页，再验长链生成
   （`/chain`、`/conv` 各一份，目标各一）。
4. 验短链：创建 → 三种字母各拉一次 → 内容格式正确。
5. 启用 timer，手动触发一次服务确认状态文件更新。
6. 最后才把客户端里的订阅地址换成短链。

## 9. 验证手册（ Definition of Done ）

**铁律：静态检查通过 ≠ 能用。** `sing-box check` 查不出的坑包括
空 direct detour、规则集旧字段、ECH 查询被拒等，全是启动/运行时
才炸。每类产物必须走完三层验证：

1. **结构对照**：与上一版产物做字段级 diff——分组名单与成员、规则
   列表、DNS、节点字段应仅有预期差异（如规则 URL 换镜像域名）。
   改构建器时用同一份输入同时跑新旧两条路径对照（A/B），消除订阅
   源内容轮换带来的假差异。
2. **内核校验**：`mihomo -t -f <clash 配置>`、
   `sing-box check -c <sing-box 配置>` 均须通过。
3. **真内核实跑**：在服务器上用生成的 sing-box 配置实际启动
   （另加一个本地 mixed 入口指向主选择器），经链路请求
   `https://www.gstatic.com/generate_204` 应得 204，再请求一个
   常规站点应得 200；日志中应看到规则集从自家镜像更新成功、
   无 FATAL。Clash 侧同理可用 mihomo 实跑或客户端导入验证。
4. **真机验收**：客户端更新订阅后，入口组、出口组均应有延迟数值，
   实际打开网页正常。延迟显示原理：出口组延迟是冷启动两跳握手的
   全程耗时（入口腿 RTT 的数倍），天然高于单跳客户端复用连接池
   的测速数字，属正常现象，以实际浏览体感为准。

## 10. 运维与故障速查

- **状态查看**：`rules_status.json` 看最近一次刷新结果；服务日志
  只记生成路径（如 `chain target=singbox path=own`），不记链接。
- **回退**：构建器保留了脚本路径与内置合并两级回退（骨架缺失或
  构建异常时自动降级），并保留上一版服务文件备份即可快速回滚。
- **故障表**：

| 症状 | 根因 | 处理 |
|---|---|---|
| 订阅拉取时 DoT 853 大量拨号取消 | 引导 DNS 用了 DoT/853，被运营商干扰 | 引导改 DoH/443（第 5 章） |
| 链式无延迟、`ECH ... REFUSED` | ECH 实时查询撞 DNS reject 规则 | 生成端内嵌 ECH + ech-dns 兜底（5.2） |
| 内核启动 FATAL `empty direct outbound` | 裸 direct 被用作 detour | 给 direct 补 connect_timeout（5.2） |
| 内核启动 FATAL `invalid ECH configs pem` | PEM 标签写错 | 标签须为 `ECH CONFIGS`（带空格） |
| 规则集初始化大面积失败 | 规则集 URL 404（分支/文件名漂移） | 对照官方仓库 rule-set 分支修正清单并刷新 |
| 客户端测速显示出口延迟数秒 | 冷启动两跳握手的测度特性 | 正常；以实跑体感为准（第 9 章） |
| 短链 404 | 码不存在或 ingress 未放行 `/c/`/`/m/`/`/s/` | 查 links.json 与入口分流表 |

## 11. 安全与隐私清单

- 原始订阅只存服务器 `links.json`（0600）；短码即凭证，不公开分享，
  自定义码可记性强但熵低，权衡自担。
- 生成与拉取的日志只记路径类型与结果，不记 URL、参数与内容。
- 服务只监听回环，公网暴露面只有隧道/反代一层；管理操作走 SSH。
- 凭据（token、密钥）不写进代码仓库、不写进本文这类文档；示例值
  一律占位。
- **知情义务**：凡涉及用户数据流向的变更（数据存在哪、经过谁），
  即便结论是安全的，也要主动说明，不默默处理。

## 12. 附录：接口清单

| 方法与路径 | 用途 |
|---|---|
| `GET /` | 转换页面 |
| `GET /version` | 引擎版本探活 |
| `GET /conv?target=&url=` | 普通转换（自研管线，clash/singbox） |
| `GET /sub?target=&url=` | 普通转换（透传转换引擎，其他格式） |
| `GET /chain?target=&entry=&exit=` | 链式生成（长链，内部兼容用） |
| `POST /shorten` | 创建短链（JSON 体，可选自定义码） |
| `GET /c/<码>` / `/m/<码>` / `/s/<码>` | 短链拉取（按创建格式 / Mihomo / sing-box） |
| `GET /rules/<clash|singbox>/<文件>` | 规则镜像下发（仅清单内文件） |
