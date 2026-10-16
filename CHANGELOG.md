# Changelog

本项目遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/) 风格。

> **状态说明**：本插件**未开发完成**，处于**测试阶段**。在 1.0.0 之前，
> API、配置项与文件格式均可能在不通知的情况下变更。

## [0.6.1] — 2026-10-16

本版本修掉一个**客户端主题适配的实际 bug**，并补上能发现这类问题的契约测试。

### 修复

- **面板用了 8 个宿主根本不存在的主题 token**（客户端「浅色模式难看」的根因）
  - 之前用 `--dsw-alias-bg-secondary` / `bg-primary` / `bg-tertiary` /
    `text-primary` / `text-tertiary` / `border-secondary` / `border-danger` /
    `text-danger` —— 实测宿主
    `@deepseek-ai/dsh-client-ui-theme` 的 107 个 token 里**一个都没有**，
    只有 `brand-primary` 是对的
  - 后果：每个声明都落到写死的暗色回退值（`#e6e6e6` 文字 / `#222` 背景 /
    `rgba(255,255,255,.x)` 边框），等于**硬编码深色主题** ——
    浅色模式下就是深色卡片 + 低对比文字。而 README 当时声称"样式走主题 token"，
    属不实描述
  - 现改用真实存在的 12 个 token：`label-primary` / `label-tertiary` /
    `bg-layer-1` / `bg-layer-2` / `border-l2` / `interactive-bg-hover` /
    `settings-card-fill` / `settings-card-stroke` / `brand-primary` /
    `state-idle-primary` / `state-error-primary` / `state-error-secondary`
  - 同时**移除所有字面色回退值**：token 缺失时宁可继承，也不要静默变成另一种主题

### 新增

- **客户端 bundle 契约测试 `test/client-contract.test.mjs`（14 项）**
  - 在沙箱里**真执行 `client.js`**（假 `window.__ModuleLoader__` + 最小 React 替身）
  - 校验：`load` 的 id、factory 返回 `module.exports` 的 CommonJS 契约、
    `inject` 声明、`settings.section` 注册形状（用 id 而非 key）、
    面板组件真渲染且产出控件文本、只 `require('react')`、
    **只允许使用宿主真实存在的 token**、无写死颜色、token 无字面色回退
  - 这正是本轮开发中 5 个"只能靠重启 DSH 用眼睛看"才能发现的 client bug 的
    自动化替代品（裸 return、slot 选错、缺 icon、缺 locale、token 名编造）

### 变更

- CI 步骤增加：pcapng IDB 回归、TCP 重组、流式解析、客户端契约（共 6 个测试套件）
- README 的"样式走主题 token"改为可验证陈述，并新增"面板视觉未逐像素核对"的
  诚实标注

## [0.6.0] — 2026-10-16

本版本补上最后一块边界能力：**大文件流式解析**。此前分析必须整文件读入内存
（上限 96 MB），现在超过 16 MB 的文件改为分块读取，峰值内存不再随文件大小增长。

### 新增

- **流式解析 `parseCaptureStream(path, opts)`**（`lib/pcap.js`）
  - `ChunkReader` 按块读取（默认 4 MB，可用 `chunkBytes` 调），只保留
    「当前块 + 至多一个完整 block/record」，峰值内存与文件大小解耦
  - pcapng 与经典 pcap 两条路径都支持；块/记录跨 chunk 边界由 carry 缓冲
    拼接处理，已用 4 KB / 8 KB / 64 KB 极小 chunk 验证
  - 输出与整读路径**逐字段等价**（含 stats、重组统计、SNI/DNS、HTTP 事务、
    TLS 详情、包列表），两者共用同一套 block/record 解释器
  - 重组完成后释放 `payloadBuf` 视图，让底层 chunk 能被回收
- **路由与工具层接线**：`/analyze`、`/flows`、`/search`、`/packets`、`/export`
  与 `capture_analyze` / `capture_search` / `capture_export` 均按阈值分流：
  ≤ 16 MB 整读（最快），更大则流式。响应新增 `streamed` 字段表明走了哪条路径
  - in-memory 的 `maxAnalyzeBytes` 上限只作用于小文件分支
  - 流式分支另有 2 GB 硬上限，超过则明确报错而不是尝试读入
- **测试 `test/streaming.test.mjs`（9 组）**：双格式等价性、跨边界 chunk、
  `maxPackets`、截断文件、非法输入、流式下的重组、**路由接线**
  （18.3 MB 文件经 `/analyze` 与 `/packets` 走流式）

### 变更

- `pcapng` 的 block 处理拆成 `pcapngBlockLength` / `consumePcapngBlock` +
  `createParseState`，整读与流式共用，避免两份实现漂移
- 装机验证 45 → **48 项**（新增流式入口、路由接入、工具接入三项）

### 修复

- 经典 pcap 解析里两处未使用的局部变量（`readU16` / `origLen`）随重构清理

## [0.5.0] — 2026-10-16

本版本补齐工程面与工具面：新增两个 agent 工具、类型声明、结构化日志、
源码内路由契约测试，并把装机验证扩展到 45 项。

### 新增

- **`capture_status` 工具**：**不停止抓包**也能查看进度 —— 已落盘包数/字节、
  抓包时长、后端与网卡，以及已捕获内容的轻量预览（DNS/SNI/TLS/HTTP 计数与
  SNI 名单）。长抓包时用它轮询确认目标流量已进来，再 stop。
  - 预览解析跳过重组以保持轮询廉价；仅在文件 ≤ 8 MB 时做
  - pktmon 会话（ETL 尚未转换）也能报进度
- **`capture_export` 工具**：把抓包导出成文件并返回路径，JSON/CSV 两种格式。
  CSV 带 BOM 与 `time`/`tls` 列；JSON 含 meta/stats/reassembly/talkers/
  DNS/SNI/HTTP/TLS。无浏览器也能拿到结构化产物。
- **类型声明 `types/index.d.ts`**：8 个 interface 描述路由与工具的数据契约
  （`CaptureEntry`/`InterfaceEntry`/`BackendReport`/`AnalyzeResult`/
  `PacketRow`/`HttpTransaction`/`TlsInfo`/`ReassemblyStats`/`SearchResult`/
  `CaptureConfig`），`package.json` 声明 `types` 与 `./types` 导出
- **结构化日志**：`apply()` 通过 `ctx.logger` 记录加载/挂载/卸载与配置摘要；
  host 没提供 logger 时自动降级为 no-op，绝不因日志缺失而抛错
- **源码内路由契约测试** `test/routes.test.mjs`（**23 项**）：用假 host context
  挂载真实路由并逐个调用 —— 注册数量、方法校验、id 校验、路径穿越防御、
  跨包 HTTP 重组、时间戳 ISO、分页、导出 BOM、正则校验、dispose 清理。
  不需要已安装 profile，可在 CI 裸跑

### 变更

- 装机验证 38 → **45 项**（新增：类型声明存在与覆盖、types 导出字段、
  8 个 agent 工具齐备、ctx.logger 降级、pcap.js 关键实现存在）
- README 与 package.json 的 meta 描述同步到 Npcap 优先的现状

### 修复

- **`/search` 的报文体检索失效**：0.4.0 把 `/analyze` 的 `streams` 拍平成摘要后，
  search 仍按旧的嵌套形状取 `s.http.request?.bodyPreview`，导致 `bodies` 恒空。
  现改为从 `transactions` 取。由新增的路由契约测试发现

## [0.4.0] — 2026-10-16

本版本补上解析深度：**TCP 流重组**、**HTTP 报文体提取**、**TLS 握手详情**、
**人类可读时间戳**。此前跨包的 HTTP 消息只能看到首包，TLS 只能拿到 SNI。

### 新增

- **TCP 流重组**（`lib/pcap.js` 的 `buildStreams`）
  - 按 4 元组（规范化端点对）分组，每方向独立重组
  - 片段按 **seq 排序**，并处理 2^32 回绕：偏移以首个片段为基准取模，
    落在模空间"负半区"的片段判为更早到达 —— **乱序捕获也能拼对**
  - 重叠去重、空洞计数（`gaps`）、越界截断标记（`truncated`）
  - 自动识别客户端方向：优先看哪一侧先发 HTTP 请求行或 ClientHello
- **HTTP 事务提取**：把重组后的双向缓冲配对成一次请求/响应
  - 请求：方法、路径、Host、User-Agent、Content-Type、Content-Length、**请求体预览**
  - 响应：状态码、reason、Content-Type、Content-Length、Server、**响应体预览**
  - 只有文本类型（`text/*`、`application/json|xml|…`）才取体，二进制体只记长度
  - `Transfer-Encoding: chunked` 会标记出来，但不还原分块体（见已知问题）
- **TLS 握手详情**（`tlsClientHello` / `tlsServerHello`）
  - ClientHello：记录层版本、客户端版本、`supported_versions` 列表、
    **密码套件清单（带规范名）**、扩展列表、SNI
  - ServerHello：协商版本（含从 `supported_versions` 扩展取 TLS 1.3 真版本）与协商套件
  - 全部读取带边界检查，snaplen 截断的包不会抛异常
- **时间戳**：`meta.firstTime` / `lastTime`、包行 `time`、CSV 新增 `time` 列（ISO-8601 UTC）
- **配置项**：`reassemble`、`streamCapKb`、`maxStreams`、`httpBodyPreviewBytes`
- **面板**：新增「HTTP 事务（重组后）」与「TLS 握手」两块，包列表显示时间；
  底注改为与实测一致的「Npcap 免管理员」
- **测试**：`test/stream-reassembly.test.mjs` 共 7 组（跨包 HTTP、乱序、缺口、
  ClientHello、ServerHello、时间戳、上限与开关）
- **脚本**：`repoint-dsh-capture.mjs`（修正 profile 依赖指向）、`recheck-22.mjs`（完成度复核）

### 变更

- `parseCapture(buf, opts)` 的 `opts` 现在真正透传到 pcap / pcapng 解析器
  （此前只吃 `maxPackets`，`streamCap` 等被静默忽略）
- `/dsh-capture/flows` 增加 `streams` 与 `tlsHandshakes`；`/analyze` 增加
  `transactions`（拍平的 HTTP 事务）、`tls`、`reassembly`
- `/dsh-capture/search` 增加 `tls`、`streams`、`bodies` 命中类别
- 包行增加 `payloadBytes`（TCP 载荷长度，`bytes` 是整帧长度）
- 装机验证 29 → **38 项**

### 修复

- `parseOptsFrom(cfg)` 未生效的问题：现在 `reassemble:false` 等配置真正影响到解析
- CSV 表头增加 `time` 与 `tls` 列后，装机验证的断言同步更新

### 已知问题（未修复）

- **TLS 不解密**：只解析明文握手，应用数据是密文；解密需要 SSLKEYLOGFILE 或私钥
- **HTTP/2、HTTP/3 未解析**：只识别 HTTP/1.x 文本协议
- **chunked 响应体未拼接**
- 大文件仍未流式解析（整文件读入，默认上限 96 MB）
- pktmon + 提权助手路径仍未经真机验证

## [0.3.0] — 2026-10-16

本版本接入 Npcap 后端，**并更正了 0.1.0 起一直存在的错误结论**：「抓包需要管理员权限」。

### ⚠️ 重要更正：抓包不需要管理员权限

0.1.0/0.2.0 的文档、README 与 CHANGELOG 都写着「抓包需要管理员权限」。
**这是错的** —— 该结论只探测了 `pktmon` 就推广到全部路径。

实测事实：

| 路径 | 需要管理员？ | 证据 |
|---|---|---|
| **Npcap / dumpcap** | **不需要** | `dumpcap.exe` manifest 为 `asInvoker`；非提权连续三轮抓到 164 / 100 / 83 个包 |
| pktmon | 需要 | `PktMon` 是内核驱动，`pktmon filter list` 无提权返回 exit 5 |

另外，Npcap 的 `AdminOnly=1` **并不阻止**非提权抓包 —— 它只在进程首次打开适配器时
触发一次 `NpcapHelper` 确认框（不是 UAC）。此前把该确认框误判为提权需求。

### 新增
- **`lib/npcap.js`：Npcap/dumpcap 后端**（首选）
  - 从注册表 `HKLM\SOFTWARE\WOW6432Node\Wireshark\InstallDir` 定位安装目录（支持非默认路径），并以常见路径兜底
  - **按设备名 `\Device\NPF_{GUID}` 寻址**，绝不用数字索引（索引会在虚拟网卡间漂移，导致静默抓到空网卡）
  - 网卡分类 `wifi`/`ethernet`/`virtual`/`loopback`，默认优选真实网卡
  - 网卡列表 **5 分钟缓存**，避免同一会话反复触发 Npcap 确认框
  - 支持 `-f` **BPF 表达式**、`-s` snaplen、`-b` 环形缓冲、`-a` 定时停止
  - 停止用 `taskkill /F /PID <pid> /T`：dumpcap 逐块落盘，强杀后文件仍完整（实测 42 包零丢失）
- **`lib/perm.js` 重写**：后端选择改为 Npcap 优先 → pktmon（+提权助手）→ 不可用，并给出可执行的说明
- **抓包成败判据改为数 EPB 数据块**（`0x00000006` / `0x00000003`）：
  文件体积不可靠 —— 一个 484 字节的 pcapng 完全合法却零包
- `GET /interfaces` 路由：网卡清单，`?refresh=1` 强制重枚举
- `GET /status` 增加 `live` 字段：抓包中可读实时包数
- `capture_start` 新增 `device` / `bpf` / `snaplen` / `durationSec` / `ringFileMb` 参数
- `capture_list` 返回每个抓包的**包数**
- `capture_probe` 报告选定后端、网卡清单与默认网卡
- 结构化 `filters` → BPF 表达式转换（多条件用 `or` 连接）
- 面板：网卡选择器（含「刷新网卡」）、BPF 高级输入、后端状态卡、抓包中提示
- `test/pcapng-idb.test.mjs`：pcapng IDB 回归测试

### 修复
- **解析器严重 bug：所有真实 pcapng 的包全被丢弃**
  `parsePcapng` 从 **SHB 块偏移 20** 读 `linkType`，但 SHB 根本没有该字段
  （布局为 `type/len/byte-order-magic/version/section-length/options`），
  于是读进 options 区得到 `0xFFFFFFFF`，导致 `unsupportedLink` 计满、包数为 0。
  **正确位置是 IDB 偏移 8、2 字节。**
  此前未被发现是因为合成测试文件的 IDB 是简化版（16 字节无 options），
  恰好绕过了错误偏移；真实 dumpcap 产出的 IDB 带 192 字节选项区才暴露出来。
  修复后真实抓包解析恢复正常（164 / 100 / 83 包，SNI 与 DNS 均正确）。
- `routes.js` 中 `mountRoutes(ctx, config)` 内部引用了未定义的 `cfg`，导致 `/start`
  抛 `cfg is not defined`。已改为在函数入口归一化配置。
- `/download` 路由现在遵守 `allowDownload: false` 配置。
- `lib/tools.js` 整文件重写为后端无关的流程层（原先硬编码 pktmon 的 ETL 流程）。

### 变更
- `lib/perm.js`、`lib/tools.js` 重写；`lib/index.js`、`lib/routes.js`、`client/client.js` 调整
- 路由 12 → **13** 条
- 装机验证 21 → **29** 项
- `version` 0.2.0 → 0.3.0

### 新增验证
- **端到端真实抓包 9 项全过**：`/status` 选后端 → `/interfaces` → `/start` 真实抓包 →
  抓包中实时包数 → `/stop` 零丢包 → `/analyze` 解析出 SNI/DNS → `/export` CSV 行数与包数一致 →
  BPF 过滤生效（156 包违规 0）

### 已知问题（未修复）
- **pktmon + 提权助手路径未在真机验证**：本机有 Npcap，后端自动选它，
  因此 UAC 全链与拒绝分支均未跑通
- TCP 流重组、HTTP 报文体重组、TLS 握手版本/密码套件均未实现
- 大文件未流式解析（整文件读入，默认上限 96 MB）
- 抓包文件无自动清理（Npcap 后端可用 `ringFileMb` 回绕，旧文件需手动删）
- 仅 Windows

## [0.2.0] — 2026-10-16

本版本主要解决「抓包必须让整个 DSH 以管理员运行」这个实际痛点，并补齐
包级浏览、结构化导出与可配置项。

### 新增
- **一次性提权助手**（`lib/elevate.js` + `lib/run-elevated.ps1`）：
  非提权 DSH 抓包时，只把 `pktmon start/stop` 委托给一个短命的提权助手，
  经 UAC 授权后立即退出；DSH 本身始终保持普通权限。**拒绝 UAC 时不会失败**，
  而是返回可执行的替代方案说明。
  该路径也可用配置关闭（`useElevation: false`），适合无人值守环境。
- **完整环境探测**（`lib/perm.js`）：同时报告 pktmon 可用性、Npcap 安装状态、
  驱动是否运行、`AdminOnly` 取值，以及提权途径是否可用。
  当 Npcap 被放宽到 `AdminOnly=0` 时，正确识别为「可非提权抓包」。
- **包级浏览** `GET /dsh-capture/packets`：分页读取单个数据包，
  支持 `proto` / `port` / `host` / `q` 过滤。
- **结构化导出** `GET /dsh-capture/export?format=csv|json`：
  CSV 带 BOM（Excel 直接正确识别 UTF-8），JSON 输出完整摘要。
- **正则检索** `GET /dsh-capture/search?pattern=...`：
  用户正则做长度上限与语法校验，无效正则返回 400 而非抛错。
- **Config schema**（schemastery）：`maxAnalyzeBytes` / `maxAnalyzePackets` /
  `useElevation` / `defaultPktSize` / `allowDownload`，
  可在 profile 的 `cordis.patch.yml` 覆盖。
- **i18n**：`locale/en.json` 与 `locale/zh.json`。
- **CI**（`.github/workflows/ci.yml`）：语法检查、PowerShell 解析、
  解析器自测、图标与 manifest 契约、exports 完整性、README 声明校验。

### 变更
- 面板升级：显示三类能力（pktmon / Npcap / 可抓包），
  权限诊断逐条列出；新增「导出 CSV / 导出 JSON / 浏览数据包」，
  包列表支持上/下页；开始按钮在「需提权」状态下仍可点击并说明将弹 UAC。
- 抓包与停止的路由改为复用工具层流程，HTTP 面板与 agent 工具共用一套实现。
- `version` 0.1.1 → 0.2.0

### 测试
- 装机验证从 14 项扩展到 **21 项**，新增覆盖 packages 分页与过滤、
  CSV/JSON 导出、正则检索（含无效正则）、方法校验。
- 新增 CI 本地等效检查脚本。

### 已知问题（未修复）
- **真实提权环境下的完整抓包链路仍未端到端验证**：本机开发时 DSH 为非提权，
  提权助手本身未经真实 UAC 流程验证（代码路径与 UAC 拒绝分支已按文档实现，
  但未在真机跑通「提权 → 抓包 → 停止 → 转换 → 分析」全链）。
- **Npcap 后端未接入**：仅在探测层识别 Npcap/`AdminOnly`，
  实际抓包仍走 pktmon；改 `AdminOnly=0` 后的免提权抓包路径尚未实现。
- 仅 Windows；IPv6 扩展头链、大文件流式解析未验证。
- 抓包文件无自动清理/轮转策略，长期使用需手动删除。

## [0.1.1] — 2026-10-15

### 修复
- **图标未声明**：`package.json` 缺少顶层 `icon` 字段，导致宿主回退到默认图形
  （表现为设置页显示通用设置图标）。现声明为 `./icon.svg`。
- **`exports` 契约错误**：声明了 `./locale/en.json` 但该文件不存在。已移除该条，
  仅保留实际存在的 `./locale/zh.json`。
- **Client bundle 导出契约**：`client.js` 原本用裸 `return {...}`，
  而 `window.__ModuleLoader__` 要求 CommonJS 契约
  （`return module.exports`），否则 loader 视为"没有导出"、面板不出现。
- **slot 选错**：原本注册到 `sidebar.right.pane.tab`，但该 slot 渲染的是
  「右侧栏已打开标签页的内容」，需先经 `sidebarRightTabs.register()` 声明 tab
  才会被渲染 —— 直接注册永不显示。已改用 `settings.section`
  （设置页分区，与 `dsh-wallpaper-engine` 同一注册形状）。

### 变更
- 图标重绘：由通用波形图改为「捕获框 + 数据包流」语义
- `version` 0.1.0 → 0.1.1

### 已知问题（未修复）
- **实时抓包需要管理员权限**：`pktmon` 是内核驱动，其设备对象只对管理员开放。
  实测 `pktmon filter list` / `start` / `stop` 在非提权下均返回
  `exit=5 无法与 PktMon 驱动程序通信。拒绝访问。`；`netsh trace` 同样被挡。
- **Npcap 后端尚未接入**：本机已装 Npcap，但其注册表项
  `HKLM\SOFTWARE\WOW6432Node\Npcap\AdminOnly = 1`，非提权进程无法打开网卡。
  改该值需一次性提权。
- **真实提权下的完整抓包链路未端到端验证**（抓 → 停 → 转 → 析）
- IPv6 扩展头链在真实流量下未验证
- 仅 Windows 适配

## [0.1.0] — 2026-10-15

### 新增
- 首个可用版本：`pktmon` 实时抓包 + 自研 pcapng/pcap 解析器
- 流量提取：DNS 查询、TLS SNI、明文 HTTP、Top 会话/端口/端点
- 6 个 agent 工具：`capture_probe` / `list` / `start` / `stop` / `analyze` / `search`
- 9 条 `/dsh-capture/*` HTTP 路由
- 设置页面板（纯 React + `--dsw-alias-*` 主题 token）
- 装机验证脚本与解析器自测
