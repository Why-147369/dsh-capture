# dsh-capture

> **⚠️ 未开发完成 · 测试阶段（Work in Progress / Pre-release）**
>
> 本插件**尚未开发完成**，处于**测试阶段**，请勿用于生产环境。
>
> 已知限制（详见下方「当前状态」）：
> - 仅适配 **Windows**
> - Npcap 后端首次打开网卡时**可能弹一次确认框**（不是 UAC）
> - 无 Npcap 的机器走 pktmon，需要**一次 UAC 提权**
> - TCP 流重组、HTTP 报文体重组尚未实现
> - API、配置项、文件格式均可能在后续版本中变更

---

## 这是什么

面向 DeepSeek Harness 的**抓包与流量分析**插件。

它填补了 DSH 插件生态的一个空白：在主流社区目录（dshfind 收录约 1.9 万条、deepseek1024 约 1.4 万条）里，
`mitmproxy` / `wireshark` / `tcpdump` / `packet-capture` 等关键词**全部零命中** —— 即此前没有任何 DSH 插件能做抓包。

## 两个抓包后端（自动选择）

| 后端 | 依赖 | 需要管理员？ | 说明 |
|---|---|---|---|
| **Npcap**（优先） | Wireshark 自带 | **不需要** | `dumpcap.exe` 的 manifest 是 `asInvoker`，标准用户即可抓包 |
| **pktmon**（后备） | Windows 10 1809+ 自带 | 需要（一次 UAC） | `PktMon` 是内核驱动，设备对象只对管理员开放 |

插件启动时自动探测并优选 Npcap。**没有 Wireshark 的机器**才回退到 pktmon，并弹出一次 UAC 走提权助手。

> **关于「抓包一定要管理员吗」**：不需要。早期版本曾把 pktmon 的限制误当成通用结论，
> 实测证明 Npcap 路径在非提权下可正常抓包（连续三轮 164 / 100 / 83 个包）。
> Windows 上 Npcap 的 `AdminOnly=1` **并不阻止**非提权抓包。

## 能力

- **实时抓包**：Npcap（dumpcap）或 pktmon，均零第三方 npm 依赖
- **BPF 过滤**：Npcap 后端支持完整 libpcap 表达式，如 `tcp port 443 and host 1.1.1.1`
- **网卡选择**：自动识别真实网卡（WLAN / 以太网），跳过 VMware / 环回 / 空闲虚拟适配器
- **离线解析**：自研 pcapng / pcap 解析器，零外部依赖
- **TCP 流重组**：按 4 元组分组、按 seq 排序、检测缺口与重传，跨包消息能完整读出
- **HTTP 事务**：从重组流里配对请求/响应，提取方法、路径、Host、状态码、Content-Type、Content-Length 与**报文体预览**
- **TLS 握手详情**：SNI、记录层版本、客户端版本、`supported_versions`、**密码套件清单**（ClientHello）；协商版本与套件（ServerHello）
- **流量提取**：Ethernet / IPv4 / IPv6 / TCP / UDP / ICMP / ARP，以及
  - DNS 查询（A / AAAA / CNAME / HTTPS …）
  - TLS SNI 与握手参数
  - 明文 HTTP/1.x 请求行与响应状态
  - Top 会话、Top 端口、端点数
- **时间戳**：包行与摘要都带 ISO-8601 UTC 时间（按文件声明的 `if_tsresol` 换算）
- **大文件流式解析**：超过 16 MB 的抓包分块读取，峰值内存不随文件大小增长（上限 2 GB）
- **包级浏览**：分页读取单个数据包，支持协议 / 端口 / 主机 / 关键词过滤
- **结构化导出**：CSV（带 BOM，Excel 直接可读）与 JSON 摘要（含流与 HTTP 事务）
- **6 个 agent 工具**：让模型自己抓包并读懂流量
- **设置页面板**：后端状态、网卡选择、BPF 输入、抓包列表、包浏览、HTTP 事务、TLS 握手、导出

## 当前状态

### 已验证 ✅

- **端到端真实抓包**（Npcap 后端，9 项全过）：
  `/status` 选后端 → `/interfaces` 枚举 11 网卡 → `/start` 真实抓包 →
  抓包中读到实时包数 → `/stop` 零丢包 → `/analyze` 解析出 SNI/DNS →
  `/export` CSV 行数与包数一致 → BPF 过滤生效（156 包违规 0）
- Host 侧插件加载、**13 条** `/dsh-capture/*` HTTP 路由注册与调用
- 后端自动优选 Npcap；网卡分类正确（11 个中推荐 2 个真实网卡，误标 0）
- 默认网卡按设备名（`\Device\NPF_{GUID}`）寻址，不用易漂移的数字索引
- 结构化过滤器 → BPF 转换正确（含多条件 or 连接）
- 抓包成败按 **EPB 数据块数**判定（文件体积不可靠：合法零包文件也可能有 484 字节）
- 解析器：真实 dumpcap 产出解析正确（164 / 100 / 83 包，SNI 与 DNS 均命中）
- 解析器回归测试：带 options 的真实形状 IDB、linkType=0 容错、多包完整解析
- **TCP 重组回归测试（7 组）**：跨包 HTTP 请求/响应完整读出、乱序片段按 seq 排序、
  缺口检出、ClientHello 版本与套件、ServerHello 协商结果、ISO 时间、上限约束与开关
- **流式解析测试（9 组）**：pcapng/pcap 流式结果与整读逐字段一致、4KB chunk 跨边界、
  `maxPackets`、截断文件、非法输入、流式下的重组、**路由接线**（18.3 MB 文件经
  `/analyze` 与 `/packets` 走流式）
- 方法校验（`GET /start` → 405）、无效 id → 404、路径穿越 id → 404
- 包级浏览分页与协议/端口过滤、CSV/JSON 导出、正则检索（无效正则返 400）
- Client bundle 契约、slot 注册（`settings.section`）、图标与 manifest 契约
- **客户端契约测试（14 项）**：在沙箱里真执行 `client.js` —— 导出契约、slot 注册形状、
  面板真渲染、**只允许使用宿主真实存在的 12 个 `--dsw-alias-*` token**、无写死颜色
- 装机验证共 **48 项**、单元/契约测试 **6 组全过**、端到端 **9 项**

### 未验证 / 已知问题 ⚠️

- **pktmon + 提权助手路径未在真机跑通**：本机有 Npcap，后端自动选了它，
  因此 `run-elevated.ps1` 的 UAC 全链（提权 → 抓包 → 停止 → 转换 → 分析）
  与 UAC 拒绝分支都**未经真机验证**
- **TLS 不解密**：只解析明文握手（ClientHello / ServerHello）。应用数据是密文，
  要解密需要 SSLKEYLOGFILE 或私钥 —— 尚未支持
- **HTTP/2 与 HTTP/3 未解析**：只识别 HTTP/1.x 文本协议
- **chunked 响应体未拼接**：`Transfer-Encoding: chunked` 只记录头部，不还原分块体
- **流式解析的包数组仍随包数增长**：受 `maxAnalyzePackets` 约束，不是无上限；
  真正需要任意大时可先按 BPF 裁剪抓包
- **面板的视觉呈现未在真机上逐像素核对**：契约测试能证明它注册正确、能渲染出
  控件、且只用真实 token，但"在你当前主题下看起来好不好看"仍需肉眼确认
- 抓包文件无自动清理策略（Npcap 后端支持 `ringFileMb` 回绕，但旧文件需手动删）
- 仅 Windows；macOS / Linux 未支持

## 安装（本地开发版）

```bash
git clone https://github.com/Why-147369/dsh-capture.git
cd dsh-capture
node install-dsh-capture.mjs
```

装完**完全退出并重启 DSH App** 才生效（desktop profile 由 Electron App 独占管理）。

## 权限说明

**Npcap 后端不需要管理员权限。** `dumpcap.exe` 的 manifest 声明 `asInvoker`，
标准用户即可抓包 —— 实测在一个非提权的 DSH 会话里连续抓了三轮
（164 / 100 / 83 个包），且 Npcap 的 `AdminOnly=1` 并未阻止。

**只有 pktmon 需要管理员**，因为 `PktMon` 是内核驱动
（`TYPE=1 KERNEL_DRIVER`），设备对象只对管理员开放 —— 连只读的
`pktmon filter list` 都返回 `exit=5 无法与 PktMon 驱动程序通信。拒绝访问。`，
`netsh trace` 同样被挡。

所以：

| 你的机器 | 走哪条路 | 提权需求 |
|---|---|---|
| 装了 Wireshark（含 Npcap） | Npcap / dumpcap | **无**（首次开网卡可能弹一次 Npcap 确认框） |
| 只有系统自带 | pktmon | 一次 UAC（提权助手，助手跑完即退） |

**如果不想每次看到 Npcap 的确认框**，可一次性放宽（需管理员）：

```powershell
reg add "HKLM\SOFTWARE\WOW6432Node\Npcap" /v AdminOnly /t REG_DWORD /d 0 /f
```

**代价**：本机任何用户都能抓包。单人机器无妨，多人共用请自行权衡。

**非提权下始终可用的部分**：`capture_analyze` / `capture_search` / `packets` /
`export` 对已有 pcapng 文件的解析完全正常。

## 配置

在 profile 的 `cordis.patch.yml` 里给本插件行加 `config`（该层在插件升级后仍保留）：

```yaml
- id: dsh-capture
  config:
    maxAnalyzeBytes: 100663296   # 单次分析读入上限（字节），默认 96 MB
    maxAnalyzePackets: 200000    # 单次解析包数上限，默认 120000
    useElevation: true           # 非提权时是否经 UAC 委托抓包；无人值守可设 false
    defaultPktSize: 256          # 默认每包截取字节数 64..262144
    allowDownload: true          # 是否允许 /download 返回原始抓包字节
    reassemble: true             # 是否做 TCP 流重组（关掉可省内存，但跨包 HTTP/TLS 读不全）
    streamCapKb: 256             # 每个方向保留的重组字节上限（KB）
    maxStreams: 2000             # 单次分析最多重组的 TCP 流数
    httpBodyPreviewBytes: 4096   # HTTP 报文体预览上限（字节，0 = 不取体）
```

## Agent 工具

| 工具 | 作用 |
|---|---|
| `capture_probe` | 报告选定后端（Npcap / pktmon）、权限需求、可用网卡与默认网卡 |
| `capture_list` | 列出已保存抓包，返回寻址用 id 与**包数** |
| `capture_start` | 开始抓包。支持 `device`（网卡）、`bpf`（原始 libpcap 表达式）、`filters`（结构化）、`snaplen`、`durationSec`、`ringFileMb` |
| `capture_status` | **不停止抓包**也能看进度：已落盘包数/字节、时长、后端、已捕获 DNS/SNI 预览 |
| `capture_stop` | 停止并返回包数（Npcap 直接停；pktmon 转 pcapng） |
| `capture_analyze` | 解析抓包 → 摘要（会话/端口/DNS/**TLS 握手**/HTTP）＋ **重组后的 TCP 流与 HTTP 请求/响应配对（含报文体）** |
| `capture_search` | 在抓包里按关键词检索，**包含重组后的 HTTP 报文体**（"有没有连过 X"／"哪个请求带了这个字段"） |
| `capture_export` | 导出 CSV / JSON 到抓包目录并返回路径（无浏览器也能拿产物） |

典型用法：

```
1. capture_probe                              → 看后端与可选网卡
2. capture_start {bpf:"tcp port 443"}         → 只抓 HTTPS，文件小
3. （复现目标操作）
4. capture_status                             → 长抓包时轮询，确认目标流量已进来
5. capture_stop                               → 拿到 id 与包数
6. capture_analyze {id, topN:30}              → 看流量摘要 + HTTP 事务 + TLS 握手
7. capture_search {id, query:"api.xxx"}       → 确认是否访问过某域名/某字段
8. capture_export {id, format:"csv"}          → 拿结构化文件
```

## HTTP 路由

| 路径 | 方法 | 作用 |
|---|---|---|
| `/dsh-capture/status` | GET | 后端选择 + 环境报告 + 抓包中实时状态（`?refresh=1` 强制重枚举网卡） |
| `/dsh-capture/interfaces` | GET | 网卡清单与默认网卡（`?refresh=1` 强制刷新，可能弹一次确认） |
| `/dsh-capture/sessions` | GET | 已保存抓包列表（含包数） |
| `/dsh-capture/start` | POST | 开始抓包（自动选后端；pktmon 需提权时返回 403 + 说明） |
| `/dsh-capture/stop` | POST | 停止并返回包数 |
| `/dsh-capture/analyze` | GET/POST | 解析摘要 + `transactions`（HTTP 事务）+ `tls` + `reassembly` |
| `/dsh-capture/flows` | GET | 会话/端口/DNS/SNI/HTTP，**`streams`（重组流）与 `tlsHandshakes`**，支持 `q=` 过滤 |
| `/dsh-capture/packets` | GET | **包级浏览**：`offset`/`limit`/`proto`/`port`/`host`/`q`；每行带 `time`（ISO） |
| `/dsh-capture/export` | GET | **结构化导出**：`format=csv\|json`（CSV 含 `time`/`tls` 列） |
| `/dsh-capture/search` | GET | **正则检索**：`pattern=`（长度上限 200），含 `bodies`（报文体命中） |
| `/dsh-capture/download` | GET | 下载 pcapng（受 `allowDownload` 控制） |
| `/dsh-capture/delete` | POST | 删除抓包 |
| `/dsh-capture/raw-status` | GET | pktmon 过滤规则原文（排障用） |

## 安全设计

- **id 不可穿越**：抓包文件 id 是对文件名的 sha256 前缀；解析时二次校验路径必须落在抓包目录内
- **无 shell 注入**：所有子进程用 `spawn(cmd, argv, { shell: false })`，用户输入永不拼进命令行
- **未知块安全跳过**：pcapng 解析对未知块 / 截断包只计数不抛异常，半写文件仍可用
- **内存有界**：分析单次读入 ≤ 96 MB、解析包数 ≤ 120k；重组另有双重上限
  （每方向 `streamCapKb`、总流数 `maxStreams`），超限标记 `truncated` 而不是继续吃内存
- **重组的诚实性**：检出到 seq 空洞会记进 `gaps`，不会把不连续的数据当成完整消息

## 开发

```bash
# 安装到 desktop profile
node install-dsh-capture.mjs

# 把依赖指向修正到本仓库真身（防止下次 pnpm install 回退到旧副本）
node repoint-dsh-capture.mjs --check      # 只比较
node repoint-dsh-capture.mjs              # 备份 + 改依赖 + pnpm install + 校验

# 源码 → 安装副本同步（profile 里是 pnpm 拷的副本，不是符号链接）
node sync-dsh-capture.mjs

# 验证
node verify-installed.mjs              # 装机回归 48 项（后端/网卡/BPF/路由/重组/流式/工具/类型）
node verify-icon.cjs                   # 图标与 manifest
node recheck-22.mjs                    # 完成度清单复核（22 项）
node dsh-capture/test/selftest.mjs               # 解析器基础自测
node dsh-capture/test/pcapng-idb.test.mjs        # pcapng IDB 偏移 + if_tsresol 回归
node dsh-capture/test/stream-reassembly.test.mjs # TCP 重组 / HTTP 体 / TLS 详情（7 组）
node dsh-capture/test/streaming.test.mjs         # 流式解析 + 路由接线（9 组）
node dsh-capture/test/client-contract.test.mjs   # 客户端 bundle 契约（14 项，真执行 client.js）
node dsh-capture/test/routes.test.mjs            # 路由契约（23 项，CI 可裸跑）
```

`test/routes.test.mjs` 用假 host context 挂载真实路由，不需要已安装 profile，
也不碰网络与抓包 —— CI 上直接可跑。

## 文件结构

```
dsh-capture/
├── package.json
├── cordis.patch.yml
├── icon.svg
├── locale/{en,zh}.json
├── types/index.d.ts     # 路由与工具的数据契约（纯类型）
├── lib/
│   ├── index.js         # 入口：挂路由 + 注册 agent 工具 + Config
│   ├── routes.js        # 13 条 HTTP 路由
│   ├── pcap.js          # pcapng/pcap 解析器 + 流式解析 + TCP 重组 + HTTP/TLS 提取（零依赖）
│   ├── npcap.js         # Npcap/dumpcap 后端（首选，免提权）
│   ├── pktmon.js        # pktmon 驱动封装（后备）
│   ├── perm.js          # 后端选择与环境报告
│   ├── elevate.js       # 一次性提权助手调用方（pktmon 用）
│   ├── run-elevated.ps1 # 提权助手（跑完即退）
│   └── tools.js         # 抓包流程、后端路由、id→路径解析
├── client/client.js     # 设置页面板（纯 React + 主题 token）
└── test/
    ├── selftest.mjs               # 解析器基础自测
    ├── pcapng-idb.test.mjs        # IDB 偏移 + if_tsresol 回归
    ├── stream-reassembly.test.mjs # TCP 重组 / HTTP 体 / TLS 详情（7 组）
    ├── streaming.test.mjs         # 流式解析 + 路由接线（9 组）
    ├── client-contract.test.mjs   # 客户端 bundle 契约（14 项，真执行 client.js）
    └── routes.test.mjs            # 路由契约（23 项，无需已安装 profile）
```

## License

MIT
