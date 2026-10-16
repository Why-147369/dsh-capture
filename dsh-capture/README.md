# dsh-capture

> **⚠️ 未开发完成 · 测试阶段（Work in Progress / Pre-release）**
>
> 本插件**尚未开发完成**，处于**测试阶段**，请勿用于生产环境。
>
> 已知限制（详见下方「当前状态」）：
> - **实时抓包需要管理员权限**，非提权下只能做离线分析
> - 抓包后端仅适配 Windows（`pktmon`）；Npcap 后端尚未接入
> - 真实提权环境下的完整抓包链路**尚未端到端验证**
> - API、配置项、文件格式均可能在后续版本中变更
>
> 欢迎反馈问题，但请预期功能不完整与行为变化。

---

## 这是什么

面向 DeepSeek Harness 的**抓包与流量分析**插件。

它填补了 DSH 插件生态的一个空白：在主流社区目录（dshfind 收录约 1.9 万条、deepseek1024 约 1.4 万条）里，
`mitmproxy` / `wireshark` / `tcpdump` / `packet-capture` 等关键词**全部零命中** —— 即此前没有任何 DSH 插件能做抓包。

## 能力

- **实时抓包**：驱动 Windows 自带的 `pktmon`，**不需要**安装 Npcap 或 Wireshark
- **离线解析**：自研 pcapng / pcap 解析器，零外部依赖
- **流量提取**：Ethernet / IPv4 / IPv6 / TCP / UDP / ICMP，以及
  - DNS 查询（A / AAAA / CNAME / HTTPS …）
  - TLS SNI 主机名（从 ClientHello 解析）
  - 明文 HTTP/1.x 请求行与响应状态
  - Top 会话、Top 端口、端点数
- **6 个 agent 工具**：让模型自己抓包并读懂流量
- **设置页面板**：开始/停止抓包、抓包列表、一键看摘要

## 当前状态

### 已验证 ✅

- Host 侧插件加载、**12 条** `/dsh-capture/*` HTTP 路由注册与调用
- 环境探测：pktmon 可用性、Npcap 安装与 `AdminOnly`、提权途径（非提权环境正确报 `需提权`）
- 方法校验（`GET /start` → 405）、无效 id → 404、路径穿越 id → 404
- **端到端**：合成 pcapng → `analyze` 正确解析出 SNI
- **包级浏览**：分页、协议过滤、端口过滤
- **导出**：CSV（带 BOM，表头正确）、JSON 摘要
- **正则检索**：命中正确；无效正则返回 400 而不抛 500
- 解析器自测：SNI + DNS 帧的包数 / TCP / UDP / 端口断言，含截断文件容错
- Client bundle 契约（`module.exports`）、slot 注册（`settings.section`）
- 图标与 manifest 契约（17 项）
- 卸载 `disposeRoutes` 清空全部注册

装机验证共 **21 项**，全部通过。

### 未验证 / 已知问题 ⚠️

- **真实提权下的完整抓包链路未端到端验证**：开发机 DSH 为非提权，
  提权助手（`run-elevated.ps1` + UAC）未在真机跑通
  「提权 → 抓包 → 停止 → 转换 → 分析」全链。UAC 拒绝分支同样未经真机验证。
- **Npcap 后端未接入**：只在探测层识别 Npcap 与 `AdminOnly`，
  实际抓包仍走 pktmon；`AdminOnly=0` 后的免提权抓包路径尚未实现
- IPv6 扩展头链在真实流量下未验证；大文件未做流式解析（整文件读入，上限 96 MB）
- 抓包文件无自动清理 / 轮转策略
- 仅 Windows 适配；macOS / Linux 未支持
- 设置页 UI 的深浅主题适配仅按 token 规则编写，未在真实页面逐项核对

## 安装（本地开发版）

```bash
git clone https://github.com/Why-147369/dsh-capture.git
cd dsh-capture
node install-dsh-capture.mjs
```

装完**完全退出并重启 DSH App** 才生效（desktop profile 由 Electron App 独占管理）。

## 权限说明

`pktmon` 需要管理员权限，这是内核层设计（驱动设备对象只对管理员开放），不是插件缺陷。
实测在非提权下，连只读的 `pktmon filter list` 都返回
`exit=5 无法与 PktMon 驱动程序通信。拒绝访问。`，`netsh trace` 同样被挡。

**三条路可选，插件会按环境自动选择：**

1. **一次性提权（默认）**：插件只把 `pktmon start/stop` 委托给一个短命的提权助手，
   弹出的 UAC 授权后助手立即退出 —— **DSH 本身始终保持普通权限**。
   拒绝 UAC 也不会报错，面板会说明替代方案。无人值守环境可用
   `useElevation: false` 关掉这条路径。
2. **让 DSH 直接以管理员运行**：最简单，但整个会话（含所有插件与子进程）
   都会继承提权令牌，安全性上不如第 1 条。
3. **放宽 Npcap，长期免提权**：若已装 Npcap，可一次性把它设为允许标准用户访问：

   ```powershell
   # 以管理员身份执行一次
   reg add "HKLM\SOFTWARE\WOW6432Node\Npcap" /v AdminOnly /t REG_DWORD /d 0 /f
   ```

   **代价**：本机任何用户都能抓包。多人共用电脑请自行权衡。
   （说明：插件目前只在探测层识别该设置，**尚未接入 Npcap 抓包后端**。）

**非提权下仍可用的部分**：`capture_analyze` / `capture_search` / `packets` /
`export` 对已有 pcapng 文件的解析完全正常 —— 只有「实时抓」这一环受权限限制。

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
```

## Agent 工具

| 工具 | 作用 |
|---|---|
| `capture_probe` | 检查抓包能力、权限状态、文件目录 |
| `capture_list` | 列出已保存抓包，返回寻址用 id |
| `capture_start` | 开始抓包，支持 ip/port/protocol 过滤（最多 16 条） |
| `capture_stop` | 停止并把 ETL 转成 pcapng |
| `capture_analyze` | 解析抓包 → 流量摘要（会话/端口/DNS/SNI/HTTP） |
| `capture_search` | 在抓包里按关键词检索（"有没有连过 X"） |

## HTTP 路由

| 路径 | 方法 | 作用 |
|---|---|---|
| `/dsh-capture/status` | GET | 环境探测（pktmon / Npcap / 提权途径）+ 当前会话状态 |
| `/dsh-capture/sessions` | GET | 已保存抓包列表 |
| `/dsh-capture/start` | POST | 开始抓包（非提权时经 UAC 委托；拒绝则返回 403 + 说明） |
| `/dsh-capture/stop` | POST | 停止并转换 |
| `/dsh-capture/analyze` | GET/POST | 解析摘要 |
| `/dsh-capture/flows` | GET | 会话/端口/DNS/SNI/HTTP，支持 `q=` 过滤 |
| `/dsh-capture/packets` | GET | **包级浏览**：`offset`/`limit`/`proto`/`port`/`host`/`q` |
| `/dsh-capture/export` | GET | **结构化导出**：`format=csv\|json` |
| `/dsh-capture/search` | GET | **正则检索**：`pattern=`（长度上限 200） |
| `/dsh-capture/download` | GET | 下载 pcapng |
| `/dsh-capture/delete` | POST | 删除抓包 |
| `/dsh-capture/raw-status` | GET | pktmon 过滤规则原文（排障用） |

## 安全设计

- **id 不可穿越**：抓包文件 id 是对文件名的 sha256 前缀；解析时二次校验路径必须落在抓包目录内
- **无 shell 注入**：所有子进程用 `spawn(cmd, argv, { shell: false })`，用户输入永不拼进命令行
- **未知块安全跳过**：pcapng 解析对未知块 / 截断包只计数不抛异常，半写文件仍可用
- **内存有界**：分析单次读入 ≤ 96 MB、解析包数 ≤ 120k，超限时明确报错

## 开发

```bash
# 安装到 desktop profile
node install-dsh-capture.mjs

# 源码 → 安装副本同步（profile 里是 pnpm 拷的副本，不是符号链接）
node sync-dsh-capture.mjs

# 验证
node verify-installed.mjs            # 装机回归 21 项
node verify-icon.cjs                 # 图标与 manifest 17 项
node dsh-capture/test/selftest.mjs   # 解析器自测
```

## 文件结构

```
dsh-capture/
├── package.json
├── cordis.patch.yml
├── icon.svg
├── locale/{en,zh}.json
├── lib/
│   ├── index.js         # 入口：挂路由 + 注册 agent 工具 + Config
│   ├── routes.js        # 12 条 HTTP 路由
│   ├── pcap.js          # pcapng/pcap 解析器（零依赖）
│   ├── pktmon.js        # pktmon 驱动封装（非提权路径）
│   ├── perm.js          # 环境与权限探测（pktmon / Npcap / AdminOnly）
│   ├── elevate.js       # 一次性提权助手调用方
│   ├── run-elevated.ps1 # 提权助手（跑完即退）
│   └── tools.js         # 抓包流程与 id→路径解析
├── client/client.js     # 设置页面板（纯 React + 主题 token）
└── test/selftest.mjs
```

## License

MIT
