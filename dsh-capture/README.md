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

- Host 侧插件加载、9 条 `/dsh-capture/*` HTTP 路由注册与调用
- 权限探测在非提权环境正确报 `needsElevation`
- 方法校验（`GET /start` → 405）、无效 id → 404、路径穿越 id → 404
- **端到端**：合成 pcapng → `analyze` 正确解析出 SNI
- 解析器自测：SNI + DNS 帧的包数 / TCP / UDP / 端口断言，含截断文件容错
- Client bundle 契约（`module.exports`）、slot 注册（`settings.section`）
- 图标与 manifest 契约

### 未验证 / 已知问题 ⚠️

- **真实提权环境下的完整抓包链路**：本机 DSH 为非提权进程，`pktmon` 返回
  `exit=5 无法与 PktMon 驱动程序通信。拒绝访问。`，因此「抓 → 停 → 转 → 析」这条链路**没有跑通过**
- **Npcap 后端未接入**：本机已装 Npcap，但其 `AdminOnly=1`，
  需改注册表（一次性提权）后才能非提权抓包；插件尚未走这条路
- **IPv6 扩展头链**在真实流量下的表现未验证
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

**非提权下仍可用的部分**：`capture_analyze` / `capture_search` 对已有 pcapng 文件的解析完全正常。

**想免去管理员？** 两条路径（尚未实现，欢迎 PR）：
1. 一次性把 Npcap 的 `AdminOnly` 改为 0，之后走 Npcap 即可非提权抓包
2. 给插件加提权代理，只把 `pktmon start/stop` 委托出去

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
| `/dsh-capture/status` | GET | 后端探测 + 当前会话状态 |
| `/dsh-capture/sessions` | GET | 已保存抓包列表 |
| `/dsh-capture/start` | POST | 开始抓包 |
| `/dsh-capture/stop` | POST | 停止并转换 |
| `/dsh-capture/analyze` | GET/POST | 解析摘要 |
| `/dsh-capture/flows` | GET | 会话/端口/DNS/SNI/HTTP，支持 `q=` 过滤 |
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
node verify-installed.mjs      # Host 侧 14 项
node verify-icon.cjs           # 图标与 manifest 16 项
node dsh-capture/test/selftest.mjs   # 解析器自测
```

## 文件结构

```
dsh-capture/
├── package.json
├── cordis.patch.yml
├── icon.svg
├── locale/zh.json
├── lib/
│   ├── index.js     # 入口：挂路由 + 注册 agent 工具
│   ├── routes.js    # HTTP 路由
│   ├── pcap.js      # pcapng/pcap 解析器（零依赖）
│   ├── pktmon.js    # pktmon 驱动封装
│   └── tools.js     # 抓包流程与 id→路径解析
├── client/client.js # 设置页面板（纯 React + 主题 token）
└── test/selftest.mjs
```

## License

MIT
