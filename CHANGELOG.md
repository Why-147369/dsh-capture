# Changelog

本项目遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/) 风格。

> **状态说明**：本插件**未开发完成**，处于**测试阶段**。在 1.0.0 之前，
> API、配置项与文件格式均可能在不通知的情况下变更。

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
