# Changelog

本项目遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/) 风格。

> **状态说明**：本插件**未开发完成**，处于**测试阶段**。在 1.0.0 之前，
> API、配置项与文件格式均可能在不通知的情况下变更。

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
