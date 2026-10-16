/**
 * dsh-capture host entry.
 *
 * Mounts the /dsh-capture/* HTTP routes once the profile composes the
 * webServer service, and registers agent-facing tools so the model can start
 * a capture, inspect a finished one, and pull structured traffic facts
 * (talkers, ports, DNS names, TLS SNI, plaintext HTTP) without reading pcap
 * bytes itself.
 *
 * Tool definitions follow the host's `defineTool` shape: `parameters` is a
 * plain property map whose fields carry `required: true`, and the result is
 * produced by `execute(args, exec)`. A `output.schema` is declared so the
 * model sees a typed result instead of free-form JSON.
 *
 * The route mount is idempotent per process: if this entry is ever composed
 * twice (for example a future `dsh plugin` reconcile adds the package to
 * `dsh.profile.bundles` while the profile patch also inserts it), the second
 * fiber no-ops instead of throwing on the duplicate-route contract.
 */
import { readFileSync, statSync } from 'node:fs';
import { basename } from 'node:path';
import z from '@deepseek-ai/schemastery';
import { parseCapture, DNS_TYPES } from './pcap.js';
import { mountRoutes } from './routes.js';
import { clearFilters } from './pktmon.js';
import { probeEnvironment } from './perm.js';
import {
  captureDir, listCaptures, resolveCaptureId,
  startCaptureFlow, stopCaptureFlow,
} from './tools.js';

export const name = 'dsh-capture';

/**
 * Tunable settings, declared with the host's schemastery schema so the profile
 * can validate and override them from `cordis.patch.yml` under this plugin's
 * row; that patch layer survives plugin upgrades.
 *
 * Read values with `readConfig(config)` — schemastery resolves `.default(...)`
 * layers, but a direct unit test may pass a plain object, so the reader is
 * defensive about both shapes.
 */
export const Config = z.object({
  /** Bytes read into memory for one analysis call. */
  maxAnalyzeBytes: z.number().step(1).min(1).default(96 * 1024 * 1024),
  /** Packets parsed per analysis call. */
  maxAnalyzePackets: z.number().step(1).min(1).default(120000),
  /**
   * Try the one-shot elevated helper when DSH itself is not elevated.
   * Set false to never show a UAC prompt.
   */
  useElevation: z.boolean().default(true),
  /** Default per-packet capture size when a caller does not specify one. */
  defaultPktSize: z.number().step(1).min(64).default(256),
  /** Allow the download route to return raw capture bytes. */
  allowDownload: z.boolean().default(true),
});

const DEFAULTS = {
  maxAnalyzeBytes: 96 * 1024 * 1024,
  maxAnalyzePackets: 120000,
  useElevation: true,
  defaultPktSize: 256,
  allowDownload: true,
};

/**
 * Read a config value, tolerating schemastery values, plain objects, and
 * missing config alike.
 * @param {object} config
 * @param {string} key
 * @returns {any}
 */
export function readConfigValue(config, key) {
  const fallback = DEFAULTS[key];
  if (!config || typeof config !== 'object') return fallback;
  const raw = config[key];
  if (raw === undefined || raw === null) return fallback;
  // schemastery wraps values; unwrap defensively.
  const unwrapped = (typeof raw === 'object' && typeof raw.get === 'function') ? raw.get() : raw;
  if (unwrapped === undefined || unwrapped === null) return fallback;
  if (typeof fallback === 'number') {
    const n = Number(unwrapped);
    return Number.isFinite(n) && n > 0 ? n : fallback;
  }
  if (typeof fallback === 'boolean') return unwrapped !== false;
  return unwrapped;
}

/**
 * Normalize the whole config into plain values.
 * @param {object} config
 * @returns {object}
 */
function readConfig(config) {
  return {
    maxAnalyzeBytes: readConfigValue(config, 'maxAnalyzeBytes'),
    maxAnalyzePackets: readConfigValue(config, 'maxAnalyzePackets'),
    useElevation: readConfigValue(config, 'useElevation'),
    defaultPktSize: readConfigValue(config, 'defaultPktSize'),
    allowDownload: readConfigValue(config, 'allowDownload'),
  };
}

let mounted = false;

/**
 * Register the plugin against the host context.
 * @param {object} ctx host context (may acquire webServer and tools services)
 * @param {object} config optional profile override
 */
export function apply(ctx, config) {
  // Normalize once: schemastery gives a validated object, but a direct unit
  // test may pass a plain object or nothing at all.
  const cfg = readConfig(config);

  ctx.inject(['webServer'], (hostCtx) => {
    hostCtx.effect(() => {
      if (mounted) return;
      mounted = true;
      const disposeRoutes = mountRoutes(hostCtx, cfg);
      return () => {
        mounted = false;
        disposeRoutes();
      };
    }, 'dsh-capture: http routes');
  });

  // Agent tools are optional: a profile without the tools service still gets
  // the HTTP panel, so this stays behind an inject instead of throwing.
  ctx.inject(['tools'], (toolCtx) => {
    toolCtx.effect(() => registerTools(toolCtx, cfg), 'dsh-capture: agent tools');
  });
}

/**
 * Build the tool surface.
 * @param {object} ctx context carrying the tools service
 * @param {object} cfg plugin config
 * @returns {() => void} disposer
 */
function registerTools(ctx, cfg) {
  const disposers = [];
  const tools = ctx.tools;
  if (!tools || typeof tools.register !== 'function') return () => {};

  /**
   * Register one defineTool result. `tools.register` is the documented entry;
   * a returned disposer, when present, is collected for teardown.
   * @param {object} definition
   */
  const add = (definition) => {
    const dispose = tools.register(definition);
    if (typeof dispose === 'function') disposers.push(dispose);
  };

  add({
    name: 'capture_probe',
    description:
      '检查本机抓包能力：pktmon 是否可用、是否缺管理员权限、Npcap 安装与 AdminOnly 设置、可用的提权途径。在 capture_start 之前调用一次；抓包失败时也用它解释原因。',
    parameters: {},
    output: {
      schema: {
        type: 'object',
        additionalProperties: true,
        required: true,
        properties: { ok: { type: 'boolean', required: true } },
      },
      render: (_args, value) => {
        const lines = [];
        const flag = (b) => (b ? '是' : '否');
        lines.push(`平台: ${value.platform} | 可抓包: ${flag(value.canCapture)} | 需提权才可抓: ${flag(value.canCaptureWithElevation)}`);
        lines.push(`pktmon: 存在=${flag(value.pktmonExists)} 可用=${flag(value.pktmonUsable)} 需提权=${flag(value.pktmonNeedsElevation)}`);
        if (value.npcap) {
          lines.push(`Npcap: 已装=${flag(value.npcap.installed)} 驱动运行=${flag(value.npcap.driverRunning)} AdminOnly=${value.npcap.adminOnly ?? '未知'} 可非提权抓包=${flag(value.npcap.clickableCapture)}`);
        }
        if (value.cli && (value.cli.tshark || value.cli.dumpcap)) {
          lines.push(`外部工具: tshark=${value.cli.tshark || '无'} dumpcap=${value.cli.dumpcap || '无'}`);
        }
        if (value.elevation) lines.push(`提权途径: 支持=${flag(value.elevation.supported)} (${value.elevation.mechanism})`);
        lines.push(`目录: ${value.dir ?? ''}`);
        if (Array.isArray(value.notes) && value.notes.length) {
          lines.push('');
          lines.push(...value.notes);
        }
        return [{ type: 'text', text: lines.join('\n') }];
      },
    },
    execute: async () => {
      const backend = await probeEnvironment();
      return { ...backend, ok: true, dir: captureDir() };
    },
  });

  add({
    name: 'capture_list',
    description:
      '列出本机已保存的抓包文件。返回每个抓包的 id（其余 capture_* 工具用它寻址）、文件名、大小与修改时间。',
    parameters: {},
    output: {
      schema: {
        type: 'object',
        additionalProperties: true,
        required: true,
        properties: { ok: { type: 'boolean', required: true } },
      },
      render: (_args, value) => [{
        type: 'text',
        text: value.captures?.length
          ? `共 ${value.captures.length} 个抓包：\n` + value.captures
            .slice(0, 30)
            .map((c) => `- id=${c.id} ${c.name} (${(c.size / 1024).toFixed(1)} KB)`)
            .join('\n')
          : `没有抓包文件。目录：${value.dir}`,
      }],
    },
    execute: async () => ({ ok: true, dir: captureDir(), captures: listCaptures() }),
  });

  add({
    name: 'capture_start',
    description:
      '用 Windows 自带 pktmon 开始实时抓包。可用 filters 限定范围以缩小文件（最多 16 条）。多数环境需要管理员权限；失败原因由 capture_probe 解释。开始后必须调用 capture_stop 结束并转换文件。',
    parameters: {
      name: {
        type: 'string',
        description: '文件名主干，仅允许字母数字与 ._-，最长 48 字符。省略则自动生成。',
      },
      filters: {
        type: 'array',
        description: 'pktmon 过滤规则，例如 [{"ip":"1.1.1.1"},{"port":443},{"protocol":"TCP"}]。留空抓全部流量（文件会很大）。',
        items: {
          type: 'object',
          additionalProperties: false,
          properties: {
            ip: { type: 'string', description: 'IP 地址过滤。' },
            port: { type: 'integer', description: '端口过滤。' },
            protocol: { type: 'string', enum: ['TCP', 'UDP', 'ICMP'], description: '传输层协议过滤。' },
          },
        },
      },
      maxPktSize: {
        type: 'integer',
        description: '每包截取字节数 64..262144，默认 256。只关心首部与握手时可用更小值。',
      },
      maxFileMb: {
        type: 'integer',
        description: '可选的文件体积上限（MB），到达后 pktmon 会复用文件。',
      },
    },
    output: {
      schema: {
        type: 'object',
        additionalProperties: true,
        required: true,
        properties: { ok: { type: 'boolean', required: true } },
      },
      render: (_args, value) => [{
        type: 'text',
        text: value.ok
          ? `抓包已开始：${value.state?.etl ?? ''}\n${value.hint ?? ''}`
          : `启动失败：${value.error ?? '未知错误'}`,
      }],
    },
    execute: async (args) => startCaptureFlow({
      name: args?.name,
      filters: Array.isArray(args?.filters) ? args.filters : [],
      maxPktSize: Number(args?.maxPktSize) || cfg.defaultPktSize,
      maxFileMb: Number(args?.maxFileMb) || undefined,
      // Config can forbid UAC prompts entirely for unattended setups.
      elevate: cfg.useElevation !== false,
    }),
  });

  add({
    name: 'capture_stop',
    description:
      '停止正在进行的抓包，把 ETL 转换为 pcapng，并返回新抓包的 id。capture_start 之后必须调用；同时会清理 pktmon 过滤规则。',
    parameters: {},
    output: {
      schema: {
        type: 'object',
        additionalProperties: true,
        required: true,
        properties: { ok: { type: 'boolean', required: true } },
      },
      render: (_args, value) => [{
        type: 'text',
        text: value.ok
          ? `抓包已停止并转换：id=${value.capture?.id ?? '?'} ${value.capture?.name ?? ''} (${((value.sizeBytes ?? 0) / 1024).toFixed(1)} KB)\n${value.hint ?? ''}`
          : `停止流程未产出可分析文件：${value.error ?? ''}`,
      }],
    },
    execute: async () => stopCaptureFlow(),
  });

  add({
    name: 'capture_analyze',
    description:
      '解析一个已保存的抓包（id 来自 capture_list），返回流量摘要：包/字节数、时间范围、Top 会话、Top 端口、DNS 查询、TLS SNI 主机名、明文 HTTP 请求。这是理解抓包内容的主要工具。',
    parameters: {
      id: { type: 'string', required: true, description: 'capture_list 返回的抓包 id。' },
      topN: { type: 'integer', description: '返回的会话/端口条数，默认 20，最大 100。' },
    },
    output: {
      schema: {
        type: 'object',
        additionalProperties: true,
        required: true,
        properties: { ok: { type: 'boolean', required: true } },
      },
      render: (_args, value) => {
        if (!value.ok) return [{ type: 'text', text: `分析失败：${value.error ?? ''}` }];
        const m = value.meta ?? {};
        const lines = [
          `文件 ${value.file} | ${(value.sizeBytes / 1024).toFixed(1)} KB | 包 ${m.packets} | 字节 ${m.bytes}`,
          `TCP ${m.tcpPackets ?? 0} / UDP ${m.udpPackets ?? 0}`,
          `DNS 名称 ${value.summary?.dnsNames ?? 0} | TLS 主机 ${value.summary?.httpsHosts ?? 0} | HTTP 请求 ${value.summary?.httpRequests ?? 0} | 端点 ${value.summary?.endpoints ?? 0}`,
        ];
        if (value.sni?.length) lines.push('TLS SNI: ' + value.sni.slice(0, 10).map((s) => `${s.name}(${s.count})`).join(', '));
        if (value.dns?.length) lines.push('DNS: ' + value.dns.slice(0, 10).map((d) => `${d.name}/${d.type}`).join(', '));
        if (value.talkers?.length) lines.push('Top 会话: ' + value.talkers.slice(0, 5).map((t) => `${t.src}->${t.dst}(${t.bytes}B)`).join(', '));
        if (value.stats?.malformed) lines.push(`跳过畸形包 ${value.stats.malformed}，截断 ${value.stats.truncated ?? 0}`);
        return [{ type: 'text', text: lines.join('\n') }];
      },
    },
    execute: async (args) => {
      const full = resolveCaptureId(String(args?.id ?? ''));
      if (!full) return { ok: false, error: 'capture id 无效或文件已删除。先用 capture_list 获取有效 id。' };
      const topN = Math.min(100, Math.max(1, Number(args?.topN) || 20));
      return analyzeBounded(full, topN, cfg);
    },
  });

  add({
    name: 'capture_search',
    description:
      '在一个抓包里按关键词检索：匹配 DNS 查询名、TLS SNI 主机名、HTTP 主机/路径，以及包含该关键词的 IP 端点。用于回答「这次会话有没有连过 X」。',
    parameters: {
      id: { type: 'string', required: true, description: 'capture_list 返回的抓包 id。' },
      query: { type: 'string', required: true, description: '大小写不敏感的子串关键词。' },
      limit: { type: 'integer', description: '每类最多返回条数，默认 50，最大 200。' },
    },
    output: {
      schema: {
        type: 'object',
        additionalProperties: true,
        required: true,
        properties: { ok: { type: 'boolean', required: true } },
      },
      render: (_args, value) => {
        if (!value.ok) return [{ type: 'text', text: `检索失败：${value.error ?? ''}` }];
        const n = (value.dns?.length ?? 0) + (value.sni?.length ?? 0)
          + (value.http?.length ?? 0) + (value.endpoints?.length ?? 0);
        if (!n) return [{ type: 'text', text: `「${value.query}」在该抓包中没有匹配。` }];
        return [{
          type: 'text',
          text: `「${value.query}」命中 ${n} 条：`
            + `\nDNS ${value.dns?.length ?? 0} | SNI ${value.sni?.length ?? 0} | HTTP ${value.http?.length ?? 0} | 端点 ${value.endpoints?.length ?? 0}`
            + (value.sni?.length ? `\nSNI: ${value.sni.slice(0, 8).map((s) => s.name).join(', ')}` : '')
            + (value.dns?.length ? `\nDNS: ${value.dns.slice(0, 8).map((d) => d.name).join(', ')}` : ''),
        }];
      },
    },
    execute: async (args) => {
      const full = resolveCaptureId(String(args?.id ?? ''));
      if (!full) return { ok: false, error: 'capture id 无效或文件已删除。' };
      const q = String(args?.query ?? '').trim().toLowerCase();
      if (!q) return { ok: false, error: 'query 不能为空。' };
      const limit = Math.min(200, Math.max(1, Number(args?.limit) || 50));
      return searchCapture(full, q, limit, cfg);
    },
  });

  return () => {
    // Drop any pktmon filter this plugin installed, then drop registrations.
    clearFilters().catch(() => {});
    for (const d of disposers) { try { d(); } catch { /* teardown must not throw */ } }
  };
}

/**
 * Packet cap for one parse call.
 * @param {object} cfg normalized config
 * @returns {number}
 */
function maxPacketsFrom(cfg) {
  const n = Number(cfg?.maxAnalyzePackets);
  return Number.isFinite(n) && n > 0 ? n : DEFAULTS.maxAnalyzePackets;
}

/**
 * Analyze a capture with hard memory bounds.
 * @param {string} full absolute path resolved from a known id
 * @param {number} topN
 * @param {object} cfg
 * @returns {object}
 */
function analyzeBounded(full, topN, cfg) {
  const st = statSync(full);
  const cap = Number.isFinite(cfg?.maxAnalyzeBytes) ? cfg.maxAnalyzeBytes : DEFAULTS.maxAnalyzeBytes;
  if (st.size > cap) {
    return {
      ok: false,
      error: `抓包文件 ${(st.size / 1048576).toFixed(1)} MB 超过分析上限 ${(cap / 1048576).toFixed(0)} MB。可用 filters 缩小抓包范围，或提高插件 config 的 maxAnalyzeBytes。`,
      file: basename(full),
      sizeBytes: st.size,
    };
  }
  const parsed = parseCapture(readFileSync(full), { maxPackets: maxPacketsFrom(cfg) });
  const { packets, http, dns, sni, talkers, topPorts, meta, stats } = parsed;
  return {
    ok: true,
    file: basename(full),
    sizeBytes: st.size,
    meta,
    stats,
    talkers: talkers.slice(0, topN),
    topPorts: topPorts.slice(0, topN),
    dns: dns.slice(0, topN * 4).map((d) => ({ ...d, type: DNS_TYPES[d.type] || String(d.type) })),
    sni: sni.slice(0, topN),
    http: http.slice(0, topN),
    summary: {
      dnsNames: [...new Set(dns.map((d) => d.name))].length,
      httpsHosts: [...new Set(sni.map((s) => s.name))].length,
      httpRequests: http.length,
      endpoints: [...new Set([...talkers.map((t) => t.src), ...talkers.map((t) => t.dst)])].length,
      packetSample: packets.slice(0, 20).map((p) => ({
        proto: p.proto, src: p.src, dst: p.dst,
        sport: p.sport ?? null, dport: p.dport ?? null, bytes: p.bytes ?? 0,
      })),
    },
  };
}

/**
 * Keyword search across the derived views of a capture.
 * @param {string} full
 * @param {string} q already lowercased
 * @param {number} limit
 * @param {object} cfg
 * @returns {object}
 */
function searchCapture(full, q, limit, cfg) {
  const parsed = analyzeBounded(full, 100, cfg);
  if (!parsed.ok) return parsed;
  const hit = (s) => String(s ?? '').toLowerCase().includes(q);
  return {
    ok: true,
    query: q,
    file: parsed.file,
    dns: parsed.dns.filter((d) => hit(d.name)).slice(0, limit),
    sni: parsed.sni.filter((s) => hit(s.name)).slice(0, limit),
    http: parsed.http.filter((h) => hit(h.host) || hit(h.path) || hit(h.method)).slice(0, limit),
    endpoints: parsed.talkers
      .filter((t) => hit(t.src) || hit(t.dst))
      .slice(0, limit)
      .map((t) => ({ src: t.src, dst: t.dst, packets: t.packets, bytes: t.bytes })),
    ports: parsed.topPorts.filter((p) => hit(String(p.port))).slice(0, limit),
  };
}
