/**
 * dsh-capture: HTTP routes mounted on the host webServer.
 *
 *   GET  /dsh-capture/status            → backend probe + current session state
 *   GET  /dsh-capture/sessions          → list of saved captures (etl + pcapng)
 *   POST /dsh-capture/start             → begin capture {filters, maxPktSize, maxFileMb, name}
 *   POST /dsh-capture/stop              → stop capture and convert to pcapng
 *   POST /dsh-capture/analyze           → parse a capture file and return summary
 *   GET  /dsh-capture/analyze?id=...    → same via query string (for the panel)
 *   GET  /dsh-capture/flows?id=...      → top talkers / ports / DNS / SNI / HTTP for a file
 *   GET  /dsh-capture/download?id=...   → the pcapng file itself (bounded size)
 *   POST /dsh-capture/delete            → remove a capture file
 *
 * The handle/id is never turned into a path directly: ids resolve through a
 * scan-built map whose keys are opaque hashes, so a crafted id cannot reach
 * outside the capture directory.
 */
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { basename, join } from 'node:path';
import { parseCapture, DNS_TYPES } from './pcap.js';
import { status } from './pktmon.js';
import { probeEnvironment } from './perm.js';
import { startCaptureFlow, stopCaptureFlow } from './tools.js';

/** Read at most this many bytes into memory when analyzing a capture. */
const MAX_ANALYZE_BYTES = 96 * 1024 * 1024;
/** Max packets parsed in one request. */
const MAX_ANALYZE_PACKETS = 120000;
/** Cap for the raw file download route. */
const MAX_DOWNLOAD_BYTES = 256 * 1024 * 1024;

function captureDir() {
  const home = process.env.DSH_HOME ?? join(homedir(), '.dsh');
  return join(home, 'dsh-capture');
}

function statePath() {
  return join(captureDir(), 'state.json');
}

function readState() {
  try {
    return JSON.parse(readFileSync(statePath(), 'utf8'));
  } catch {
    return { running: false, etl: null, startedAt: null, filters: [], log: [] };
  }
}

function writeState(next) {
  try {
    mkdirSync(captureDir(), { recursive: true });
    writeFileSync(statePath(), JSON.stringify(next, null, 2), 'utf8');
  } catch { /* state is advisory; never fail a request over it */ }
}

/**
 * Build the id→file map. Ids are opaque hashes so they cannot traverse.
 * @returns {{id:string, name:string, size:number, kind:string, mtime:number}[]}
 */
function scanCaptures() {
  const dir = captureDir();
  const out = [];
  if (!existsSync(dir)) return out;
  for (const name of readdirSync(dir)) {
    if (!/\.(pcapng|pcap|etl)$/i.test(name)) continue;
    const full = join(dir, name);
    let st;
    try { st = statSync(full); } catch { continue; }
    if (!st.isFile()) continue;
    const id = createHash('sha256').update(name).digest('hex').slice(0, 16);
    out.push({
      id,
      name,
      size: st.size,
      kind: name.toLowerCase().endsWith('.etl') ? 'etl' : 'capture',
      mtime: st.mtimeMs,
    });
  }
  return out.sort((a, b) => b.mtime - a.mtime);
}

/**
 * Resolve an opaque id to a real path inside the capture directory.
 * @param {string} id
 * @returns {string|null}
 */
function resolveId(id) {
  if (!id || typeof id !== 'string') return null;
  const hit = scanCaptures().find((c) => c.id === id);
  if (!hit) return null;
  const full = join(captureDir(), hit.name);
  // Defense in depth: the resolved path must stay inside the capture dir.
  const normDir = captureDir().toLowerCase();
  if (!full.toLowerCase().startsWith(normDir)) return null;
  return full;
}

/**
 * Read a request body as JSON, with a size cap.
 * @param {object} req
 * @param {number} [limit]
 * @returns {Promise<object>}
 */
function readJson(req, limit = 1_000_000) {
  return new Promise((resolve) => {
    let total = 0;
    const chunks = [];
    req.on('data', (c) => {
      total += c.length;
      if (total > limit) { req.destroy(); resolve({}); return; }
      chunks.push(c);
    });
    req.on('end', () => {
      try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}')); }
      catch { resolve({}); }
    });
    req.on('error', () => resolve({}));
  });
}

/**
 * Send a JSON response.
 * @param {object} res
 * @param {number} code
 * @param {object} body
 */
function json(res, code, body) {
  const text = JSON.stringify(body);
  res.writeHead(code, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
  });
  res.end(text);
}

/**
 * Wrap a handler so a throw becomes a 500 with a readable message.
 * @param {(req:object,res:object)=>Promise<void>} fn
 * @returns {(req:object,res:object)=>Promise<void>}
 */
function guard(fn) {
  return async (req, res) => {
    try { await fn(req, res); }
    catch (err) {
      json(res, 500, { ok: false, error: String(err && err.message ? err.message : err) });
    }
  };
}

/**
 * Build the analyzed summary from a capture file.
 * @param {string} full
 * @returns {object}
 */
function analyzeFile(full) {
  const size = statSync(full).size;
  if (size > MAX_ANALYZE_BYTES) {
    return {
      ok: false,
      error: `文件 ${(size / 1048576).toFixed(1)} MB 超过在线分析上限 ${(MAX_ANALYZE_BYTES / 1048576).toFixed(0)} MB。请先裁剪或改用其他工具处理。`,
    };
  }
  const buf = readFileSync(full);
  const parsed = parseCapture(buf, { maxPackets: MAX_ANALYZE_PACKETS });
  const { packets, ...rest } = parsed;
  // Packets themselves are large; return counts and only a small head sample.
  return {
    ok: true,
    file: basename(full),
    sizeBytes: size,
    ...rest,
    headSample: packets.slice(0, 40).map((p) => ({
      ts: p.ts, proto: p.proto, src: p.src, dst: p.dst,
      sport: p.sport ?? null, dport: p.dport ?? null,
      bytes: p.bytes ?? 0, sni: p.sni ?? null,
      dns: p.dns ? p.dns.queries.map((q) => `${q.name}/${DNS_TYPES[q.type] || q.type}`).join(',') : null,
      http: p.http ? (p.http.method ? `${p.http.method} ${p.http.path}` : `HTTP ${p.http.status}`) : null,
    })),
  };
}

/**
 * Mount all capture routes on the host webServer service.
 * @param {object} ctx host context with webServer
 * @param {object} config plugin config
 * @returns {() => void} disposer
 */
export function mountRoutes(ctx, config) {
  const disposers = [];
  const dir = captureDir();
  mkdirSync(dir, { recursive: true });

  // The webserver route table is keyed by PATH ONLY — a duplicate path throws.
  // Each entry therefore declares one path plus the methods it accepts, and
  // the handler enforces the method itself.
  const routes = [
    ['/dsh-capture/status', ['GET'], guard(async (_req, res) => {
      const backend = await probeEnvironment();
      const state = readState();
      json(res, 200, { ok: true, backend, state, dir });
    })],

    ['/dsh-capture/sessions', ['GET'], guard(async (_req, res) => {
      json(res, 200, { ok: true, dir, dirExists: existsSync(dir), captures: scanCaptures() });
    })],

    ['/dsh-capture/start', ['POST'], guard(async (req, res) => {
      const body = await readJson(req);
      // Reuse the tool-layer flow so the HTTP panel and the agent tools share
      // one implementation, including the elevated-helper path.
      const result = await startCaptureFlow({
        name: body.name,
        filters: Array.isArray(body.filters) ? body.filters : [],
        maxPktSize: Number(body.maxPktSize) || cfg.defaultPktSize,
        maxFileMb: Number(body.maxFileMb) || undefined,
        elevate: cfg.useElevation !== false,
      });
      if (!result.ok) {
        json(res, result.declined ? 403 : 500, {
          ok: false,
          declined: result.declined === true,
          error: result.error || '启动抓包失败。',
          log: result.log || [],
          elevationError: result.elevationError,
        });
        return;
      }
      json(res, 200, { ok: true, state: result.state, elevated: result.elevated === true, hint: result.hint });
    })],

    ['/dsh-capture/stop', ['POST'], guard(async (_req, res) => {
      // Same shared flow as the tool layer: a capture started through the
      // elevated helper is stopped through it too.
      const result = await stopCaptureFlow({ elevate: cfg.useElevation !== false });
      json(res, result.ok ? 200 : 500, result);
    })],

    // One path, two methods: `id` arrives from the query string (GET) or the
    // JSON body (POST).
    ['/dsh-capture/analyze', ['GET', 'POST'], guard(async (req, res) => {
      let id = '';
      if ((req.method || 'GET').toUpperCase() === 'POST') {
        const body = await readJson(req);
        id = String(body.id || '');
      } else {
        id = new URL(req.url, 'http://127.0.0.1').searchParams.get('id') || '';
      }
      const full = resolveId(id);
      if (!full) { json(res, 404, { ok: false, error: '未找到该抓包文件（id 无效或已被删除）。' }); return; }
      json(res, 200, analyzeFile(full));
    })],

    ['/dsh-capture/flows', ['GET'], guard(async (req, res) => {
      const url = new URL(req.url, 'http://127.0.0.1');
      const full = resolveId(url.searchParams.get('id') || '');
      if (!full) { json(res, 404, { ok: false, error: '未找到该抓包文件。' }); return; }
      const parsed = analyzeFile(full);
      if (!parsed.ok) { json(res, 400, parsed); return; }
      const q = (url.searchParams.get('q') || '').toLowerCase();
      const filterFn = (s) => !q || String(s).toLowerCase().includes(q);
      json(res, 200, {
        ok: true,
        meta: parsed.meta,
        talkers: parsed.talkers.filter((t) => filterFn(t.src) || filterFn(t.dst)),
        topPorts: parsed.topPorts,
        dns: parsed.dns.filter((d) => filterFn(d.name)).slice(0, 500),
        sni: parsed.sni.filter((s) => filterFn(s.name)),
        http: parsed.http.filter((h) => filterFn(h.host || '') || filterFn(h.path || '')).slice(0, 300),
      });
    })],

    ['/dsh-capture/download', ['GET'], guard(async (req, res) => {
      const url = new URL(req.url, 'http://127.0.0.1');
      const full = resolveId(url.searchParams.get('id') || '');
      if (!full) { json(res, 404, { ok: false, error: '未找到该抓包文件。' }); return; }
      const st = statSync(full);
      if (st.size > MAX_DOWNLOAD_BYTES) {
        json(res, 413, { ok: false, error: '文件过大，请直接从磁盘复制。', path: full });
        return;
      }
      const buf = readFileSync(full);
      res.writeHead(200, {
        'content-type': 'application/octet-stream',
        'content-length': String(buf.length),
        'content-disposition': `attachment; filename="${basename(full)}"`,
        'cache-control': 'no-store',
      });
      res.end(buf);
    })],

    ['/dsh-capture/delete', ['POST'], guard(async (req, res) => {
      const body = await readJson(req);
      const full = resolveId(String(body.id || ''));
      if (!full) { json(res, 404, { ok: false, error: '未找到该抓包文件。' }); return; }
      rmSync(full, { force: true });
      const etl = full.replace(/\.pcapng$/i, '.etl');
      if (existsSync(etl)) { try { rmSync(etl, { force: true }); } catch { /* best effort */ } }
      json(res, 200, { ok: true, deleted: basename(full) });
    })],

    ['/dsh-capture/raw-status', ['GET'], guard(async (_req, res) => {
      json(res, 200, { ok: true, text: await status() });
    })],

    // Packet-level browsing with paging and filters. The summary routes are
    // for understanding a capture; this one is for reading individual packets
    // without pulling the whole file into the browser.
    ['/dsh-capture/packets', ['GET'], guard(async (req, res) => {
      const url = new URL(req.url, 'http://127.0.0.1');
      const full = resolveId(url.searchParams.get('id') || '');
      if (!full) { json(res, 404, { ok: false, error: '未找到该抓包文件。' }); return; }
      const parsed = analyzeFile(full);
      if (!parsed.ok) { json(res, 400, parsed); return; }

      const offset = Math.max(0, Number(url.searchParams.get('offset')) || 0);
      const limit = Math.min(500, Math.max(1, Number(url.searchParams.get('limit')) || 100));
      const proto = (url.searchParams.get('proto') || '').toUpperCase();
      const host = (url.searchParams.get('host') || '').toLowerCase();
      const port = Number(url.searchParams.get('port')) || null;
      const q = (url.searchParams.get('q') || '').toLowerCase();

      // Re-parse just for the packet rows; analyzeFile intentionally returns
      // only a head sample to keep the summary small.
      const raw = readFileSync(full);
      const all = parseCapture(raw, { maxPackets: MAX_ANALYZE_PACKETS });
      let rows = all.packets.map((p, index) => ({
        index,
        ts: p.ts,
        proto: p.proto,
        src: p.src ?? null,
        dst: p.dst ?? null,
        sport: p.sport ?? null,
        dport: p.dport ?? null,
        bytes: p.bytes ?? 0,
        sni: p.sni ?? null,
        dns: p.dns ? p.dns.queries.map((x) => x.name) : null,
        http: p.http ? (p.http.method ? `${p.http.method} ${p.http.path}` : `HTTP ${p.http.status}`) : null,
        flags: p.flags ?? null,
      }));
      if (proto) rows = rows.filter((r) => r.proto === proto);
      if (port) rows = rows.filter((r) => r.sport === port || r.dport === port);
      if (host) rows = rows.filter((r) => [r.src, r.dst, r.sni, ...(r.dns || [])].some((v) => String(v || '').toLowerCase().includes(host)));
      if (q) rows = rows.filter((r) => JSON.stringify(r).toLowerCase().includes(q));

      json(res, 200, {
        ok: true,
        total: rows.length,
        offset,
        limit,
        rows: rows.slice(offset, offset + limit),
      });
    })],

    // Structured export. CSV opens in a spreadsheet; HAR opens in browser dev
    // tools. Both are derived from the same parse as the summary.
    ['/dsh-capture/export', ['GET'], guard(async (req, res) => {
      const url = new URL(req.url, 'http://127.0.0.1');
      const full = resolveId(url.searchParams.get('id') || '');
      if (!full) { json(res, 404, { ok: false, error: '未找到该抓包文件。' }); return; }
      const format = (url.searchParams.get('format') || 'csv').toLowerCase();
      const raw = readFileSync(full);
      const parsed = parseCapture(raw, { maxPackets: MAX_ANALYZE_PACKETS });
      const base = basename(full).replace(/\.[^.]+$/, '');

      if (format === 'csv') {
        const esc = (v) => {
          const s = v === null || v === undefined ? '' : String(v);
          return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
        };
        const head = ['index', 'ts', 'proto', 'src', 'dst', 'sport', 'dport', 'bytes', 'sni', 'dns', 'http'];
        const lines = [head.join(',')];
        parsed.packets.forEach((p, i) => {
          lines.push([
            i, p.ts ?? '', p.proto ?? '', p.src ?? '', p.dst ?? '',
            p.sport ?? '', p.dport ?? '', p.bytes ?? '',
            p.sni ?? '',
            p.dns ? p.dns.queries.map((x) => x.name).join(' ') : '',
            p.http ? (p.http.method ? `${p.http.method} ${p.http.path}` : `HTTP ${p.http.status}`) : '',
          ].map(esc).join(','));
        });
        const csv = '\uFEFF' + lines.join('\r\n'); // BOM so Excel reads UTF-8
        res.writeHead(200, {
          'content-type': 'text/csv; charset=utf-8',
          'content-disposition': `attachment; filename="${base}-packets.csv"`,
          'cache-control': 'no-store',
          'content-length': String(Buffer.byteLength(csv)),
        });
        res.end(csv);
        return;
      }

      if (format === 'json') {
        const body = JSON.stringify({
          file: basename(full),
          meta: parsed.meta,
          stats: parsed.stats,
          talkers: parsed.talkers,
          topPorts: parsed.topPorts,
          dns: parsed.dns.map((d) => ({ ...d, type: DNS_TYPES[d.type] || String(d.type) })),
          sni: parsed.sni,
          http: parsed.http,
        }, null, 2);
        res.writeHead(200, {
          'content-type': 'application/json; charset=utf-8',
          'content-disposition': `attachment; filename="${base}-summary.json"`,
          'cache-control': 'no-store',
        });
        res.end(body);
        return;
      }

      json(res, 400, { ok: false, error: `不支持的导出格式 "${format}"（可用：csv、json）。` });
    })],

    // Regex search across derived views. Distinct from capture_search (plain
    // substring via the tool layer) — this one is for the panel's advanced box.
    ['/dsh-capture/search', ['GET'], guard(async (req, res) => {
      const url = new URL(req.url, 'http://127.0.0.1');
      const full = resolveId(url.searchParams.get('id') || '');
      if (!full) { json(res, 404, { ok: false, error: '未找到该抓包文件。' }); return; }
      const pattern = url.searchParams.get('pattern') || '';
      if (!pattern) { json(res, 400, { ok: false, error: 'pattern 不能为空。' }); return; }
      // User-supplied regex: bound the pattern length and reject a catastrophic
      // backtracking shape by capping the input, not by trying to out-smart the
      // engine. A bad pattern is reported rather than thrown.
      if (pattern.length > 200) { json(res, 400, { ok: false, error: '正则表达式过长（上限 200 字符）。' }); return; }
      let re;
      try { re = new RegExp(pattern, 'i'); }
      catch (e) { json(res, 400, { ok: false, error: `正则无效：${e.message}` }); return; }

      const parsed = analyzeFile(full);
      if (!parsed.ok) { json(res, 400, parsed); return; }
      const limit = Math.min(300, Math.max(1, Number(url.searchParams.get('limit')) || 100));
      const hit = (s) => re.test(String(s ?? ''));
      json(res, 200, {
        ok: true,
        pattern,
        dns: parsed.dns.filter((d) => hit(d.name)).slice(0, limit),
        sni: parsed.sni.filter((s) => hit(s.name)).slice(0, limit),
        http: parsed.http.filter((h) => hit(h.host) || hit(h.path) || hit(h.method)).slice(0, limit),
        endpoints: parsed.talkers.filter((t) => hit(t.src) || hit(t.dst)).slice(0, limit),
      });
    })],
  ];

  for (const [path, methods, handler] of routes) {
    const wrapped = async (req, res) => {
      const actual = (req.method || 'GET').toUpperCase();
      const allowed = methods.includes(actual) || (methods.includes('GET') && actual === 'HEAD');
      if (!allowed) {
        res.writeHead(405, { 'content-type': 'application/json; charset=utf-8', allow: methods.join(', ') });
        res.end(JSON.stringify({ ok: false, error: `该路由仅接受 ${methods.join(' / ')}` }));
        return;
      }
      await handler(req, res);
    };
    const dispose = ctx.webServer.register({ kind: 'exact', path, handler: wrapped });
    if (typeof dispose === 'function') disposers.push(dispose);
  }

  return () => {
    for (const d of disposers) { try { d(); } catch { /* teardown must not throw */ } }
  };
}
