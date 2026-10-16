/**
 * 装机后验证：不依赖 DSH 重启，直接用装好的模块跑一遍关键路径。
 *   1) lib/index.js 能 import 且导出 apply
 *   2) lib/routes.js 用假 ctx.webServer 能注册全部路由（路径不重复）
 *   3) lib/pktmon.js 的探测在本环境返回完整结构
 *   4) 路由 handler 真能被调用并回 JSON（status / sessions / analyze）
 *   5) 端到端：写一个合成 pcapng，走 analyze 路由拿到摘要
 *   6) dispose 后注册清空
 *
 * 路径自适应：默认查 DSH_HOME 下的 desktop profile，可用 --profile=<路径> 覆盖。
 *
 * 用法: node verify-installed.mjs [--profile=<profile目录>]
 */
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const fromArg = process.argv.find((a) => a.startsWith('--profile='));
const PROFILE = fromArg
  ? fromArg.slice('--profile='.length)
  : (process.env.DSH_PROFILE_DIR
    || path.join(process.env.DSH_HOME || path.join(process.env.USERPROFILE || '', '.dsh'), 'profiles', 'desktop'));
const INST = path.join(PROFILE, 'node_modules', 'dsh-capture');
const HOME = process.env.DSH_HOME || path.join(process.env.USERPROFILE || '', '.dsh');

/** Windows 绝对路径必须转成 file:// URL 才能被 ESM loader 接受。 */
const asUrl = (p) => pathToFileURL(p).href;

const lines = [];
const say = (s) => { lines.push(s); console.log(s); };
let failures = 0;
const check = (name, ok, detail = '') => {
  say(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? '  — ' + detail : ''}`);
  if (!ok) failures++;
};

if (!fs.existsSync(path.join(INST, 'lib', 'index.js'))) {
  console.error(`未找到已安装的插件：${INST}\n先运行 install-dsh-capture.mjs。`);
  process.exit(1);
}
say(`PROFILE = ${PROFILE}`);
say(`INST    = ${INST}`);
say('');

// ---- 1) 入口模块 ----
let mod;
try {
  mod = await import(asUrl(path.join(INST, 'lib', 'index.js')));
  check('lib/index.js 可导入并导出 apply', typeof mod.apply === 'function', `name=${mod.name}`);
} catch (e) {
  check('lib/index.js 可导入并导出 apply', false, String(e.message));
  say('  后续检查跳过');
  fs.writeFileSync(path.join(PROFILE, '..', '..', 'verify-installed.log'), lines.join('\n'), 'utf8');
  process.exit(1);
}

const { mountRoutes } = await import(asUrl(path.join(INST, 'lib', 'routes.js')));
const { probeBackend } = await import(asUrl(path.join(INST, 'lib', 'pktmon.js')));

// ---- 2) 假 webServer，抓取注册的路由 ----
const registered = new Map();
const fakeCtx = {
  webServer: {
    register(route) {
      // 复刻宿主契约：同 path 重复注册会 throw
      if (registered.has(route.path)) throw new Error(`duplicate route "${route.path}"`);
      registered.set(route.path, route);
      return () => registered.delete(route.path);
    },
  },
};

let disposeRoutes;
try {
  disposeRoutes = mountRoutes(fakeCtx, {});
  check('mountRoutes 注册成功（无重复路径）', registered.size > 0, `${registered.size} 条路由`);
  for (const p of registered.keys()) say(`        ${p}`);
} catch (e) {
  check('mountRoutes 注册成功（无重复路径）', false, String(e.message));
}

// ---- 3) 后端探测 ----
const probe = await probeBackend();
check('probeBackend 返回结构完整',
  typeof probe.pktmonExists === 'boolean' && Array.isArray(probe.notes),
  `pktmonExists=${probe.pktmonExists} canRun=${probe.canRun} needsElevation=${probe.needsElevation}`);
check('能识别出权限状态（可用 / 需提权 / 无组件）',
  probe.canRun || probe.needsElevation || !probe.pktmonExists,
  (probe.notes && probe.notes[0]) || '');

// ---- 4) 真正调用路由 handler ----
function fakeExchange(url, method = 'GET', body = null) {
  const res = {
    statusCode: 0, headers: null, body: '',
    writeHead(code, headers) { this.statusCode = code; this.headers = headers; },
    end(text) { this.body = text || ''; },
  };
  const req = {
    url, method,
    on(event, cb) {
      if (event === 'data' && body !== null) cb(Buffer.from(JSON.stringify(body)));
      if (event === 'end') cb();
    },
    destroy() {},
  };
  return { req, res };
}

async function callRoute(routePath, url, method, body) {
  const route = registered.get(routePath);
  if (!route) throw new Error(`路由未注册: ${routePath}`);
  const { req, res } = fakeExchange(url, method, body);
  await route.handler(req, res);
  const raw = res.body;
  const ctype = (res.headers && (res.headers['content-type'] || res.headers['Content-Type'])) || '';
  // Export routes answer with text/csv, octet-stream, or a standalone JSON
  // *document* (not the {ok:...} API envelope). Keep those as raw text so the
  // assertion inspects the exported payload itself.
  const isDocument = /text\/csv|application\/octet-stream/.test(ctype)
    || (res.headers && res.headers['content-disposition']);
  if (isDocument) {
    return { code: res.statusCode, body: raw, contentType: ctype };
  }
  let parsed;
  try { parsed = JSON.parse(raw); } catch { parsed = raw; }
  return { code: res.statusCode, body: parsed, contentType: ctype };
}

try {
  const s = await callRoute('/dsh-capture/status', '/dsh-capture/status', 'GET');
  check('GET /status 返回 200 且含 backend', s.code === 200 && !!s.body.backend,
    `code=${s.code} pktmonExists=${s.body?.backend?.pktmonExists ?? '?'}`);
} catch (e) { check('GET /status', false, String(e.message)); }

try {
  const s = await callRoute('/dsh-capture/sessions', '/dsh-capture/sessions', 'GET');
  check('GET /sessions 返回列表', s.code === 200 && Array.isArray(s.body.captures),
    `code=${s.code} captures=${s.body?.captures?.length ?? '?'}`);
} catch (e) { check('GET /sessions', false, String(e.message)); }

try {
  const wrong = await callRoute('/dsh-capture/start', '/dsh-capture/start', 'GET');
  check('方法校验：GET /start 被拒 405', wrong.code === 405, `code=${wrong.code}`);
} catch (e) { check('方法校验：GET /start 被拒 405', false, String(e.message)); }

try {
  const bad = await callRoute('/dsh-capture/analyze', '/dsh-capture/analyze?id=deadbeefdeadbeef', 'GET');
  check('无效 id 返回 404', bad.code === 404, `code=${bad.code}`);
} catch (e) { check('无效 id 返回 404', false, String(e.message)); }

try {
  const trav = await callRoute('/dsh-capture/analyze', '/dsh-capture/analyze?id=../../../../etc/passwd', 'GET');
  check('路径穿越 id 被拒', trav.code === 404, `code=${trav.code}`);
} catch (e) { check('路径穿越 id 被拒', false, String(e.message)); }

// ---- 5) 端到端：合成 pcapng（TLS ClientHello 带 SNI）→ analyze ----
function buildPcapngWithOneHttps(sniHost) {
  const host = Buffer.from(sniHost, 'latin1');
  const sniExt = Buffer.concat([
    Buffer.from([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
    Buffer.from([(host.length >> 8) & 0xff, host.length & 0xff]), host,
  ]);
  sniExt.writeUInt16BE(sniExt.length - 4, 2);
  sniExt.writeUInt16BE(sniExt.length - 7, 4);
  const body = Buffer.concat([
    Buffer.from([0x03, 0x03]), Buffer.alloc(32, 0x22), Buffer.from([0x00]),
    Buffer.from([0x00, 0x02, 0x13, 0x01]), Buffer.from([0x01, 0x00]),
    Buffer.from([(sniExt.length >> 8) & 0xff, sniExt.length & 0xff]), sniExt,
  ]);
  const hs = Buffer.concat([Buffer.from([0x01]), Buffer.from([(body.length >> 8) & 0xff, body.length & 0xff, 0x00]), body]);
  const rec = Buffer.concat([Buffer.from([0x16, 0x03, 0x01, (hs.length >> 8) & 0xff, hs.length & 0xff]), hs]);
  const tcp = Buffer.alloc(20 + rec.length);
  tcp.writeUInt16BE(51000, 0); tcp.writeUInt16BE(443, 2);
  tcp[12] = 0x50; tcp[13] = 0x18;
  rec.copy(tcp, 20);
  const ip = Buffer.alloc(20 + tcp.length);
  ip[0] = 0x45; ip[9] = 6; ip.writeUInt16BE(ip.length, 2);
  ip.writeUInt32BE(0x0a000005, 12); ip.writeUInt32BE(0x0a000006, 16);
  tcp.copy(ip, 20);
  const frame = Buffer.alloc(14 + ip.length);
  frame.writeUInt16BE(0x0800, 12);
  ip.copy(frame, 14);

  const shbBody = Buffer.alloc(16);
  shbBody.writeUInt32LE(0x1a2b3c4d, 0); shbBody.writeUInt16LE(1, 4); shbBody.writeUInt32LE(1, 12);
  const shb = Buffer.concat([Buffer.from([0x0a, 0x0d, 0x0d, 0x0a]), Buffer.from([0, 0, 0, 0]), shbBody]);
  const pad = (4 - (shb.length % 4)) % 4;
  const total = shb.length + pad + 4;
  const lenBuf = Buffer.alloc(4); lenBuf.writeUInt32LE(total, 0);
  const shbOut = Buffer.concat([shb, Buffer.alloc(pad), lenBuf]);
  shbOut.writeUInt32LE(total, 4);

  const fpad = (4 - (frame.length % 4)) % 4;
  const ftotal = 32 + frame.length + fpad;
  const hdr = Buffer.alloc(28);
  hdr.writeUInt32LE(0x00000006, 0); hdr.writeUInt32LE(ftotal, 4);
  hdr.writeUInt32LE(0x0000ffff, 12); hdr.writeUInt32LE(1, 16);
  hdr.writeUInt32LE(frame.length, 20); hdr.writeUInt32LE(frame.length, 24);
  const flen = Buffer.alloc(4); flen.writeUInt32LE(ftotal, 0);
  return Buffer.concat([shbOut, hdr, frame, Buffer.alloc(fpad), flen]);
}

const captureDir = path.join(HOME, 'dsh-capture');
fs.mkdirSync(captureDir, { recursive: true });
const testFile = path.join(captureDir, 'verify-e2e.pcapng');
fs.writeFileSync(testFile, buildPcapngWithOneHttps('example.org'));
say(`       写入测试抓包 ${testFile} (${fs.statSync(testFile).size} B)`);

const sess = await callRoute('/dsh-capture/sessions', '/dsh-capture/sessions', 'GET');
const hit = (sess.body.captures || []).find((c) => c.name === 'verify-e2e.pcapng');
check('测试抓包出现在 sessions 列表', !!hit, hit ? `id=${hit.id}` : '未找到');

if (hit) {
  const an = await callRoute('/dsh-capture/analyze', `/dsh-capture/analyze?id=${hit.id}`, 'GET');
  check('analyze 路由解析出 SNI', an.code === 200 && (an.body.sni || []).some((s) => s.name === 'example.org'),
    `code=${an.code} sni=${JSON.stringify((an.body.sni || []).map((s) => s.name))} packets=${an.body.meta?.packets}`);
  const fl = await callRoute('/dsh-capture/flows', `/dsh-capture/flows?id=${hit.id}&q=example`, 'GET');
  check('flows 路由支持关键词过滤', fl.code === 200 && (fl.body.sni || []).length > 0,
    `code=${fl.code} sni=${(fl.body.sni || []).length}`);

  // --- packet-level browsing ---
  const pk = await callRoute('/dsh-capture/packets', `/dsh-capture/packets?id=${hit.id}&limit=10`, 'GET');
  check('packets 路由返回包列表（含分页字段）',
    pk.code === 200 && Array.isArray(pk.body.rows) && typeof pk.body.total === 'number',
    `code=${pk.code} total=${pk.body?.total} rows=${pk.body?.rows?.length}`);
  const pkProto = await callRoute('/dsh-capture/packets', `/dsh-capture/packets?id=${hit.id}&proto=TCP`, 'GET');
  check('packets 路由支持协议过滤',
    pkProto.code === 200 && (pkProto.body.rows || []).every((r) => r.proto === 'TCP'),
    `code=${pkProto.code} rows=${pkProto.body?.rows?.length}`);
  const pkPort = await callRoute('/dsh-capture/packets', `/dsh-capture/packets?id=${hit.id}&port=443`, 'GET');
  check('packets 路由支持端口过滤',
    pkPort.code === 200 && (pkPort.body.rows || []).every((r) => r.sport === 443 || r.dport === 443),
    `code=${pkPort.code} rows=${pkPort.body?.rows?.length}`);

  // --- CSV export ---
  const csv = await callRoute('/dsh-capture/export', `/dsh-capture/export?id=${hit.id}&format=csv`, 'GET');
  check('export 路由输出 CSV（带表头与 BOM）',
    csv.code === 200 && typeof csv.body === 'string' && csv.body.includes('index,ts,proto'),
    `code=${csv.code} head=${String(csv.body).slice(0, 40).replace(/\n/g, '\\n')}`);

  // --- JSON export ---
  const js = await callRoute('/dsh-capture/export', `/dsh-capture/export?id=${hit.id}&format=json`, 'GET');
  check('export 路由输出 JSON 摘要',
    js.code === 200 && typeof js.body === 'string' && js.body.includes('"meta"'),
    `code=${js.code} len=${String(js.body).length}`);

  // --- regex search ---
  const se = await callRoute('/dsh-capture/search', `/dsh-capture/search?id=${hit.id}&pattern=^example`, 'GET');
  check('search 路由支持正则',
    se.code === 200 && (se.body.sni || []).some((s) => s.name === 'example.org'),
    `code=${se.code} sni=${JSON.stringify((se.body.sni || []).map((s) => s.name))}`);
  const seBad = await callRoute('/dsh-capture/search', `/dsh-capture/search?id=${hit.id}&pattern=[`, 'GET');
  check('search 路由对无效正则返回 400（不抛 500）', seBad.code === 400, `code=${seBad.code}`);

  const del = await callRoute('/dsh-capture/delete', '/dsh-capture/delete', 'POST', { id: hit.id });
  check('delete 路由移除测试文件', del.code === 200 && !fs.existsSync(testFile), `code=${del.code}`);
}

// ---- 6) 卸载必须干净 ----
try {
  const before = registered.size;
  disposeRoutes();
  check('disposeRoutes 清空注册', registered.size === 0, `before=${before} after=${registered.size}`);
} catch (e) { check('disposeRoutes 清空注册', false, String(e.message)); }

say('');
const passed = lines.filter((l) => l.startsWith('PASS')).length;
say(failures === 0 ? `全部通过（${passed} 项）` : `${passed} 项通过，${failures} 项失败`);

const logPath = path.join(process.cwd(), 'verify-installed.log');
fs.writeFileSync(logPath, lines.join('\n'), 'utf8');
say('LOG=' + logPath);
process.exit(failures === 0 ? 0 : 1);
