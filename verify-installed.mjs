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
/** Capture directory, declared early: several checks below use it. */
const captureDir = path.join(HOME, 'dsh-capture');

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
const { probeEnvironment, backendLabel } = await import(asUrl(path.join(INST, 'lib', 'perm.js')));
const npcap = await import(asUrl(path.join(INST, 'lib', 'npcap.js')));
const toolsMod = await import(asUrl(path.join(INST, 'lib', 'tools.js')));
const pcapMod = await import(asUrl(path.join(INST, 'lib', 'pcap.js')));

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

// ---- 3) 后端选择与环境探测 ----
const env = await probeEnvironment();
check('probeEnvironment 返回结构完整',
  typeof env.canCapture === 'boolean' && Array.isArray(env.notes) && 'backend' in env,
  `backend=${env.backend} canCapture=${env.canCapture} needsElevation=${env.needsElevation}`);
check('backendLabel 可用', typeof backendLabel(env) === 'string', backendLabel(env));
check('平台判定为 Windows', env.isWindows === true, `platform=${env.platform}`);
check('能识别出可用的抓包后端（或说明为何不可用）',
  env.canCapture || env.notes.length > 0,
  env.canCapture ? `后端 ${env.backend}` : (env.notes[0] || ''));

// Npcap 若存在，接口分类必须正确（虚拟网卡不得被标为推荐）
if (env.npcap && env.npcap.available) {
  const real = env.interfaces.filter((i) => i.recommended);
  const virtAsReal = env.interfaces.filter((i) => i.recommended && (i.kind === 'virtual' || i.kind === 'loopback'));
  check('Npcap 接口分类正确（虚拟/环回不得标为推荐）', virtAsReal.length === 0,
    `${env.interfaces.length} 个网卡，推荐 ${real.length} 个，误标 ${virtAsReal.length} 个`);
  check('Npcap 能选出默认网卡', !!env.defaultInterface,
    env.defaultInterface ? `${env.defaultInterface.label} [${env.defaultInterface.kind}]` : '未选出');
  // 设备名必须是 \Device\NPF_{...} 形式，绝不用数字索引
  if (env.defaultInterface) {
    check('默认网卡使用设备名而非索引',
      env.defaultInterface.device.startsWith('\\Device\\NPF_'),
      env.defaultInterface.device);
  }
}

// ---- 3b) 结构化过滤器 → BPF 转换 ----
{
  const cases = [
    { in: [{ port: 443 }], want: 'port 443' },
    { in: [{ protocol: 'TCP' }], want: 'tcp' },
    { in: [{ ip: '1.1.1.1', port: 53 }], want: 'host 1.1.1.1 and port 53' },
    { in: [], want: '' },
  ];
  let bad = 0;
  for (const c of cases) {
    const got = toolsMod.filtersToBpf(c.in);
    if (c.want === '') { if (got !== '') bad++; }
    else if (!got.includes(c.want)) bad++;
  }
  check('filtersToBpf 转换正确', bad === 0, `${cases.length} 个用例，${bad} 个不符`);
  const multi = toolsMod.filtersToBpf([{ port: 80 }, { port: 443 }]);
  check('filtersToBpf 多条件用 or 连接', /or/.test(multi), multi);
}

// ---- 3c) 抓包成功判据：必须数 EPB 块，不能看文件大小 ----
{
  // 构造一个"合法但零包"的 pcapng（SHB+IDB+ISB），大小 > 24 字节
  const shbBody = Buffer.alloc(16);
  shbBody.writeUInt32LE(0x1a2b3c4d, 0);
  shbBody.writeUInt16LE(1, 4);
  const shb = Buffer.concat([Buffer.from([0x0a, 0x0d, 0x0d, 0x0a]), Buffer.from([0, 0, 0, 0]), shbBody]);
  const pad = (4 - (shb.length % 4)) % 4;
  const total = shb.length + pad + 4;
  const lenBuf = Buffer.alloc(4); lenBuf.writeUInt32LE(total, 0);
  const shbOut = Buffer.concat([shb, Buffer.alloc(pad), lenBuf]);
  shbOut.writeUInt32LE(total, 4);
  const emptyFile = path.join(captureDir, 'verify-empty.pcapng');
  fs.writeFileSync(emptyFile, shbOut);
  const st = npcap.countPacketBlocks(emptyFile);
  check('countPacketBlocks 识别零包文件',
    st.packets === 0 && st.bytes > 24,
    `bytes=${st.bytes} packets=${st.packets}（体积大但零包，必须判 0）`);
  fs.rmSync(emptyFile, { force: true });
}

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

// ---- 5) 端到端：合成 pcapng（TLS ClientHello + 跨包 HTTP）→ analyze ----

/** 构造一个 Ethernet/IPv4/TCP 帧。 */
function tcpFrame({ srcIp, dstIp, sport, dport, seq, payload }) {
  const tcp = Buffer.alloc(20 + payload.length);
  tcp.writeUInt16BE(sport, 0); tcp.writeUInt16BE(dport, 2);
  tcp.writeUInt32BE(seq >>> 0, 4);
  tcp[12] = 0x50; tcp[13] = 0x18;
  payload.copy(tcp, 20);
  const ip = Buffer.alloc(20 + tcp.length);
  ip[0] = 0x45; ip[9] = 6; ip.writeUInt16BE(ip.length, 2);
  ip.writeUInt32BE(ipToInt(srcIp), 12); ip.writeUInt32BE(ipToInt(dstIp), 16);
  tcp.copy(ip, 20);
  const frame = Buffer.alloc(14 + ip.length);
  frame.writeUInt16BE(0x0800, 12);
  ip.copy(frame, 14);
  return frame;
}

function ipToInt(ip) {
  const p = ip.split('.').map(Number);
  return ((p[0] << 24) >>> 0) + (p[1] << 16) + (p[2] << 8) + p[3];
}

/** 构造完整 pcapng：SHB + IDB(带 options) + N 个 EPB。 */
function buildPcapng(frames) {
  const shbBody = Buffer.alloc(16);
  shbBody.writeUInt32LE(0x1a2b3c4d, 0); shbBody.writeUInt16LE(1, 4); shbBody.writeUInt32LE(1, 12);
  const shb = Buffer.concat([Buffer.from([0x0a, 0x0d, 0x0d, 0x0a]), Buffer.from([0, 0, 0, 0]), shbBody]);
  const pad = (4 - (shb.length % 4)) % 4;
  const total = shb.length + pad + 4;
  const lenBuf = Buffer.alloc(4); lenBuf.writeUInt32LE(total, 0);
  const shbOut = Buffer.concat([shb, Buffer.alloc(pad), lenBuf]);
  shbOut.writeUInt32LE(total, 4);

  // IDB with a real option block, linkType = 1 (Ethernet)
  const optName = Buffer.concat([
    Buffer.from([0x02, 0x00]), Buffer.from([8, 0x00]), Buffer.from('verify12', 'latin1'),
  ]);
  const optEnd = Buffer.from([0x00, 0x00, 0x00, 0x00]);
  const idbBody = Buffer.concat([
    Buffer.from([0x01, 0x00]), Buffer.from([0x00, 0x00]),
    Buffer.from([0x00, 0x00, 0x04, 0x00]), optName, optEnd,
  ]);
  const idbTotal = 8 + idbBody.length + 4;
  const idbHdr = Buffer.alloc(8);
  idbHdr.writeUInt32LE(0x00000001, 0); idbHdr.writeUInt32LE(idbTotal, 4);
  const idbTail = Buffer.alloc(4); idbTail.writeUInt32LE(idbTotal, 0);
  const idb = Buffer.concat([idbHdr, idbBody, idbTail]);

  const parts = [shbOut, idb];
  let ts = 1700000000;
  for (const frame of frames) {
    const fpad = (4 - (frame.length % 4)) % 4;
    const ftotal = 32 + frame.length + fpad;
    const hdr = Buffer.alloc(28);
    hdr.writeUInt32LE(0x00000006, 0); hdr.writeUInt32LE(ftotal, 4);
    hdr.writeUInt32LE(Math.floor(ts * 1e6 / 4294967296), 12);
    hdr.writeUInt32LE(Math.floor(ts * 1e6) % 4294967296, 16);
    hdr.writeUInt32LE(frame.length, 20); hdr.writeUInt32LE(frame.length, 24);
    const flen = Buffer.alloc(4); flen.writeUInt32LE(ftotal, 0);
    parts.push(Buffer.concat([hdr, frame, Buffer.alloc(fpad), flen]));
    ts += 0.001;
  }
  return Buffer.concat(parts);
}

/** 构造 TLS ClientHello（带 SNI）。 */
function clientHelloRec(sniHost) {
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
  return Buffer.concat([Buffer.from([0x16, 0x03, 0x01, (hs.length >> 8) & 0xff, hs.length & 0xff]), hs]);
}

/** 构造端到端测试用抓包：TLS 握手 + 一个跨包 HTTP 事务。 */
function buildFixtures(sniHost) {
  const rec = clientHelloRec(sniHost);
  const reqBody = '{"verify_target":1}';
  const resBody = '{"created":true}';
  const reqText = `POST /api/v1/verify HTTP/1.1\r\nHost: ${sniHost}\r\nContent-Type: application/json\r\nContent-Length: ${Buffer.byteLength(reqBody, 'utf8')}\r\n\r\n${reqBody}`;
  const resText = `HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: ${Buffer.byteLength(resBody, 'utf8')}\r\n\r\n${resBody}`;
  const reqB = Buffer.from(reqText, 'utf8');
  const resB = Buffer.from(resText, 'utf8');
  const cut = 40;
  return [
    tcpFrame({ srcIp: '10.0.0.5', dstIp: '10.0.0.6', sport: 51000, dport: 443, seq: 1, payload: rec }),
    // HTTP request split across two packets — only reassembly can read it whole.
    tcpFrame({ srcIp: '10.0.0.5', dstIp: '10.0.0.7', sport: 51001, dport: 80, seq: 1000, payload: reqB.subarray(0, cut) }),
    tcpFrame({ srcIp: '10.0.0.5', dstIp: '10.0.0.7', sport: 51001, dport: 80, seq: 1000 + cut, payload: reqB.subarray(cut) }),
    tcpFrame({ srcIp: '10.0.0.7', dstIp: '10.0.0.5', sport: 80, dport: 51001, seq: 5000, payload: resB }),
  ];
}

fs.mkdirSync(captureDir, { recursive: true });
const testFile = path.join(captureDir, 'verify-e2e.pcapng');
fs.writeFileSync(testFile, buildPcapng(buildFixtures('example.org')));
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

  // --- step C: reassembly / HTTP transactions / TLS details / time ---
  check('analyze 返回重组统计（reassembly）',
    an.code === 200 && an.body.reassembly && typeof an.body.reassembly.streams === 'number',
    `reassembly=${JSON.stringify(an.body.reassembly)}`);
  check('analyze 返回 packets 的 ISO 时间',
    an.code === 200 && /^\d{4}-\d{2}-\d{2}T/.test(String(an.body.meta?.firstTime || '')),
    `firstTime=${an.body.meta?.firstTime}`);
  // --- packet-level browsing ---
  const pk = await callRoute('/dsh-capture/packets', `/dsh-capture/packets?id=${hit.id}&limit=10`, 'GET');
  check('packets 路由返回包列表（含分页字段）',
    pk.code === 200 && Array.isArray(pk.body.rows) && typeof pk.body.total === 'number',
    `code=${pk.code} total=${pk.body?.total} rows=${pk.body?.rows?.length}`);
  check('packets 行带 time（ISO）与 payloadBytes',
    pk.code === 200 && (pk.body.rows || []).every((r) => r.time == null || /^\d{4}-\d{2}-\d{2}T/.test(String(r.time)))
      && (pk.body.rows || []).every((r) => typeof r.payloadBytes === 'number'),
    `sample=${JSON.stringify((pk.body.rows || [])[0] ?? null)}`);
  check('flows 暴露重组后的流（streams）与 TLS 握手（tlsHandshakes）',
    fl.code === 200 && Array.isArray(fl.body.streams) && Array.isArray(fl.body.tlsHandshakes),
    `streams=${fl.body?.streams?.length} tls=${fl.body?.tlsHandshakes?.length}`);
  const srch = await callRoute('/dsh-capture/search', `/dsh-capture/search?id=${hit.id}&pattern=example`, 'GET');
  check('search 响应包含 bodies / streams 字段',
    srch.code === 200 && Array.isArray(srch.body.bodies) && Array.isArray(srch.body.streams),
    `code=${srch.code} bodies=${srch.body?.bodies?.length} streams=${srch.body?.streams?.length}`);

  // 跨包 HTTP：请求被切成两个包，只有重组后才能读出完整方法与路径
  const tx = an.body.transactions || [];
  const post = tx.find((t) => t.method === 'POST');
  check('analyze 重组出跨包 HTTP 请求（方法/路径/Host）',
    !!post && post.path === '/api/v1/verify' && post.host === 'example.org',
    `transactions=${tx.length} post=${JSON.stringify(post ? { m: post.method, p: post.path, h: post.host } : null)}`);
  check('analyze 报文体重组完整（请求体 + 响应体）',
    !!post && post.requestBody === '{"verify_target":1}' && String(post.responseBody || '').startsWith('{"created":true}'),
    `reqBody=${JSON.stringify(post?.requestBody)} resBody=${JSON.stringify(post?.responseBody)}`);
  check('analyze 读出响应状态码与 Content-Length',
    !!post && post.status === 201 && post.responseBytes === Buffer.byteLength('{"created":true}', 'utf8'),
    `status=${post?.status} bytes=${post?.responseBytes}`);
  check('analyze 读出 TLS 握手详情（协议版本）',
    (an.body.tls || []).some((t) => t.clientVersionName === 'TLS 1.2' && (t.cipherSuites || []).length > 0),
    `tls=${JSON.stringify((an.body.tls || []).map((t) => t.clientVersionName))}`);

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
  check('export 路由输出 CSV（带表头、时间列与 BOM）',
    csv.code === 200 && typeof csv.body === 'string'
      && csv.body.startsWith('\uFEFF')
      && csv.body.includes('index,time,ts,proto,src,dst,sport,dport')
      && csv.body.includes(',tls,')
      && /^\uFEFF?index,time,ts,proto/.test(csv.body.replace('﻿', '')),
    `code=${csv.code} head=${String(csv.body).slice(0, 48).replace(/\n/g, '\\n')}`);

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

// ---- 7) 类型声明与 agent 工具注册面 ----
{
  const typesPath = path.join(INST, 'types', 'index.d.ts');
  check('随包提供类型声明 types/index.d.ts', fs.existsSync(typesPath),
    fs.existsSync(typesPath) ? `${(fs.statSync(typesPath).size / 1024).toFixed(1)} KB` : '缺失');
  if (fs.existsSync(typesPath)) {
    const dts = fs.readFileSync(typesPath, 'utf8');
    const needed = ['CaptureEntry', 'InterfaceEntry', 'AnalyzeResult', 'PacketRow', 'HttpTransaction', 'TlsInfo', 'ReassemblyStats', 'CaptureConfig'];
    const missing = needed.filter((n) => !new RegExp(`interface ${n}\\b`).test(dts));
    check('类型声明覆盖关键契约（8 个 interface）', missing.length === 0,
      missing.length ? `缺 ${missing.join(', ')}` : needed.join(', '));
  }
  const pkgJson = JSON.parse(fs.readFileSync(path.join(INST, 'package.json'), 'utf8'));
  check('package.json 声明 types 字段与 types 导出',
    pkgJson.types === './types/index.d.ts' && pkgJson.exports?.['./types'] === './types/index.d.ts',
    `types=${pkgJson.types} exports=${pkgJson.exports?.['./types']}`);

  // agent 工具注册面：源码里必须声明全部 8 个工具
  const idxSrc = fs.readFileSync(path.join(INST, 'lib', 'index.js'), 'utf8');
  const want = ['capture_probe', 'capture_list', 'capture_start', 'capture_stop',
    'capture_analyze', 'capture_search', 'capture_status', 'capture_export'];
  const missingTools = want.filter((w) => !idxSrc.includes(`name: '${w}'`));
  check(`agent 工具齐备（${want.length} 个）`, missingTools.length === 0,
    missingTools.length ? `缺 ${missingTools.join(', ')}` : want.join(', '));

  check('接入 ctx.logger 且可降级（无 logger 时不抛）',
    /makeLogger/.test(idxSrc) && /noop/.test(idxSrc),
    'makeLogger + noop 回退');
}

// ---- 8) 源码级语法/契约快检（防回归） ----
{
  const pcapSrc = fs.readFileSync(path.join(INST, 'lib', 'pcap.js'), 'utf8');
  check('pcap.js 含流重组与 TLS 详情实现',
    /function buildStreams/.test(pcapSrc) && /function tlsClientHello/.test(pcapSrc)
      && /function tlsServerHello/.test(pcapSrc) && /function reassembleDirection/.test(pcapSrc),
    'buildStreams / tlsClientHello / tlsServerHello / reassembleDirection');
  check('pcap.js 读取 if_tsresol（时间戳分辨率）',
    /function readTsResolution/.test(pcapSrc) && /if_tsresol|tsResolutions/.test(pcapSrc),
    'readTsResolution + tsResolutions');

  check('pcap.js 提供流式解析入口',
    /export async function parseCaptureStream/.test(pcapSrc) && /class ChunkReader/.test(pcapSrc),
    'parseCaptureStream + ChunkReader');

  // 路由与工具层必须真的用上流式（否则大文件仍撞整读上限）
  const routesSrc2 = fs.readFileSync(path.join(INST, 'lib', 'routes.js'), 'utf8');
  check('路由层接入流式（shouldStream + parseCaptureStream）',
    /shouldStream/.test(routesSrc2) && /parseCaptureStream/.test(routesSrc2),
    'analyzeFile / packets / export 均按阈值分流');
  const idxSrc2 = fs.readFileSync(path.join(INST, 'lib', 'index.js'), 'utf8');
  check('工具层接入流式（parseMaybeStream）',
    /parseMaybeStream/.test(idxSrc2) && /STREAM_THRESHOLD_BYTES/.test(idxSrc2),
    'analyzeBounded / exportCapture 按阈值分流');
}

say('');
const passed = lines.filter((l) => l.startsWith('PASS')).length;
say(failures === 0 ? `全部通过（${passed} 项）` : `${passed} 项通过，${failures} 项失败`);

const logPath = path.join(process.cwd(), 'verify-installed.log');
fs.writeFileSync(logPath, lines.join('\n'), 'utf8');
say('LOG=' + logPath);
process.exit(failures === 0 ? 0 : 1);
