/**
 * HTTP 路由契约测试（源码内，不依赖已安装 profile）。
 *
 * 为什么需要：verify-installed.mjs 是"装机回归"，会真的枚举本机网卡、
 * 依赖 profiles/desktop 存在。CI 上跑不了，也不该跑。这个文件只验证
 * **路由契约本身**：注册、方法校验、参数校验、错误码、输出形状 ——
 * 全用假 host context，不碰网络、不碰抓包。
 *
 * 运行: node dsh-capture/test/routes.test.mjs
 */
import assert from 'node:assert/strict';
import { mkdirSync, writeFileSync, rmSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';
import { createHash } from 'node:crypto';
import { mountRoutes } from '../lib/routes.js';

/* ------------------------- 假 host context ------------------------- */

const registered = new Map();
const fakeCtx = {
  webServer: {
    register({ path, handler }) {
      registered.set(path, { path, handler });
      return () => registered.delete(path);
    },
  },
};

/* ------------------------- 假 req / res ------------------------- */

function fakeExchange(url, method = 'GET', body = null) {
  const res = {
    statusCode: 0, headers: null, body: '',
    writeHead(code, headers) { this.statusCode = code; this.headers = headers; },
    end(text) { this.body = text == null ? '' : String(text); },
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

async function call(routePath, opts = {}) {
  const route = registered.get(routePath);
  assert.ok(route, `路由未注册: ${routePath}`);
  const { req, res } = fakeExchange(opts.url || routePath, opts.method || 'GET', opts.body ?? null);
  await route.handler(req, res);
  const ctype = (res.headers && (res.headers['content-type'] || res.headers['Content-Type'])) || '';
  // Export routes answer with a downloadable document (content-disposition),
  // not a JSON envelope — hand those back as raw text.
  const isDocument = !!(res.headers && res.headers['content-disposition'])
    || /text\/csv|application\/octet-stream/.test(ctype);
  if (!isDocument && (/json/.test(ctype) || (!ctype && /^[[{]/.test(res.body)))) {
    try { return { code: res.statusCode, headers: res.headers, body: JSON.parse(res.body) }; }
    catch { return { code: res.statusCode, headers: res.headers, body: res.body }; }
  }
  return { code: res.statusCode, headers: res.headers, body: res.body };
}

/* ------------------------- 测试用抓包文件 ------------------------- */

const capDir = join(process.env.DSH_HOME ?? join(homedir(), '.dsh'), 'dsh-capture');
mkdirSync(capDir, { recursive: true });

function ipToInt(ip) {
  const p = ip.split('.').map(Number);
  return ((p[0] << 24) >>> 0) + (p[1] << 16) + (p[2] << 8) + p[3];
}

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
  const eth = Buffer.alloc(14 + ip.length);
  eth.writeUInt16BE(0x0800, 12);
  ip.copy(eth, 14);
  return eth;
}

function buildPcapng(frames) {
  const shbBody = Buffer.alloc(16);
  shbBody.writeUInt32LE(0x1a2b3c4d, 0);
  shbBody.writeUInt16LE(1, 4);
  const shb = Buffer.concat([Buffer.from([0x0a, 0x0d, 0x0d, 0x0a]), Buffer.from([0, 0, 0, 0]), shbBody]);
  const pad = (4 - (shb.length % 4)) % 4;
  const total = shb.length + pad + 4;
  const lenBuf = Buffer.alloc(4); lenBuf.writeUInt32LE(total, 0);
  const shbOut = Buffer.concat([shb, Buffer.alloc(pad), lenBuf]);
  shbOut.writeUInt32LE(total, 4);

  // IDB with if_tsresol = 9 (nanoseconds), as dumpcap writes it.
  const optRes = Buffer.concat([Buffer.from([0x09, 0x00, 0x01, 0x00, 0x09]), Buffer.alloc(3)]);
  const optEnd = Buffer.from([0x00, 0x00, 0x00, 0x00]);
  const idbBody = Buffer.concat([
    Buffer.from([0x01, 0x00]), Buffer.from([0x00, 0x00]),
    Buffer.from([0x00, 0x00, 0x04, 0x00]), optRes, optEnd,
  ]);
  const idbTotal = 8 + idbBody.length + 4;
  const idbHdr = Buffer.alloc(8);
  idbHdr.writeUInt32LE(0x00000001, 0); idbHdr.writeUInt32LE(idbTotal, 4);
  const idbTail = Buffer.alloc(4); idbTail.writeUInt32LE(idbTotal, 0);
  const parts = [shbOut, Buffer.concat([idbHdr, idbBody, idbTail])];

  let ts = 1700000000;
  for (const f of frames) {
    const fpad = (4 - (f.length % 4)) % 4;
    const ftotal = 32 + f.length + fpad;
    const hdr = Buffer.alloc(28);
    hdr.writeUInt32LE(0x00000006, 0);
    hdr.writeUInt32LE(ftotal, 4);
    const ticks = Math.round(ts * 1e9);
    hdr.writeUInt32LE(Math.floor(ticks / 4294967296), 12);
    hdr.writeUInt32LE(ticks % 4294967296, 16);
    hdr.writeUInt32LE(f.length, 20);
    hdr.writeUInt32LE(f.length, 24);
    const flen = Buffer.alloc(4); flen.writeUInt32LE(ftotal, 0);
    parts.push(Buffer.concat([hdr, f, Buffer.alloc(fpad), flen]));
    ts += 0.001;
  }
  return Buffer.concat(parts);
}

const MARK = 'route-test-marker';
const tmpName = `routes-test-${Date.now()}.pcapng`;
const tmpPath = join(capDir, tmpName);
const reqBody = JSON.stringify({ marker: MARK });
const reqText = `POST /route/test HTTP/1.1\r\nHost: routes.test\r\nContent-Type: application/json\r\nContent-Length: ${Buffer.byteLength(reqBody)}\r\n\r\n${reqBody}`;
const resText = 'HTTP/1.1 202 Accepted\r\nContent-Type: application/json\r\nContent-Length: 15\r\n\r\n{"routes":"ok"}';
const reqB = Buffer.from(reqText, 'utf8');
const resB = Buffer.from(resText, 'utf8');
const cut = 35;
writeFileSync(tmpPath, buildPcapng([
  tcpFrame({ srcIp: '10.9.0.1', dstIp: '10.9.0.2', sport: 40001, dport: 80, seq: 1, payload: reqB.subarray(0, cut) }),
  tcpFrame({ srcIp: '10.9.0.1', dstIp: '10.9.0.2', sport: 40001, dport: 80, seq: 1 + cut, payload: reqB.subarray(cut) }),
  tcpFrame({ srcIp: '10.9.0.2', dstIp: '10.9.0.1', sport: 80, dport: 40001, seq: 9000, payload: resB }),
]), 'binary');

// The id is the sha256 of the file name, as routes.js computes it.
const id = createHash('sha256').update(tmpName).digest('hex').slice(0, 16);

/* ------------------------------ 执行 ------------------------------ */

const dispose = mountRoutes(fakeCtx, { reassemble: true });
const checks = [];
const check = (name, cond, detail = '') => {
  checks.push({ name, ok: !!cond, detail });
  console.log(`  [${cond ? 'PASS' : 'FAIL'}] ${name}${detail ? '  — ' + detail : ''}`);
};

try {
  check('注册了 13 条路由', registered.size === 13, `实际 ${registered.size}`);

  const status = await call('/dsh-capture/status');
  check('status 返回 ok', status.code === 200 && status.body.ok === true, `code=${status.code}`);

  const list = await call('/dsh-capture/sessions');
  check('sessions 返回列表', list.code === 200 && Array.isArray(list.body.captures),
    `code=${list.code} n=${list.body?.captures?.length}`);
  const hit = (list.body.captures || []).find((c) => c.name === tmpName);
  check('新建的抓包出现在列表里', !!hit, hit ? `id=${hit.id}` : '未找到');

  // 方法校验：POST-only 路由用 GET 必须 405
  const badMethod = await call('/dsh-capture/start', { method: 'GET' });
  check('GET /start 被拒 405', badMethod.code === 405, `code=${badMethod.code}`);

  // 参数校验：不存在的 id → 404
  const notFound = await call('/dsh-capture/analyze', { url: '/dsh-capture/analyze?id=deadbeefdeadbeef' });
  check('无效 id 返回 404', notFound.code === 404, `code=${notFound.code}`);

  // 路径穿越防御
  const trav = await call('/dsh-capture/analyze', { url: '/dsh-capture/analyze?id=../../../etc/passwd' });
  check('路径穿越 id 被拒 404', trav.code === 404, `code=${trav.code}`);

  const an = await call('/dsh-capture/analyze', { url: `/dsh-capture/analyze?id=${id}` });
  check('analyze 返回 meta/reassembly/transactions',
    an.code === 200 && an.body.meta && an.body.reassembly && Array.isArray(an.body.transactions),
    `code=${an.code} packets=${an.body?.meta?.packets} tx=${an.body?.transactions?.length}`);
  check('analyze 时间戳为 ISO 且年份正确',
    /^2023-11-14T/.test(String(an.body.meta?.firstTime || '')),
    `firstTime=${an.body.meta?.firstTime}`);

  const tx = (an.body.transactions || [])[0];
  check('跨包 HTTP 请求被重组（方法/路径/Host）',
    !!tx && tx.method === 'POST' && tx.path === '/route/test' && tx.host === 'routes.test',
    tx ? `${tx.method} ${tx.host}${tx.path}` : '无事务');
  check('请求体被重组完整', tx?.requestBody === reqBody, JSON.stringify(tx?.requestBody));
  check('响应状态码与体被读出', tx?.status === 202 && String(tx?.responseBody || '').startsWith('{"routes":"ok"'),
    `status=${tx?.status} body=${JSON.stringify(tx?.responseBody)}`);

  const pk = await call('/dsh-capture/packets', { url: `/dsh-capture/packets?id=${id}&limit=10` });
  check('packets 分页返回行', pk.code === 200 && Array.isArray(pk.body.rows) && pk.body.total === 3,
    `total=${pk.body?.total} rows=${pk.body?.rows?.length}`);
  check('packets 行带 time/ts/payloadBytes',
    (pk.body.rows || []).every((r) => /^\d{4}-\d{2}-\d{2}T/.test(String(r.time)) && typeof r.payloadBytes === 'number'),
    JSON.stringify((pk.body.rows || [])[0] ?? null).slice(0, 140));

  const pkProto = await call('/dsh-capture/packets', { url: `/dsh-capture/packets?id=${id}&proto=UDP` });
  check('protocol 过滤生效（UDP 无行）', pkProto.code === 200 && (pkProto.body.rows || []).length === 0,
    `rows=${pkProto.body?.rows?.length}`);

  const fl = await call('/dsh-capture/flows', { url: `/dsh-capture/flows?id=${id}&q=routes` });
  check('flows 支持 q 过滤并带 streams/tlsHandshakes',
    fl.code === 200 && Array.isArray(fl.body.streams) && Array.isArray(fl.body.tlsHandshakes),
    `streams=${fl.body?.streams?.length} tls=${fl.body?.tlsHandshakes?.length}`);

  const csv = await call('/dsh-capture/export', { url: `/dsh-capture/export?id=${id}&format=csv` });
  check('CSV 导出带 BOM 与 time/tls 列',
    csv.code === 200 && typeof csv.body === 'string'
      && csv.body.charCodeAt(0) === 0xFEFF
      && /index,time,ts,proto/.test(csv.body.slice(1, 60))
      && csv.body.includes(',tls,'),
    `code=${csv.code} head=${String(csv.body).slice(0, 44)}`);

  const js = await call('/dsh-capture/export', { url: `/dsh-capture/export?id=${id}&format=json` });
  check('JSON 导出含 tls/streams/httpTransactions',
    js.code === 200 && typeof js.body === 'string'
      && js.body.includes('"tls"') && js.body.includes('"streams"') && js.body.includes('"httpTransactions"'),
    `len=${String(js.body).length}`);

  const srch = await call('/dsh-capture/search', { url: `/dsh-capture/search?id=${id}&pattern=${MARK}` });
  check('正则检索命中请求体（bodies）',
    srch.code === 200 && Array.isArray(srch.body.bodies) && srch.body.bodies.length > 0,
    `bodies=${srch.body?.bodies?.length}`);

  const badRe = await call('/dsh-capture/search', { url: `/dsh-capture/search?id=${id}&pattern=[` });
  check('无效正则返回 400（不抛 500）', badRe.code === 400, `code=${badRe.code}`);

  const longRe = await call('/dsh-capture/search', { url: `/dsh-capture/search?id=${id}&pattern=${'a'.repeat(201)}` });
  check('超长正则返回 400', longRe.code === 400, `code=${longRe.code}`);

  const badFmt = await call('/dsh-capture/export', { url: `/dsh-capture/export?id=${id}&format=xml` });
  check('不支持的导出格式返回 400', badFmt.code === 400, `code=${badFmt.code}`);
} finally {
  dispose();
  check('dispose 后路由清空', registered.size === 0, `剩 ${registered.size}`);
  rmSync(tmpPath, { force: true });
}

const failed = checks.filter((c) => !c.ok);
console.log('');
if (failed.length) {
  console.log(`${checks.length - failed.length} / ${checks.length} 通过，失败 ${failed.length}：`);
  for (const f of failed) console.log(`  - ${f.name}${f.detail ? '  (' + f.detail + ')' : ''}`);
  process.exit(1);
}
console.log(`路由契约测试全部通过（${checks.length} 项）`);
