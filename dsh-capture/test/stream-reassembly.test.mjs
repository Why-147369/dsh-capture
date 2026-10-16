/**
 * 回归测试：TCP 流重组 + HTTP 报文体提取 + TLS 握手详情。
 *
 * 覆盖三件此前缺失的能力：
 *   1. TCP 流重组 —— HTTP 请求/响应跨包时不再截断（只看首包会漏）
 *   2. HTTP 报文体提取 —— 请求体/响应体（按 Content-Length，文本类型才取预览）
 *   3. TLS 握手详情 —— 记录版本、客户端版本、supported_versions、密码套件列表、
 *      ServerHello 协商结果（此前只有 SNI）
 *
 * 构造方式：手工拼 Ethernet/IPv4/TCP 帧，再包成 pcapng。
 * 关键用例是"消息跨包"——这正是单包解析会失败、重组才能通过的场景。
 */
import assert from 'node:assert/strict';
import { parseCapture } from '../lib/pcap.js';

/* ------------------------- 报文构造工具 ------------------------- */

const MAC_C = Buffer.from('001122334455', 'hex');
const MAC_S = Buffer.from('66778899aabb', 'hex');

/** 构造 IPv4+TCP 帧（payload 可跨多个 seq 片段）。 */
function tcpFrame(srcIp, dstIp, sport, dport, seq, payload, flags = 0x18) {
  const tcp = Buffer.alloc(20 + payload.length);
  tcp.writeUInt16BE(sport, 0);
  tcp.writeUInt16BE(dport, 2);
  tcp.writeUInt32BE(seq >>> 0, 4);
  tcp.writeUInt32BE(0, 8);
  tcp[12] = 0x50;           // data offset = 5 (20 bytes)
  tcp[13] = flags;          // PSH|ACK by default
  payload.copy(tcp, 20);

  const ip = Buffer.alloc(20 + tcp.length);
  ip[0] = 0x45; ip[9] = 6;
  ip.writeUInt16BE(ip.length, 2);
  ip.writeUInt16BE(0x4000, 6);
  ip[8] = 64;
  ip.writeUInt32BE(ipToInt(srcIp), 12);
  ip.writeUInt32BE(ipToInt(dstIp), 16);
  tcp.copy(ip, 20);

  const eth = Buffer.alloc(14 + ip.length);
  MAC_S.copy(eth, 0);
  MAC_C.copy(eth, 6);
  eth.writeUInt16BE(0x0800, 12);
  ip.copy(eth, 14);
  return eth;
}

function ipToInt(ip) {
  const p = ip.split('.').map(Number);
  return ((p[0] << 24) >>> 0) + (p[1] << 16) + (p[2] << 8) + p[3];
}

/** 构造一个 TLS 扩展。 */
function ext(type, body) {
  const h = Buffer.alloc(4);
  h.writeUInt16BE(type, 0);
  h.writeUInt16BE(body.length, 2);
  return Buffer.concat([h, body]);
}

/** 构造 ClientHello（含 SNI / 密码套件 / supported_versions）。 */
function clientHello(sni, cipherIds, versions) {
  const name = Buffer.from(sni, 'latin1');
  const sniList = Buffer.concat([
    Buffer.from([0x00, 0x00]),                       // (placeholder) list length
    Buffer.from([0x00]),                             // host_name
    (() => { const b = Buffer.alloc(2); b.writeUInt16BE(name.length, 0); return b; })(),
    name,
  ]);
  const sniBody = Buffer.concat([(() => { const b = Buffer.alloc(2); b.writeUInt16BE(sniList.length - 2, 0); return b; })(), sniList.subarray(2)]);

  const csBody = Buffer.concat(cipherIds.map((c) => { const b = Buffer.alloc(2); b.writeUInt16BE(c, 0); return b; }));
  const csField = Buffer.concat([(() => { const b = Buffer.alloc(2); b.writeUInt16BE(csBody.length, 0); return b; })(), csBody]);

  const verBody = Buffer.concat([
    Buffer.from([versions.length * 2]),
    ...versions.map((v) => { const b = Buffer.alloc(2); b.writeUInt16BE(v, 0); return b; }),
  ]);

  const extensions = Buffer.concat([
    ext(0x0000, sniBody),
    ext(0x002b, verBody),
    ext(0x000a, Buffer.from([0x00, 0x04, 0x00, 0x1d, 0x00, 0x17])),
  ]);
  const extField = Buffer.concat([(() => { const b = Buffer.alloc(2); b.writeUInt16BE(extensions.length, 0); return b; })(), extensions]);

  const body = Buffer.concat([
    Buffer.from([0x03, 0x03]),                       // client version = TLS 1.2
    Buffer.alloc(32, 0x5a),                          // random
    Buffer.from([0x00]),                             // session id length 0
    csField,
    Buffer.from([0x01, 0x00]),                       // compression: null
    extField,
  ]);
  const hs = Buffer.concat([
    Buffer.from([0x01]),
    (() => { const b = Buffer.alloc(3); b.writeUIntBE(body.length, 0, 3); return b; })(),
    body,
  ]);
  const rec = Buffer.concat([
    Buffer.from([0x16, 0x03, 0x01]),                 // handshake, record version TLS 1.0
    (() => { const b = Buffer.alloc(2); b.writeUInt16BE(hs.length, 0); return b; })(),
    hs,
  ]);
  return rec;
}

/** 构造 ServerHello（含 supported_versions = TLS 1.3 与协商密码套件）。 */
function serverHello(cipherId, negotiatedVersion) {
  const sv = Buffer.alloc(4);
  sv.writeUInt16BE(0x002b, 0);
  sv.writeUInt16BE(2, 2);
  const ver = Buffer.alloc(2);
  ver.writeUInt16BE(negotiatedVersion, 0);
  const extField = Buffer.concat([(() => { const b = Buffer.alloc(2); b.writeUInt16BE(6, 0); return b; })(), sv, ver]);

  const body = Buffer.concat([
    Buffer.from([0x03, 0x03]),                       // legacy version TLS 1.2
    Buffer.alloc(32, 0x3c),                          // random
    Buffer.from([0x00]),                             // session id length
    (() => { const b = Buffer.alloc(2); b.writeUInt16BE(cipherId, 0); return b; })(),
    Buffer.from([0x00]),                             // compression null
    extField,
  ]);
  const hs = Buffer.concat([
    Buffer.from([0x02]),
    (() => { const b = Buffer.alloc(3); b.writeUIntBE(body.length, 0, 3); return b; })(),
    body,
  ]);
  return Buffer.concat([
    Buffer.from([0x16, 0x03, 0x03]),
    (() => { const b = Buffer.alloc(2); b.writeUInt16BE(hs.length, 0); return b; })(),
    hs,
  ]);
}

/** 把帧列表包成 pcapng（SHB + 带 options 的 IDB + EPB）。 */
function buildPcapng(frames) {
  const shbBody = Buffer.alloc(16);
  shbBody.writeUInt32LE(0x1a2b3c4d, 0);
  shbBody.writeUInt16LE(1, 4);
  shbBody.writeUInt16LE(0, 6);
  const shbRaw = Buffer.concat([Buffer.from([0x0a, 0x0d, 0x0d, 0x0a]), Buffer.from([0, 0, 0, 0]), shbBody]);
  const shbPad = (4 - (shbRaw.length % 4)) % 4;
  const shbTotal = shbRaw.length + shbPad + 4;
  const shb = Buffer.concat([shbRaw, Buffer.alloc(shbPad), (() => { const b = Buffer.alloc(4); b.writeUInt32LE(shbTotal, 0); return b; })()]);
  shb.writeUInt32LE(shbTotal, 4);

  // 带 options 的 IDB（复刻真实 dumpcap 形状，linkType=1 Ethernet）
  const optName = Buffer.concat([
    Buffer.from([0x02, 0x00]), Buffer.from([50, 0x00]), Buffer.alloc(50, 0x41), Buffer.alloc(2),
  ]);
  const optEnd = Buffer.from([0x00, 0x00, 0x00, 0x00]);
  const idbBody = Buffer.concat([
    Buffer.from([0x01, 0x00]), Buffer.from([0x00, 0x00]),
    Buffer.from([0x00, 0x00, 0x04, 0x00]),
    optName, optEnd,
  ]);
  const idbTotal = 8 + idbBody.length + 4;
  const idbHdr = Buffer.alloc(8);
  idbHdr.writeUInt32LE(0x00000001, 0);
  idbHdr.writeUInt32LE(idbTotal, 4);
  const idbTail = Buffer.alloc(4);
  idbTail.writeUInt32LE(idbTotal, 0);
  const idb = Buffer.concat([idbHdr, idbBody, idbTail]);

  const parts = [shb, idb];
  let ts = 1700000000;
  for (const f of frames) {
    const pad = (4 - (f.length % 4)) % 4;
    const total = 32 + f.length + pad;
    const hdr = Buffer.alloc(28);
    hdr.writeUInt32LE(0x00000006, 0);
    hdr.writeUInt32LE(total, 4);
    // 时间戳：微妙分辨率
    hdr.writeUInt32LE(Math.floor(ts * 1e6 / 4294967296), 12);
    hdr.writeUInt32LE(Math.floor(ts * 1e6) % 4294967296, 16);
    hdr.writeUInt32LE(f.length, 20);
    hdr.writeUInt32LE(f.length, 24);
    const tail = Buffer.alloc(4);
    tail.writeUInt32LE(total, 0);
    parts.push(Buffer.concat([hdr, f, Buffer.alloc(pad), tail]));
    ts += 0.001;
  }
  return Buffer.concat(parts);
}

/* ------------------------------ 用例 1 ------------------------------ */
/* HTTP：请求与响应都跨包，体也要跨包 —— 单包解析必然截断，重组才能完整。 */

{
  const C = '10.0.0.5', S = '93.184.216.34';
  const reqBody = '{"alpha":1,"beta":2}';
  const reqText = `POST /submit HTTP/1.1\r\nHost: example.com\r\nUser-Agent: dsh-capture-test\r\nContent-Type: application/json\r\nContent-Length: ${reqBody.length}\r\n\r\n${reqBody}`;
  const resBody = '{"ok":true,"id":42}';
  const resText = `HTTP/1.1 200 OK\r\nServer: test-server\r\nContent-Type: application/json\r\nContent-Length: ${resBody.length}\r\n\r\n${resBody}`;

  const cut1 = 60;                                  // 请求头跨包
  const reqBytes = Buffer.from(reqText, 'utf8');
  const resBytes = Buffer.from(resText, 'utf8');
  const resCut = 45;

  const frames = [
    tcpFrame(C, S, 51000, 80, 1000, reqBytes.subarray(0, cut1)),
    tcpFrame(C, S, 51000, 80, 1000 + cut1, reqBytes.subarray(cut1)),
    tcpFrame(S, C, 80, 51000, 5000, resBytes.subarray(0, resCut)),
    tcpFrame(S, C, 80, 51000, 5000 + resCut, resBytes.subarray(resCut)),
  ];

  const p = parseCapture(buildPcapng(frames));

  assert.equal(p.meta.packets, 4, `应解析 4 个包，实际 ${p.meta.packets}`);
  assert.ok(p.reassembly, '应带出 reassembly 统计');
  assert.equal(p.reassembly.streams, 1, `应识别 1 条 TCP 流，实际 ${p.reassembly.streams}`);

  const tx = p.httpTransactions;
  assert.equal(tx.length, 1, `应产出 1 个 HTTP 事务，实际 ${tx.length}`);
  const t = tx[0];
  assert.equal(t.method, 'POST', `方法应为 POST，实际 ${t.method}`);
  assert.equal(t.path, '/submit', `路径应为 /submit，实际 ${t.path}`);
  assert.equal(t.host, 'example.com');
  assert.equal(t.status, 200, `状态码应为 200，实际 ${t.status}`);
  assert.equal(t.requestContentType, 'application/json');
  assert.equal(t.responseContentType, 'application/json');
  assert.equal(t.responseBytes, resBody.length, '响应 Content-Length 应被读出');
  assert.equal(t.requestBody, reqBody, `请求体应跨包重组完整，实际 ${JSON.stringify(t.requestBody)}`);
  assert.ok(String(t.responseBody).startsWith('{"ok":true'), `响应体应重组，实际 ${JSON.stringify(t.responseBody)}`);

  // 流聚合结果里也要能看到
  assert.equal(p.streams.length, 1, 'streams 应有 1 条');
  assert.ok(p.streams[0].http && p.streams[0].http.request, 'streams[0].http.request 应存在');
  assert.equal(p.streams[0].gaps, 0, '不应有空洞（片段连续）');
}

/* ------------------------------ 用例 2 ------------------------------ */
/* 乱序到达：重组必须按 seq 排序，而不是按抓包顺序。 */

{
  const C = '10.1.1.9', S = '10.1.1.1';
  const head = 'GET /ordered HTTP/1.1\r\nHost: order.test\r\n\r\n';
  const bytes = Buffer.from(head, 'utf8');
  const cut = 20;
  const partA = bytes.subarray(0, cut);
  const partB = bytes.subarray(cut);

  // 故意先把后半段放进捕获
  const frames = [
    tcpFrame(C, S, 40000, 8080, 2000 + cut, partB),
    tcpFrame(C, S, 40000, 8080, 2000, partA),
  ];
  const p = parseCapture(buildPcapng(frames));
  const tx = p.httpTransactions;
  assert.equal(tx.length, 1, '乱序也应重组成 1 个事务');
  assert.equal(tx[0].method, 'GET', `乱序重组后方法应为 GET，实际 ${tx[0].method}`);
  assert.equal(tx[0].host, 'order.test');
}

/* ------------------------------ 用例 3 ------------------------------ */
/* 缺口检测：中间丢一段时，重组不能假装连续。 */

{
  const C = '10.2.2.9', S = '10.2.2.1';
  const bytes = Buffer.from('GET /gap HTTP/1.1\r\nHost: gap.test\r\n\r\n', 'utf8');
  const frames = [
    tcpFrame(C, S, 40001, 80, 7000, bytes.subarray(0, 10)),
    // 跳过中间 10..20 字节
    tcpFrame(C, S, 40001, 80, 7000 + 20, bytes.subarray(20)),
  ];
  const p = parseCapture(buildPcapng(frames));
  assert.equal(p.streams.length, 1);
  assert.ok(p.streams[0].gaps >= 1, `应检出缺口，实际 gaps=${p.streams[0].gaps}`);
}

/* ------------------------------ 用例 4 ------------------------------ */
/* TLS：完整 ClientHello + ServerHello，必须读出 SNI、各版本与密码套件。 */

{
  const C = '10.3.3.5', S = '1.1.1.1';
  const ch = clientHello('secure.example.org', [0x1301, 0x1302, 0xc02f, 0xc030], [0x0304, 0x0303]);
  const sh = serverHello(0x1301, 0x0304);

  const frames = [
    tcpFrame(C, S, 52000, 443, 3000, ch),
    tcpFrame(S, C, 443, 52000, 9000, sh),
  ];
  const p = parseCapture(buildPcapng(frames));

  assert.ok(p.tls.length >= 1, `应解析出 TLS 握手，实际 ${p.tls.length}`);
  const hello = p.tls.find((x) => x.role === 'client');
  assert.ok(hello, '应有 ClientHello');
  assert.equal(hello.sni, 'secure.example.org', `SNI 应为 secure.example.org，实际 ${hello.sni}`);
  assert.equal(hello.recordVersionName, 'TLS 1.0', `record 版本名，实际 ${hello.recordVersionName}`);
  assert.equal(hello.clientVersionName, 'TLS 1.2', `client 版本名，实际 ${hello.clientVersionName}`);
  assert.deepEqual(hello.supportedVersions, ['TLS 1.3', 'TLS 1.2'], `supported_versions，实际 ${JSON.stringify(hello.supportedVersions)}`);
  assert.ok(hello.cipherSuites.includes('TLS_AES_128_GCM_SHA256'), '应含 0x1301 的规范名');
  assert.ok(hello.cipherSuites.includes('ECDHE_RSA_AES128_GCM_SHA256'), '应含 0xc02f 的规范名');
  assert.equal(hello.cipherSuites.length, 4, `应有 4 个密码套件，实际 ${hello.cipherSuites.length}`);

  const sHello = p.tls.find((x) => x.role === 'server');
  assert.ok(sHello, '应有 ServerHello');
  assert.equal(sHello.cipherSuite, 'TLS_AES_128_GCM_SHA256', `协商套件，实际 ${sHello.cipherSuite}`);
  assert.equal(sHello.negotiatedVersionName, 'TLS 1.3', `协商版本，实际 ${sHello.negotiatedVersionName}`);

  // 单包 SNI 兼容字段仍在
  assert.ok(p.sni.some((s) => s.name === 'secure.example.org'), 'SNI 聚合仍应工作');

  // 流的 tls 字段
  const stream = p.streams.find((s) => s.tls);
  assert.ok(stream, 'streams 应带 tls');
}

/* ------------------------------ 用例 5 ------------------------------ */
/* 时间戳：meta 里应有 ISO 时间，包行带 ts 数值。 */

{
  const C = '10.4.4.5', S = '10.4.4.1';
  const frames = [tcpFrame(C, S, 33333, 80, 1, Buffer.from('GET /t HTTP/1.1\r\nHost: t.test\r\n\r\n'))];
  const p = parseCapture(buildPcapng(frames));
  assert.ok(Number.isFinite(p.meta.firstTs), 'firstTs 应为数值');
  assert.ok(/^\d{4}-\d{2}-\d{2}T/.test(String(p.meta.firstTime)), `firstTime 应为 ISO 串，实际 ${p.meta.firstTime}`);
  assert.ok(Number.isFinite(p.packets[0].ts), '包应带 ts');
}

/* ------------------------------ 用例 6 ------------------------------ */
/* 边界：重组有上限，超大流不能吃光内存。 */

{
  const C = '10.5.5.5', S = '10.5.5.1';
  const big = Buffer.alloc(60000, 0x41);
  const frames = [];
  for (let i = 0; i < 12; i++) frames.push(tcpFrame(C, S, 44444, 80, 100 + i * 60000, big));
  const p = parseCapture(buildPcapng(frames), { streamCap: 65536, maxStreams: 10 });
  assert.equal(p.streams.length, 1, '应只有 1 条流');
  assert.ok(p.streams[0].truncated, '超过 streamCap 的流应标记 truncated');
  assert.ok(p.reassembly.reassembledBytes <= 2 * 65536, `重组字节应受上限约束，实际 ${p.reassembly.reassembledBytes}`);
}

/* ------------------------------ 用例 7 ------------------------------ */
/* 可以用 reassemble:false 关掉重组（大文件分析时省内存）。 */

{
  const C = '10.6.6.5', S = '10.6.6.1';
  const frames = [tcpFrame(C, S, 33334, 80, 1, Buffer.from('GET /x HTTP/1.1\r\nHost: x.test\r\n\r\n'))];
  const p = parseCapture(buildPcapng(frames), { reassemble: false });
  assert.equal(p.streams.length, 0, '关闭后不应有 streams');
  assert.ok(p.reassembly.disabled, '应标记 disabled');
}

console.log('TCP 重组 / HTTP 体 / TLS 详情 测试通过：');
console.log('  - HTTP 请求与响应跨包重组完整（含报文体）');
console.log('  - 乱序片段按 seq 正确排序');
console.log('  - 缺口能被检出，不假装连续');
console.log('  - ClientHello 读出 SNI / record 版本 / client 版本 / supported_versions / 密码套件名');
console.log('  - ServerHello 读出协商版本与密码套件');
console.log('  - 时间戳带 ISO 格式化');
console.log('  - 重组受上限约束，可开关');
