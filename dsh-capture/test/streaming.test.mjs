/**
 * 流式解析测试：大文件不整读，且结果与整读路径**逐字段等价**。
 *
 * 覆盖：
 *   1. pcapng 与 pcap 两种格式下，流式结果 == 整读结果
 *   2. 块/记录跨 chunk 边界（用极小 chunkBytes 逼出来）
 *   3. maxPackets 在流式路径同样生效
 *   4. 输出带 streamed / chunkBytes / bytesRead 元信息
 *   5. 截断文件不抛异常，而是计入 stats.truncated
 */
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseCapture, parseCaptureStream } from '../lib/pcap.js';

const dir = mkdtempSync(join(tmpdir(), 'dshcap-stream-'));

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

/** 构造 pcapng（IDB 带 if_tsresol=9，模拟 dumpcap）。 */
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

/** 构造经典 pcap（小端，linkType=Ethernet）。 */
function buildPcap(frames) {
  const gh = Buffer.alloc(24);
  gh.writeUInt32LE(0xa1b2c3d4, 0);   // magic LE
  gh.writeUInt16LE(2, 4);            // major
  gh.writeUInt16LE(4, 6);            // minor
  gh.writeUInt32LE(0, 8);            // thiszone
  gh.writeUInt32LE(0, 12);           // sigfigs
  gh.writeUInt32LE(262144, 16);      // snaplen
  gh.writeUInt32LE(1, 20);           // linkType Ethernet
  const parts = [gh];
  let ts = 1700000000;
  for (const f of frames) {
    const rh = Buffer.alloc(16);
    rh.writeUInt32LE(ts, 0);
    rh.writeUInt32LE(0, 4);
    rh.writeUInt32LE(f.length, 8);
    rh.writeUInt32LE(f.length, 12);
    parts.push(rh, f);
    ts += 1;
  }
  return Buffer.concat(parts);
}

/** 只比较与解析正确性相关的字段，不比对象身份。 */
function shapeOf(p) {
  return {
    format: p.meta.format,
    linkType: p.meta.linkType,
    tsResolution: p.meta.tsResolution,
    packets: p.meta.packets,
    bytes: p.meta.bytes,
    tcpPackets: p.meta.tcpPackets,
    udpPackets: p.meta.udpPackets,
    firstTime: p.meta.firstTime,
    lastTime: p.meta.lastTime,
    stats: p.stats,
    reassembly: {
      streams: p.reassembly.streams,
      reassembledBytes: p.reassembly.reassembledBytes,
      gaps: p.reassembly.gaps,
      skippedFlows: p.reassembly.skippedFlows,
    },
    sni: p.sni,
    dns: p.dns.map((d) => d.name),
    httpTransactions: p.httpTransactions.map((t) => ({
      method: t.method, path: t.path, host: t.host, status: t.status,
      requestBody: t.requestBody, responseBody: t.responseBody,
    })),
    tlsClients: p.tls.filter((t) => t.role === 'client').map((t) => ({
      sni: t.sni, clientVersionName: t.clientVersionName, suites: t.cipherSuites,
    })),
    packetsLite: p.packets.map((x) => ({
      ts: x.ts, proto: x.proto, src: x.src, dst: x.dst,
      sport: x.sport, dport: x.dport, bytes: x.bytes, sni: x.sni ?? null,
    })),
  };
}

/* ------------------------- 测试数据 ------------------------- */

const reqBody = '{"stream":"proof"}';
const reqText = `POST /stream HTTP/1.1\r\nHost: stream.test\r\nContent-Type: application/json\r\nContent-Length: ${Buffer.byteLength(reqBody)}\r\n\r\n${reqBody}`;
const resText = 'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 13\r\n\r\n{"stream":ok}';
const reqB = Buffer.from(reqText, 'utf8');
const resB = Buffer.from(resText, 'utf8');

const chRec = (() => {
  const host = Buffer.from('stream.example.org', 'latin1');
  const sniExt = Buffer.concat([
    Buffer.from([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
    Buffer.from([(host.length >> 8) & 0xff, host.length & 0xff]), host,
  ]);
  sniExt.writeUInt16BE(sniExt.length - 4, 2);
  sniExt.writeUInt16BE(sniExt.length - 7, 4);
  const body = Buffer.concat([
    Buffer.from([0x03, 0x03]), Buffer.alloc(32, 0x22), Buffer.from([0x00]),
    Buffer.from([0x00, 0x04, 0x13, 0x01, 0x13, 0x02]), Buffer.from([0x01, 0x00]),
    Buffer.from([(sniExt.length >> 8) & 0xff, sniExt.length & 0xff]), sniExt,
  ]);
  const hs = Buffer.concat([Buffer.from([0x01]), Buffer.from([(body.length >> 8) & 0xff, body.length & 0xff, 0x00]), body]);
  return Buffer.concat([Buffer.from([0x16, 0x03, 0x01, (hs.length >> 8) & 0xff, hs.length & 0xff]), hs]);
})();

const cut = 30;
const frames = [
  tcpFrame({ srcIp: '10.7.0.1', dstIp: '10.7.0.2', sport: 33301, dport: 443, seq: 1, payload: chRec }),
  tcpFrame({ srcIp: '10.7.0.1', dstIp: '10.7.0.3', sport: 33302, dport: 80, seq: 1000, payload: reqB.subarray(0, cut) }),
  tcpFrame({ srcIp: '10.7.0.1', dstIp: '10.7.0.3', sport: 33302, dport: 80, seq: 1000 + cut, payload: reqB.subarray(cut) }),
  tcpFrame({ srcIp: '10.7.0.3', dstIp: '10.7.0.1', sport: 80, dport: 33302, seq: 7000, payload: resB }),
];
// 再加些填充包，让文件跨多个 chunk
for (let i = 0; i < 40; i++) {
  frames.push(tcpFrame({
    srcIp: '10.7.1.1', dstIp: '10.7.1.2', sport: 40000 + i, dport: 9000,
    seq: 1, payload: Buffer.alloc(200 + i * 37, 0x41),
  }));
}

const ngPath = join(dir, 'stream.pcapng');
const pcPath = join(dir, 'stream.pcap');
writeFileSync(ngPath, buildPcapng(frames), 'binary');
writeFileSync(pcPath, buildPcap(frames), 'binary');

/* ------------------------------ 用例 ------------------------------ */

// 1) pcapng：流式 == 整读
{
  const inMem = parseCapture(await (await import('node:fs/promises')).readFile(ngPath));
  const streamed = await parseCaptureStream(ngPath);
  assert.deepEqual(shapeOf(streamed), shapeOf(inMem), 'pcapng 流式结果应与整读一致');
  assert.equal(streamed.meta.streamed, true, '应标记 streamed');
  assert.ok(streamed.meta.bytesRead >= 0, '应报告读取字节数');
  assert.equal(streamed.meta.chunkBytes, 4 * 1024 * 1024, '默认 chunk 应为 4 MB');
  console.log(`  pcapng 流式 == 整读（包 ${streamed.meta.packets}，流 ${streamed.reassembly.streams}，事务 ${streamed.httpTransactions.length}）`);
}

// 2) pcap：流式 == 整读
{
  const inMem = parseCapture(await (await import('node:fs/promises')).readFile(pcPath));
  const streamed = await parseCaptureStream(pcPath);
  assert.deepEqual(shapeOf(streamed), shapeOf(inMem), 'pcap 流式结果应与整读一致');
  console.log(`  pcap 流式 == 整读（包 ${streamed.meta.packets}，格式 ${streamed.meta.format}）`);
}

// 3) 极小 chunk：块/记录跨边界也必须正确
{
  for (const chunk of [4096, 8192, 65536]) {
    const a = await parseCaptureStream(ngPath, { chunkBytes: chunk });
    const b = await parseCaptureStream(ngPath);
    assert.deepEqual(shapeOf(a), shapeOf(b), `pcapng chunk=${chunk} 结果应一致`);
    const c = await parseCaptureStream(pcPath, { chunkBytes: chunk });
    const d = await parseCaptureStream(pcPath);
    assert.deepEqual(shapeOf(c), shapeOf(d), `pcap chunk=${chunk} 结果应一致`);
  }
  console.log('  小 chunk（4 KB / 8 KB / 64 KB）跨边界解析正确');
}

// 4) maxPackets 在流式路径生效
{
  const limited = await parseCaptureStream(ngPath, { maxPackets: 5 });
  assert.equal(limited.packets.length, 5, `maxPackets=5 应只留 5 个，实际 ${limited.packets.length}`);
  assert.equal(limited.meta.truncatedOrig, 1, '被上限截断应标记 truncatedOrig');
  const limitedMem = parseCapture(await (await import('node:fs/promises')).readFile(ngPath), { maxPackets: 5 });
  assert.equal(limitedMem.packets.length, 5, '整读路径同样受 maxPackets 约束');
  console.log(`  maxPackets 生效（流式 5 == 整读 5）`);
}

// 5) 截断文件：不抛异常，计入 stats.truncated
{
  const full = buildPcapng(frames);
  const cutPath = join(dir, 'cut.pcapng');
  writeFileSync(cutPath, full.subarray(0, Math.floor(full.length * 0.6)), 'binary');
  const r = await parseCaptureStream(cutPath);
  assert.ok(r.meta.packets > 0, '截断文件仍应解析出前面的包');
  assert.ok(r.stats.truncated > 0, `截断应被计数，实际 ${r.stats.truncated}`);
  // 整读路径对同一文件的结论应一致（同样不抛）
  const m = parseCapture(await (await import('node:fs/promises')).readFile(cutPath));
  assert.equal(m.meta.packets, r.meta.packets, '截断文件两条路径包数应一致');
  console.log(`  截断文件安全（${r.meta.packets} 包，truncated=${r.stats.truncated}）`);
}

// 6) 非法输入
{
  const badPath = join(dir, 'bad.bin');
  writeFileSync(badPath, Buffer.from('not a capture at all, really'));
  await assert.rejects(() => parseCaptureStream(badPath), /无法识别的抓包格式/, '非法格式应明确报错');
  const tinyPath = join(dir, 'tiny.bin');
  writeFileSync(tinyPath, Buffer.from([0x01, 0x02]));
  await assert.rejects(() => parseCaptureStream(tinyPath), /文件太小/, '过小文件应明确报错');
  console.log('  非法输入报错清晰');
}

// 7) 重组在流式路径同样成立（跨包 HTTP + TLS）
{
  const s = await parseCaptureStream(ngPath, { chunkBytes: 4096 });
  const tx = s.httpTransactions[0];
  assert.ok(tx, '流式路径应提取到 HTTP 事务');
  assert.equal(tx.method, 'POST');
  assert.equal(tx.host, 'stream.test');
  assert.equal(tx.requestBody, reqBody, '请求体应重组完整');
  assert.equal(tx.status, 200);
  const ch = s.tls.find((t) => t.role === 'client');
  assert.ok(ch && ch.sni === 'stream.example.org', '流式路径应读出 ClientHello 与 SNI');
  console.log(`  流式路径重组成立（tx=${tx.method} ${tx.host}，SNI=${ch.sni}）`);
}

// 8) 接线验证：路由对超过阈值的文件真的走流式（analyzeFile 的 streamed 标记）
{
  const { mountRoutes } = await import('../lib/routes.js');
  const registered = new Map();
  const fakeCtx = {
    webServer: {
      register({ path, handler }) { registered.set(path, { path, handler }); return () => registered.delete(path); },
    },
  };

  // 造一个明确超过 16 MB 阈值的抓包：少量大帧比海量小帧快得多。
  const bigFrames = [];
  const payload = Buffer.alloc(60000, 0x42);
  for (let i = 0; i < 320; i++) {
    bigFrames.push(tcpFrame({
      srcIp: '10.8.0.1', dstIp: '10.8.0.2', sport: 50000 + (i % 50), dport: 8443,
      seq: 1 + i, payload,
    }));
  }
  const bigPath = join(dir, 'big.pcapng');
  writeFileSync(bigPath, buildPcapng(bigFrames), 'binary');
  const bigSize = (await import('node:fs')).statSync(bigPath).size;
  assert.ok(bigSize > 16 * 1024 * 1024, `测试文件应超过 16 MB 阈值，实际 ${(bigSize / 1048576).toFixed(1)} MB`);

  // 丢进抓包目录，用真实 id 寻址
  const capDir = join(process.env.DSH_HOME ?? join((await import('node:os')).homedir(), '.dsh'), 'dsh-capture');
  (await import('node:fs')).mkdirSync(capDir, { recursive: true });
  const target = join(capDir, `stream-big-${Date.now()}.pcapng`);
  (await import('node:fs')).copyFileSync(bigPath, target);
  const id = (await import('node:crypto')).createHash('sha256')
    .update(target.split(/[\\/]/).pop()).digest('hex').slice(0, 16);

  const dispose = mountRoutes(fakeCtx, { reassemble: true });
  try {
    const res = { statusCode: 0, headers: null, body: '',
      writeHead(c, h) { this.statusCode = c; this.headers = h; },
      end(t) { this.body = t == null ? '' : String(t); } };
    const req = { url: `/dsh-capture/analyze?id=${id}`, method: 'GET', on() {}, destroy() {} };
    await registered.get('/dsh-capture/analyze').handler(req, res);
    const body = JSON.parse(res.body);
    assert.equal(body.ok, true, `analyze 应成功：${body.error ?? ''}`);
    assert.equal(body.streamed, true, `超过阈值的文件应走流式，实际 streamed=${body.streamed}`);
    assert.ok(body.meta.packets > 0, '应解析出包');
    assert.ok(['pcapng', 'pcap'].includes(body.meta.format), `格式应可识别，实际 ${body.meta.format}`);
    console.log(`  路由接线：${(bigSize / 1048576).toFixed(1)} MB 文件走流式（包 ${body.meta.packets}，streamed=${body.streamed}）`);

    // 同一个文件走 /packets 也应成功（大文件分页）
    const res2 = { statusCode: 0, headers: null, body: '',
      writeHead(c, h) { this.statusCode = c; this.headers = h; },
      end(t) { this.body = t == null ? '' : String(t); } };
    const req2 = { url: `/dsh-capture/packets?id=${id}&limit=5`, method: 'GET', on() {}, destroy() {} };
    await registered.get('/dsh-capture/packets').handler(req2, res2);
    const body2 = JSON.parse(res2.body);
    assert.equal(body2.ok, true, `packets 应成功：${body2.error ?? ''}`);
    assert.equal(body2.rows.length, 5, `应分页返回 5 行，实际 ${body2.rows?.length}`);
    console.log(`  /packets 大文件分页正常（total=${body2.total} rows=${body2.rows.length}）`);
  } finally {
    dispose();
    (await import('node:fs')).rmSync(target, { force: true });
  }
}

rmSync(dir, { recursive: true, force: true });

console.log('流式解析测试通过：');
console.log('  - pcapng / pcap 流式结果与整读逐字段一致');
console.log('  - 块与记录跨 chunk 边界解析正确');
console.log('  - maxPackets 与截断处理在两条路径上一致');
console.log('  - 非法/过小输入报错清晰');
console.log('  - 流式路径下 TCP 重组与 TLS 详情仍然成立');
console.log('  - 路由接线：超过阈值的文件经 /analyze 与 /packets 走流式');
