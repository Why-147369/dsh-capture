/**
 * 回归测试：用"带完整选项的 IDB"构造 pcapng，确保解析器不会再把
 * linkType 读成垃圾值。
 *
 * 背景：此前的自测文件里 IDB 是简化版（16 字节、无 options），
 * 恰好绕过了错误偏移，导致 linkType 被读成 0xFFFFFFFF 时测试仍然"通过"。
 * 真实 dumpcap/pktmon 写出的 IDB 带 192 字节选项区，暴露了该 bug。
 * 本测试专门覆盖这个形状。
 */
import assert from 'node:assert/strict';
import { parseCapture, DNS_TYPES } from '../lib/pcap.js';

/** 构造一个 IPv4+UDP+DNS 帧。 */
function dnsFrame(name) {
  const labels = name.split('.').map((l) => Buffer.from(l, 'latin1'));
  const qname = Buffer.concat([
    ...labels.map((l) => Buffer.concat([Buffer.from([l.length]), l])),
    Buffer.from([0x00]),
  ]);
  const dns = Buffer.concat([
    Buffer.from([0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
    qname, Buffer.from([0x00, 0x01, 0x00, 0x01]),
  ]);
  const udp = Buffer.alloc(8 + dns.length);
  udp.writeUInt16BE(53000, 0); udp.writeUInt16BE(53, 2);
  udp.writeUInt16BE(udp.length, 4);
  dns.copy(udp, 8);
  const ip = Buffer.alloc(20 + udp.length);
  ip[0] = 0x45; ip[9] = 17; ip.writeUInt16BE(ip.length, 2);
  ip.writeUInt32BE(0x0a000001, 12); ip.writeUInt32BE(0x08080808, 16);
  udp.copy(ip, 20);
  const eth = Buffer.alloc(14 + ip.length);
  eth.writeUInt16BE(0x0800, 12);
  ip.copy(eth, 14);
  return eth;
}

/** 构造一个带 options 的 IDB（复刻真实 dumpcap 的形状）。 */
function buildIdb(linkType, tsResol) {
  // option 2 (if_name) 长度 50，option 3 (if_description) 长度 4，
  // option 9 (if_tsresol) 长度 1，最后 endofopt(0,0)
  const optName = Buffer.concat([
    Buffer.from([0x02, 0x00]), Buffer.from([50, 0x00]),
    Buffer.alloc(50, 0x41), // 'A' * 50
    Buffer.alloc((4 - (50 % 4)) % 4),
  ]);
  const optDesc = Buffer.concat([
    Buffer.from([0x03, 0x00]), Buffer.from([4, 0x00]), Buffer.from('WLAN', 'latin1'),
  ]);
  const resol = Number.isFinite(tsResol) ? tsResol : 0x06;
  const optRes = Buffer.concat([
    Buffer.from([0x09, 0x00]), Buffer.from([1, 0x00]), Buffer.from([resol]),
    Buffer.alloc(3),
  ]);
  const optEnd = Buffer.from([0x00, 0x00, 0x00, 0x00]);
  const options = Buffer.concat([optName, optDesc, optRes, optEnd]);

  const body = Buffer.concat([
    Buffer.from([linkType & 0xff, (linkType >> 8) & 0xff]), // linktype (2)
    Buffer.from([0x00, 0x00]),                               // reserved (2)
    Buffer.from([0x00, 0x00, 0x04, 0x00]),                   // snaplen = 262144
    options,
  ]);
  const total = 8 + body.length + 4;
  const hdr = Buffer.alloc(8);
  hdr.writeUInt32LE(0x00000001, 0);   // IDB
  hdr.writeUInt32LE(total, 4);
  const tail = Buffer.alloc(4);
  tail.writeUInt32LE(total, 0);
  return Buffer.concat([hdr, body, tail]);
}

/** 构造完整 pcapng：SHB + IDB(带 options) + N 个 EPB。 */
function buildPcapng(frames, linkType, opts = {}) {
  const tsResol = Number.isFinite(opts.tsResol) ? opts.tsResol : 6;      // 6 = 微秒
  const units = Math.pow(10, tsResol);
  const baseTs = Number.isFinite(opts.ts) ? opts.ts : null;

  const shbBody = Buffer.alloc(16);
  shbBody.writeUInt32LE(0x1a2b3c4d, 0);
  shbBody.writeUInt16LE(1, 4);
  shbBody.writeUInt16LE(0, 6);
  const shbRaw = Buffer.concat([Buffer.from([0x0a, 0x0d, 0x0d, 0x0a]), Buffer.from([0, 0, 0, 0]), shbBody]);
  const shbPad = (4 - (shbRaw.length % 4)) % 4;
  const shbTotal = shbRaw.length + shbPad + 4;
  const shb = Buffer.concat([shbRaw, Buffer.alloc(shbPad), (() => { const b = Buffer.alloc(4); b.writeUInt32LE(shbTotal, 0); return b; })()]);
  shb.writeUInt32LE(shbTotal, 4);

  const parts = [shb, buildIdb(linkType, tsResol)];
  let idx = 0;
  for (const f of frames) {
    const pad = (4 - (f.length % 4)) % 4;
    const total = 32 + f.length + pad;
    const hdr = Buffer.alloc(28);
    hdr.writeUInt32LE(0x00000006, 0);
    hdr.writeUInt32LE(total, 4);
    // 时间戳按本文件的 if_tsresol 写入
    const t = baseTs != null ? baseTs + idx * 0.001 : 0;
    const ticks = Math.round(t * units);
    hdr.writeUInt32LE(Math.floor(ticks / 4294967296), 12);
    hdr.writeUInt32LE(ticks % 4294967296, 16);
    hdr.writeUInt32LE(f.length, 20);
    hdr.writeUInt32LE(f.length, 24);
    const tail = Buffer.alloc(4);
    tail.writeUInt32LE(total, 0);
    parts.push(Buffer.concat([hdr, f, Buffer.alloc(pad), tail]));
    idx++;
  }
  return Buffer.concat(parts);
}

// ---- 断言 ----

// 1) 带选项的 IDB：linkType 必须被正确读出（这是本次 bug 的核心回归点）
{
  const buf = buildPcapng([dnsFrame('regress.test')], 1);
  const p = parseCapture(buf);
  assert.equal(p.meta.linkType, 1, `linkType 应为 1，实际 ${p.meta.linkType}`);
  assert.notEqual(p.meta.linkType, 0xFFFFFFFF, 'linkType 不应是 0xFFFFFFFF（IDB 偏移错误）');
  assert.equal(p.stats.unsupportedLink, 0, '不应有"不支持的链路类型"');
  assert.equal(p.meta.packets, 1, `应解析出 1 个包，实际 ${p.meta.packets}`);
  assert.ok(p.dns.some((d) => d.name === 'regress.test'), 'DNS 名应被解析');
}

// 2) linkType=0（null/loopback）应被计为 unsupported，而不是崩溃
{
  const buf = buildPcapng([dnsFrame('x.test')], 0);
  const p = parseCapture(buf);
  assert.equal(p.meta.linkType, 0, 'linkType 应为 0');
  assert.ok(p.stats.unsupportedLink >= 1, 'linkType=0 应被计为不支持');
  assert.equal(p.stats.malformed, 0, '不应记为畸形');
}

// 3) 多接口场景：每个 IDB 各带自己的 linkType，取最后一个
{
  const frames = [dnsFrame('multi.test')];
  const p1 = buildPcapng(frames, 1);
  const p = parseCapture(p1);
  assert.equal(p.meta.linkType, 1);
  assert.equal(p.meta.packets, 1);
}

// 4) SHB 里不应再有"从 options 区读 linkType"的痕迹：section 版本可读
{
  const buf = buildPcapng([dnsFrame('ver.test')], 1);
  const p = parseCapture(buf);
  assert.ok(p.meta.version, '应带出 section 版本');
  assert.equal(p.meta.version.major, 1);
}

// 5) 真实世界形状：选项区总长 > 128 字节时仍正确（模拟 dumpcap 的 212 字节 IDB）
{
  const frame = dnsFrame('bigopt.test');
  const buf = buildPcapng([frame, frame, frame], 1);
  const p = parseCapture(buf);
  assert.equal(p.meta.packets, 3, `应解析出 3 个包，实际 ${p.meta.packets}`);
  assert.equal(p.stats.truncated, 0);
  assert.equal(p.stats.malformed, 0);
}

// 6) 时间戳分辨率：IDB 声明 nanosecond 时不能按微秒解读
//
// 这是真实 dumpcap/Npcap 暴露的 bug：解析器硬编码微秒，
// 而 dumpcap 写的是 if_tsresol = 9（纳秒），导致时间戳放大 1000 倍
// （2026 年变成公元 58760 年）。合成文件若不带该 option 就发现不了。
{
  const frame = dnsFrame('tsresol.test');
  const buf = buildPcapng([frame], 1, { tsResol: 9, ts: 1700000000.123456789 });

  const p = parseCapture(buf);
  assert.equal(p.meta.packets, 1, '应解析出 1 个包');
  assert.equal(p.meta.tsResolution, 1e9, `tsResolution 应为 1e9，实际 ${p.meta.tsResolution}`);

  const ts = p.meta.firstTs;
  assert.ok(Number.isFinite(ts), 'firstTs 应为数值');
  // 必须落在 2023-11-14 附近，而不是被放大 1000 倍的公元 58760 年
  const year = new Date(ts * 1000).getUTCFullYear();
  assert.equal(year, 2023, `年份应为 2023，实际 ${year}（时间戳被按错误分辨率解读）`);
  assert.ok(Math.abs(ts - 1700000000) < 1, `firstTs 应约等于 1700000000，实际 ${ts}`);
  assert.ok(/^2023-11-14T/.test(String(p.meta.firstTime)), `firstTime 应为 2023-11-14，实际 ${p.meta.firstTime}`);
}

// 7) 同样的文件若按微秒解读（默认）则会明显偏小 —— 证明上面读的是真 option
{
  const frame = dnsFrame('tsdefault.test');
  const buf = buildPcapng([frame], 1, { ts: 1700000000.5 });
  const p = parseCapture(buf);
  assert.equal(p.meta.tsResolution, 1e6, '未声明 if_tsresol 时应回落到微秒');
  assert.equal(new Date(p.meta.firstTs * 1000).getUTCFullYear(), 2023);
}

console.log('pcapng IDB 回归测试通过：');
console.log('  - 带 options 的 IDB 能正确读出 linkType');
console.log('  - linkType=0 计为 unsupported 而非崩溃');
console.log('  - section 版本可读');
console.log('  - 多包文件完整解析');
console.log('  - if_tsresol=9（纳秒）被正确解读，时间戳不放大 1000 倍');
