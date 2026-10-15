/**
 * dsh-capture self-test: builds synthetic pcapng files in memory, then checks
 * the parser against them. No network and no pktmon needed.
 *
 * Run: node test/selftest.mjs
 */
import assert from 'node:assert/strict';
import { parseCapture, DNS_TYPES } from '../lib/pcap.js';

/** Build an Ethernet + IPv4 + TCP frame with a TLS ClientHello carrying SNI. */
function ethTcp(sni) {
  const host = Buffer.from(sni, 'latin1');
  // Build a minimal TLS record: handshake/ClientHello with one SNI extension.
  const sniExt = Buffer.concat([
    Buffer.from([0x00, 0x00]),                     // ext type server_name
    Buffer.from([0x00, 0x00]),                     // ext len (patched below)
    Buffer.from([0x00, 0x00]),                     // server_name_list len
    Buffer.from([0x00]),                           // name_type host_name
    Buffer.from([(host.length >> 8) & 0xff, host.length & 0xff]),
    host,
  ]);
  sniExt.writeUInt16BE(sniExt.length - 4, 2);
  sniExt.writeUInt16BE(sniExt.length - 7, 4);
  const body = Buffer.concat([
    Buffer.from([0x03, 0x03]),                     // version
    Buffer.alloc(32, 0x11),                        // random
    Buffer.from([0x00]),                           // session id len
    Buffer.from([0x00, 0x02, 0x13, 0x01]),         // cipher suites
    Buffer.from([0x01, 0x00]),                     // compression
    Buffer.from([(sniExt.length >> 8) & 0xff, sniExt.length & 0xff]),
    sniExt,
  ]);
  const hs = Buffer.concat([Buffer.from([0x01]), Buffer.from([(body.length >> 8) & 0xff, body.length & 0xff, 0x00]), body]);
  const rec = Buffer.concat([Buffer.from([0x16, 0x03, 0x01, (hs.length >> 8) & 0xff, hs.length & 0xff]), hs]);

  const tcp = Buffer.alloc(20 + rec.length);
  tcp.writeUInt16BE(50000, 0);    // sport
  tcp.writeUInt16BE(443, 2);      // dport
  tcp.writeUInt32BE(1, 4);        // seq
  tcp.writeUInt32BE(0, 8);        // ack
  tcp[12] = 0x50;                 // data offset 5
  tcp[13] = 0x18;                 // PSH+ACK
  rec.copy(tcp, 20);

  const ip = Buffer.alloc(20 + tcp.length);
  ip[0] = 0x45; ip[9] = 6;
  ip.writeUInt16BE(ip.length, 2);
  ip.writeUInt16BE(0x1234, 4);
  ip.writeUInt32BE(0x0a000001, 12);  // 10.0.0.1
  ip.writeUInt32BE(0x0a000002, 16);  // 10.0.0.2
  tcp.copy(ip, 20);

  const eth = Buffer.alloc(14 + ip.length);
  Buffer.from([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]).copy(eth, 0);
  Buffer.from([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]).copy(eth, 6);
  eth.writeUInt16BE(0x0800, 12);
  ip.copy(eth, 14);
  return eth;
}

/** Build an Ethernet + IPv4 + UDP + DNS query frame. */
function ethDns(name) {
  const labels = name.split('.').map((l) => Buffer.from(l, 'latin1'));
  const qname = Buffer.concat([
    ...labels.map((l) => Buffer.concat([Buffer.from([l.length]), l])),
    Buffer.from([0x00]),
  ]);
  const dns = Buffer.concat([
    Buffer.from([0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
    qname,
    Buffer.from([0x00, 0x01, 0x00, 0x01]),  // type A, class IN
  ]);
  const udp = Buffer.alloc(8 + dns.length);
  udp.writeUInt16BE(5353, 0);
  udp.writeUInt16BE(53, 2);
  udp.writeUInt16BE(udp.length, 4);
  dns.copy(udp, 8);

  const ip = Buffer.alloc(20 + udp.length);
  ip[0] = 0x45; ip[9] = 17;
  ip.writeUInt16BE(ip.length, 2);
  ip.writeUInt32BE(0x0a000001, 12);
  ip.writeUInt32BE(0x08080808, 16);  // 8.8.8.8
  udp.copy(ip, 20);

  const eth = Buffer.alloc(14 + ip.length);
  eth.writeUInt16BE(0x0800, 12);
  ip.copy(eth, 14);
  return eth;
}

/** Build a pcapng file from a list of frame buffers. */
function buildPcapng(frames) {
  const blocks = [];
  // Section Header Block
  const shbBody = Buffer.alloc(16);
  shbBody.writeUInt32LE(0x1a2b3c4d, 0);   // byte-order magic
  shbBody.writeUInt16LE(1, 4);            // version major
  shbBody.writeUInt16LE(0, 6);            // version minor
  shbBody.writeUInt32LE(1, 12);           // link type = Ethernet
  const shb = Buffer.concat([
    Buffer.from([0x0a, 0x0d, 0x0d, 0x0a]),
    Buffer.from([0, 0, 0, 0]),            // total len placeholder
    shbBody,
  ]);
  const shbPad = (4 - (shb.length % 4)) % 4;
  const shbTotal = shb.length + shbPad + 4;
  const shbOut = Buffer.concat([shb, Buffer.alloc(shbPad), bufLen(shbTotal)]);
  shbOut.writeUInt32LE(shbTotal, 4);
  blocks.push(shbOut);

  for (const f of frames) {
    const pad = (4 - (f.length % 4)) % 4;
    const total = 32 + f.length + pad;
    const hdr = Buffer.alloc(28);
    hdr.writeUInt32LE(0x00000006, 0);     // Enhanced Packet Block
    hdr.writeUInt32LE(total, 4);
    hdr.writeUInt32LE(0, 8);              // interface id
    hdr.writeUInt32LE(0x0000ffff, 12);    // ts high
    hdr.writeUInt32LE(0x00000001, 16);    // ts low (microseconds)
    hdr.writeUInt32LE(f.length, 20);      // captured len
    hdr.writeUInt32LE(f.length, 24);      // original len
    blocks.push(Buffer.concat([hdr, f, Buffer.alloc(pad), bufLen(total)]));
  }
  return Buffer.concat(blocks);
}

function bufLen(n) {
  const b = Buffer.alloc(4);
  b.writeUInt32LE(n, 0);
  return b;
}

// ---- tests ----

const sni = 'api.example.com';
const dnsName = 'tracker.test.local';
const pcapng = buildPcapng([ethTcp(sni), ethDns(dnsName), ethTcp(sni)]);

const parsed = parseCapture(pcapng);
assert.equal(parsed.meta.packets, 3, `应解析出 3 个包，实际 ${parsed.meta.packets}`);
assert.equal(parsed.meta.tcpPackets, 2, '两个 TCP 包');
assert.equal(parsed.meta.udpPackets, 1, '一个 UDP 包');
assert.equal(parsed.meta.format, 'pcapng', '应识别为 pcapng');

const snis = parsed.sni.map((s) => s.name);
assert.ok(snis.includes(sni), `SNI 应包含 ${sni}，实际 ${JSON.stringify(snis)}`);
assert.equal(parsed.sni.find((s) => s.name === sni).count, 2, 'SNI 应出现两次');

const dnsNames = parsed.dns.map((d) => d.name);
assert.ok(dnsNames.includes(dnsName), `DNS 应包含 ${dnsName}，实际 ${JSON.stringify(dnsNames)}`);
assert.equal(DNS_TYPES[1], 'A', 'DNS 类型表应含 A');

assert.ok(parsed.topPorts.some((p) => p.port === 443), 'top ports 应含 443');
assert.ok(parsed.talkers.length >= 2, '应至少两条会话');
assert.ok(parsed.talkers.every((t) => t.src && t.dst), '会话必须有源与目的');

// Malformed input must fail loudly, not silently return empty results.
assert.throws(() => parseCapture(Buffer.from([0x00, 0x01, 0x02, 0x03])), /无法识别|太小/, '无效输入应抛错');
assert.throws(() => parseCapture(Buffer.alloc(2)), /太小/, '过短输入应抛错');

// A truncated pcapng should still yield the packets it contains and report it.
const truncated = pcapng.subarray(0, pcapng.length - 20);
const t = parseCapture(truncated);
assert.ok(t.meta.packets >= 2, `截断文件应仍解析出部分包，实际 ${t.meta.packets}`);
assert.ok(t.stats.truncated >= 1, '应记录截断');

console.log('selftest 通过：');
console.log(`  包 ${parsed.meta.packets} | TCP ${parsed.meta.tcpPackets} | UDP ${parsed.meta.udpPackets}`);
console.log(`  SNI: ${snis.join(', ')}`);
console.log(`  DNS: ${dnsNames.join(', ')}`);
console.log(`  端口: ${parsed.topPorts.map((p) => p.port).join(', ')}`);
console.log(`  截断用例: 包 ${t.meta.packets}, truncated=${t.stats.truncated}`);
