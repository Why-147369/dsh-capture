/**
 * dsh-capture: pcapng / pcap parser (dependency-free).
 *
 * Parses both classic .pcap and .pcapng (what `pktmon etl2pcap` emits), then
 * extracts packet-level facts: Ethernet/IP/IPv6/TCP/UDP/ICMP, DNS queries,
 * TLS SNI, and HTTP/1.x request lines when they happen to be plaintext.
 *
 * Design notes:
 *  - Everything is byte-buffer arithmetic on the input file; no native deps.
 *  - Only regular files are read; paths are validated by the caller.
 *  - The parser is deliberately lossy-safe: unknown blocks, truncated
 *    packets, and unsupported link types are skipped and counted rather than
 *    throwing, so a partially written capture still yields results.
 */

const PCAP_MAGIC_LE = 0xa1b2c3d4;
const PCAP_MAGIC_BE = 0xd4c3b2a1;
const PCAPNG_SHB = 0x0a0d0d0a;

const LINKTYPE_ETHERNET = 1;
const LINKTYPE_RAW = 101;
const LINKTYPE_LINUX_SLL = 113;
const LINKTYPE_LINUX_SLL2 = 276;

/** EtherTypes we care about. */
const ETH_IPV4 = 0x0800;
const ETH_IPV6 = 0x86dd;
const ETH_ARP = 0x0806;

const IPPROTO_TCP = 6;
const IPPROTO_UDP = 17;
const IPPROTO_ICMP = 1;
const IPPROTO_ICMPV6 = 58;

/**
 * Format a MAC address.
 * @param {Buffer} buf
 * @param {number} off
 * @returns {string}
 */
function mac(buf, off) {
  const parts = [];
  for (let i = 0; i < 6; i++) parts.push(buf[off + i].toString(16).padStart(2, '0'));
  return parts.join(':');
}

/**
 * Format an IPv4 address.
 * @param {Buffer} buf
 * @param {number} off
 * @returns {string}
 */
function ipv4(buf, off) {
  return `${buf[off]}.${buf[off + 1]}.${buf[off + 2]}.${buf[off + 3]}`;
}

/**
 * Format an IPv6 address with :: compression.
 * @param {Buffer} buf
 * @param {number} off
 * @returns {string}
 */
function ipv6(buf, off) {
  const hextets = [];
  for (let i = 0; i < 8; i++) hextets.push(buf.readUInt16BE(off + i * 2));
  // Find the longest run of zeros to compress.
  let bestStart = -1;
  let bestLen = 0;
  let runStart = -1;
  for (let i = 0; i <= 8; i++) {
    if (i < 8 && hextets[i] === 0) {
      if (runStart < 0) runStart = i;
    } else if (runStart >= 0) {
      const len = i - runStart;
      if (len > bestLen) { bestLen = len; bestStart = runStart; }
      runStart = -1;
    }
  }
  if (bestLen < 2) return hextets.map((h) => h.toString(16)).join(':');
  const head = hextets.slice(0, bestStart).map((h) => h.toString(16));
  const tail = hextets.slice(bestStart + bestLen).map((h) => h.toString(16));
  return `${head.join(':')}::${tail.join(':')}`;
}

/**
 * Decode a DNS name from its label-length encoding.
 * @param {Buffer} buf
 * @param {number} off
 * @returns {{name: string, next: number}}
 */
function dnsName(buf, off) {
  const labels = [];
  let pos = off;
  let jumped = false;
  let guard = 0;
  // A pointer may jump once; guard against loops in malformed captures.
  while (pos < buf.length && guard++ < 64) {
    const len = buf[pos];
    if (len === 0) { pos++; if (!jumped) off = pos; break; }
    if ((len & 0xc0) === 0xc0) {
      if (pos + 1 >= buf.length) break;
      const ptr = ((len & 0x3f) << 8) | buf[pos + 1];
      if (!jumped) off = pos + 2;
      jumped = true;
      pos = ptr;
      continue;
    }
    if (pos + 1 + len > buf.length) break;
    labels.push(buf.toString('latin1', pos + 1, pos + 1 + len));
    pos += 1 + len;
    if (!jumped) off = pos;
  }
  return { name: labels.join('.'), next: off };
}

/**
 * Try to pull an HTTP request line out of a TCP payload.
 * @param {Buffer} payload
 * @returns {{method: string, path: string, host: string|null} | null}
 */
function httpRequest(payload) {
  if (payload.length < 8) return null;
  const text = payload.toString('latin1', 0, Math.min(payload.length, 2048));
  const m = /^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|TRACE) (\S+) HTTP\/1\.[01]\r\n/.exec(text);
  if (!m) return null;
  const hostMatch = /\r\nHost: ([^\r\n]+)/i.exec(text);
  return { method: m[1], path: m[2], host: hostMatch ? hostMatch[1].trim() : null };
}

/**
 * Try to pull an HTTP response status line out of a TCP payload.
 * @param {Buffer} payload
 * @returns {{status: number, reason: string} | null}
 */
function httpResponse(payload) {
  if (payload.length < 12) return null;
  const text = payload.toString('latin1', 0, Math.min(payload.length, 256));
  const m = /^HTTP\/1\.[01] (\d{3}) ?([^\r\n]*)\r\n/.exec(text);
  if (!m) return null;
  return { status: Number(m[1]), reason: m[2].trim() };
}

/**
 * Extract TLS SNI (and record version) from a ClientHello.
 * @param {Buffer} payload
 * @returns {string|null}
 */
function tlsSni(payload) {
  // TLS record: type 22 (handshake), then handshake type 1 (ClientHello).
  if (payload.length < 5 || payload[0] !== 0x16) return null;
  if (payload.length < 9) return null;
  if (payload[5] !== 0x01) return null;
  // Skip: record hdr(5) + hs type(1) + length(3) + version(2) + random(32)
  let p = 5 + 4 + 2 + 32;
  if (p >= payload.length) return null;
  const sidLen = payload[p]; p += 1 + sidLen;
  if (p + 2 > payload.length) return null;
  const csLen = payload.readUInt16BE(p); p += 2 + csLen;
  if (p + 1 > payload.length) return null;
  const compLen = payload[p]; p += 1 + compLen;
  if (p + 2 > payload.length) return null;
  const extTotal = payload.readUInt16BE(p); p += 2;
  const end = Math.min(payload.length, p + extTotal);
  while (p + 4 <= end) {
    const type = payload.readUInt16BE(p);
    const len = payload.readUInt16BE(p + 2);
    if (type === 0x0000 && p + 4 + len <= payload.length) {
      // server_name list: list len(2), entry type(1), entry len(2), name
      const base = p + 4;
      if (base + 5 <= payload.length && payload[base + 2] === 0x00) {
        const nlen = payload.readUInt16BE(base + 3);
        if (base + 5 + nlen <= payload.length) {
          return payload.toString('latin1', base + 5, base + 5 + nlen);
        }
      }
    }
    p += 4 + len;
  }
  return null;
}

/**
 * Parse an Ethernet frame into transport facts.
 * @param {Buffer} frame
 * @returns {object|null}
 */
function parseEthernet(frame) {
  if (frame.length < 14) return null;
  let off = 12;
  let etherType = frame.readUInt16BE(off); off += 2;
  // Skip stacked VLAN tags.
  let guard = 0;
  while ((etherType === 0x8100 || etherType === 0x88a8) && guard++ < 4) {
    if (off + 4 > frame.length) return null;
    etherType = frame.readUInt16BE(off + 2);
    off += 4;
  }
  const out = {
    srcMac: mac(frame, 6),
    dstMac: mac(frame, 0),
  };
  if (etherType === ETH_ARP) {
    out.proto = 'ARP';
    return out;
  }
  if (etherType === ETH_IPV4) {
    return { ...out, ...parseIPv4(frame, off) };
  }
  if (etherType === ETH_IPV6) {
    return { ...out, ...parseIPv6(frame, off) };
  }
  out.proto = `ETH-0x${etherType.toString(16)}`;
  return out;
}

/**
 * Parse an IPv4 datagram.
 * @param {Buffer} buf
 * @param {number} off
 * @returns {object|null}
 */
function parseIPv4(buf, off) {
  if (off + 20 > buf.length) return null;
  const ihl = (buf[off] & 0x0f) * 4;
  if (ihl < 20 || off + ihl > buf.length) return null;
  const proto = buf[off + 9];
  const src = ipv4(buf, off + 12);
  const dst = ipv4(buf, off + 16);
  const totalLen = buf.readUInt16BE(off + 2);
  const payloadOff = off + ihl;
  const payloadEnd = Math.min(buf.length, off + (totalLen > 0 ? totalLen : buf.length - off));
  return parseTransport(buf, payloadOff, payloadEnd, proto, src, dst, 'IPv4');
}

/**
 * Parse an IPv6 datagram.
 * @param {Buffer} buf
 * @param {number} off
 * @returns {object|null}
 */
function parseIPv6(buf, off) {
  if (off + 40 > buf.length) return null;
  let proto = buf[off + 6];
  const src = ipv6(buf, off + 8);
  const dst = ipv6(buf, off + 24);
  let p = off + 40;
  // Walk the (bounded) extension header chain to the transport header.
  let guard = 0;
  while (guard++ < 8) {
    if (proto === 0 || proto === 43 || proto === 60) {
      if (p + 8 > buf.length) return null;
      const nxt = buf[p];
      const hlen = (buf[p + 1] + 1) * 8;
      proto = nxt;
      p += hlen;
      continue;
    }
    if (proto === 44) { // Fragment header
      if (p + 8 > buf.length) return null;
      proto = buf[p];
      p += 8;
      continue;
    }
    break;
  }
  return parseTransport(buf, p, buf.length, proto, src, dst, 'IPv6');
}

/**
 * Parse TCP/UDP/ICMP given the payload window.
 * @param {Buffer} buf
 * @param {number} start
 * @param {number} end
 * @param {number} proto
 * @param {string} src
 * @param {string} dst
 * @param {string} family
 * @returns {object}
 */
function parseTransport(buf, start, end, proto, src, dst, family) {
  const base = { family, src, dst, proto };
  if (proto === IPPROTO_TCP) {
    if (start + 20 > buf.length) return { ...base, proto: 'TCP', truncated: true };
    const sport = buf.readUInt16BE(start);
    const dport = buf.readUInt16BE(start + 2);
    const doff = (buf[start + 12] >> 4) * 4;
    const flags = buf[start + 13];
    const payloadStart = start + Math.max(20, doff);
    const payload = buf.subarray(Math.min(payloadStart, buf.length), Math.min(end, buf.length));
    const tcp = {
      ...base, proto: 'TCP', sport, dport,
      seq: buf.readUInt32BE(start + 4),
      ack: buf.readUInt32BE(start + 8),
      flags: { syn: !!(flags & 0x02), ack: !!(flags & 0x10), fin: !!(flags & 0x01), rst: !!(flags & 0x04), psh: !!(flags & 0x08) },
      payloadLen: payload.length,
    };
    if (payload.length) {
      const sni = tlsSni(payload);
      if (sni) tcp.sni = sni;
      const req = httpRequest(payload);
      if (req) tcp.http = req;
      else {
        const res = httpResponse(payload);
        if (res) tcp.http = res;
      }
    }
    return tcp;
  }
  if (proto === IPPROTO_UDP) {
    if (start + 8 > buf.length) return { ...base, proto: 'UDP', truncated: true };
    const sport = buf.readUInt16BE(start);
    const dport = buf.readUInt16BE(start + 2);
    const payload = buf.subarray(Math.min(start + 8, buf.length), Math.min(end, buf.length));
    const udp = { ...base, proto: 'UDP', sport, dport, payloadLen: payload.length };
    // DNS over UDP port 53.
    if (sport === 53 || dport === 53) {
      const q = parseDns(payload);
      if (q) udp.dns = q;
    }
    return udp;
  }
  if (proto === IPPROTO_ICMP || proto === IPPROTO_ICMPV6) {
    return { ...base, proto: proto === IPPROTO_ICMP ? 'ICMP' : 'ICMPv6' };
  }
  return { ...base, proto: `IP-${proto}` };
}

/**
 * Parse a DNS message header and first question.
 * @param {Buffer} payload
 * @returns {{id:number, qr:number, queries:Array<{name:string,type:number}>, answers:number}|null}
 */
function parseDns(payload) {
  if (payload.length < 12) return null;
  const id = payload.readUInt16BE(0);
  const flags = payload.readUInt16BE(2);
  const qr = (flags >> 15) & 1;
  const qdcount = payload.readUInt16BE(4);
  const ancount = payload.readUInt16BE(6);
  // Cap the question walk: a hostile capture could claim thousands.
  const queries = [];
  let p = 12;
  for (let i = 0; i < Math.min(qdcount, 8); i++) {
    const { name, next } = dnsName(payload, p);
    if (!next || next + 4 > payload.length) break;
    const type = payload.readUInt16BE(next);
    queries.push({ name, type });
    p = next + 4;
  }
  if (!queries.length && !qdcount) return { id, qr, queries: [], answers: ancount };
  if (!queries.length) return null;
  return { id, qr, queries, answers: ancount };
}

/**
 * Parse a whole capture file into packets.
 * @param {Buffer} buf
 * @param {{maxPackets?: number}} [opts]
 * @returns {object} capture summary
 */
export function parseCapture(buf, opts = {}) {
  const maxPackets = Number.isFinite(opts.maxPackets) ? opts.maxPackets : 200000;
  if (buf.length < 4) throw new Error('文件太小，不是有效的抓包文件（需至少 4 字节）');

  const first = buf.readUInt32LE(0);
  if (first === PCAPNG_SHB || buf.readUInt32BE(0) === PCAPNG_SHB) {
    return parsePcapng(buf, maxPackets);
  }
  if (first === PCAP_MAGIC_LE || first === PCAP_MAGIC_BE) {
    return parsePcapClassic(buf, maxPackets);
  }
  throw new Error('无法识别的抓包格式（既不是 pcap 也不是 pcapng）');
}

/**
 * Classic libpcap format.
 * @param {Buffer} buf
 * @param {number} maxPackets
 * @returns {object}
 */
function parsePcapClassic(buf, maxPackets) {
  const le = buf.readUInt32LE(0) === PCAP_MAGIC_LE;
  const readU32 = (o) => (le ? buf.readUInt32LE(o) : buf.readUInt32BE(o));
  const readU16 = (o) => (le ? buf.readUInt16LE(o) : buf.readUInt16BE(o));
  const linkType = readU32(20);
  let off = 24;
  const packets = [];
  const stats = { malformed: 0, truncated: 0, unsupportedLink: 0 };
  // Very large snaplen values indicate a corrupt header; bail early.
  while (off + 16 <= buf.length && packets.length < maxPackets) {
    const tsSec = readU32(off);
    const inclLen = readU32(off + 8);
    const origLen = readU32(off + 12);
    off += 16;
    if (inclLen > buf.length - off) { stats.truncated++; break; }
    const data = buf.subarray(off, off + inclLen);
    const pkt = decodeByLinkType(data, linkType, tsSec, stats);
    if (pkt) packets.push(pkt);
    off += inclLen;
  }
  return assemble(packets, stats, { format: 'pcap', linkType, truncatedOrig: 0 });
}

/**
 * pcapng format (what `pktmon etl2pcap` writes).
 * @param {Buffer} buf
 * @param {number} maxPackets
 * @returns {object}
 */
function parsePcapng(buf, maxPackets) {
  // Every section has its own endianness; the SHB magic tells us which.
  let off = 0;
  const packets = [];
  const stats = { malformed: 0, truncated: 0, unsupportedLink: 0, blocks: 0 };
  const linkTypes = [];

  while (off + 12 <= buf.length && packets.length < maxPackets) {
    const blockType = buf.readUInt32LE(off);
    if (blockType === PCAPNG_SHB) {
      const bom = buf.readUInt32LE(off + 8);
      const le = bom === 0x1a2b3c4d;
      // Verify trailer matches (structural sanity check).
      const totalLen = le ? buf.readUInt32LE(off + 4) : buf.readUInt32BE(off + 4);
      if (!Number.isFinite(totalLen) || totalLen < 12 || off + totalLen > buf.length) {
        stats.truncated++;
        break;
      }
      const linkType = le ? buf.readUInt32LE(off + 20) : buf.readUInt32BE(off + 20);
      if (off + 24 <= buf.length) linkTypes.push(linkType);
      stats.blocks++;
      off += totalLen;
      continue;
    }
    // For non-SHB blocks we must use the endianness of the last SHB. pktmon
    // writes little-endian, which is also the only writer we support.
    const le = true;
    const totalLen = le ? buf.readUInt32LE(off + 4) : buf.readUInt32BE(off + 4);
    if (!Number.isFinite(totalLen) || totalLen < 12 || off + totalLen > buf.length) {
      stats.truncated++;
      break;
    }
    if (blockType === 0x00000006) { // Enhanced Packet Block
      const capLen = buf.readUInt32LE(off + 20);
      const linkType = linkTypes[linkTypes.length - 1] ?? LINKTYPE_ETHERNET;
      const dataStart = off + 28;
      if (capLen > totalLen - 32 || dataStart + capLen > buf.length) {
        stats.truncated++;
        off += totalLen;
        continue;
      }
      const data = buf.subarray(dataStart, dataStart + capLen);
      const tsHigh = buf.readUInt32LE(off + 12);
      const tsLow = buf.readUInt32LE(off + 16);
      // Default resolution in pktmon output is microseconds.
      const tsSec = (tsHigh * 4294967296 + tsLow) / 1e6;
      const pkt = decodeByLinkType(data, linkType, tsSec, stats);
      if (pkt) packets.push(pkt);
      stats.blocks++;
    } else if (blockType === 0x00000003) { // Simple Packet Block
      const linkType = linkTypes[linkTypes.length - 1] ?? LINKTYPE_ETHERNET;
      const origLen = buf.readUInt32LE(off + 8);
      const dataStart = off + 12;
      const capLen = Math.min(origLen, totalLen - 16);
      if (dataStart + capLen <= buf.length) {
        const pkt = decodeByLinkType(buf.subarray(dataStart, dataStart + capLen), linkType, 0, stats);
        if (pkt) packets.push(pkt);
      }
      stats.blocks++;
    } else if (blockType === 0x00000001 || blockType === 0x00000005 || blockType === 0x00000004) {
      // Interface Description / Interface Statistics / Name Resolution: skip.
      stats.blocks++;
    } else {
      stats.blocks++;
    }
    off += totalLen;
  }
  return assemble(packets, stats, { format: 'pcapng', linkType: linkTypes[linkTypes.length - 1] ?? null });
}

/**
 * Decode a link-layer frame according to its link type.
 * @param {Buffer} data
 * @param {number} linkType
 * @param {number} tsSec
 * @param {object} stats
 * @returns {object|null}
 */
function decodeByLinkType(data, linkType, tsSec, stats) {
  let decoded = null;
  if (linkType === LINKTYPE_ETHERNET) {
    decoded = parseEthernet(data);
  } else if (linkType === LINKTYPE_RAW) {
    // Raw IP: first nibble decides v4 vs v6.
    const version = data.length ? (data[0] >> 4) : 0;
    if (version === 4) decoded = parseIPv4(data, 0);
    else if (version === 6) decoded = parseIPv6(data, 0);
  } else if (linkType === LINKTYPE_LINUX_SLL) {
    if (data.length > 16) {
      const proto = data.readUInt16BE(14);
      if (proto === ETH_IPV4) decoded = parseIPv4(data, 16);
      else if (proto === ETH_IPV6) decoded = parseIPv6(data, 16);
    }
  } else if (linkType === LINKTYPE_LINUX_SLL2) {
    if (data.length > 20) {
      const proto = data.readUInt16BE(0);
      if (proto === ETH_IPV4) decoded = parseIPv4(data, 20);
      else if (proto === ETH_IPV6) decoded = parseIPv6(data, 20);
    }
  } else {
    stats.unsupportedLink++;
    return null;
  }
  if (!decoded) { stats.malformed++; return null; }
  decoded.ts = tsSec;
  decoded.bytes = data.length;
  return decoded;
}

/**
 * Fold decoded packets into capture-level stats and derived flows.
 * @param {Array<object>} packets
 * @param {object} stats
 * @param {object} meta
 * @returns {object}
 */
function assemble(packets, stats, meta) {
  const talkers = new Map();
  const ports = new Map();
  const dns = [];
  const sni = new Map();
  const http = [];
  let tcpPackets = 0, udpPackets = 0, bytes = 0;
  const firstTs = packets.length ? packets[0].ts : null;
  const lastTs = packets.length ? packets[packets.length - 1].ts : null;

  for (const p of packets) {
    bytes += p.bytes || 0;
    if (p.proto === 'TCP') {
      tcpPackets++;
      if (p.dport) ports.set(p.dport, (ports.get(p.dport) || 0) + 1);
      if (p.sni) sni.set(p.sni, (sni.get(p.sni) || 0) + 1);
      if (p.http) {
        http.push({
          ts: p.ts, src: p.src, dst: p.dst, sport: p.sport, dport: p.dport,
          ...(p.http.request_line !== undefined ? {} : {}),
          method: p.http.method, path: p.http.path, host: p.http.host,
          status: p.http.status, reason: p.http.reason,
        });
      }
    } else if (p.proto === 'UDP') {
      udpPackets++;
      if (p.dns) {
        for (const q of p.dns.queries) {
          dns.push({ ts: p.ts, src: p.src, dst: p.dst, name: q.name, type: q.type, answers: p.dns.answers });
        }
      }
    }
    if (p.src && p.dst) {
      const key = `${p.src} -> ${p.dst}`;
      const cur = talkers.get(key) || { src: p.src, dst: p.dst, packets: 0, bytes: 0 };
      cur.packets++;
      cur.bytes += p.bytes || 0;
      talkers.set(key, cur);
    }
  }

  return {
    meta: { ...meta, packets: packets.length, bytes, tcpPackets, udpPackets, firstTs, lastTs },
    stats,
    talkers: [...talkers.values()].sort((a, b) => b.bytes - a.bytes).slice(0, 100),
    topPorts: [...ports.entries()].map(([port, count]) => ({ port, count })).sort((a, b) => b.count - a.count).slice(0, 50),
    dns,
    sni: [...sni.entries()].map(([name, count]) => ({ name, count })).sort((a, b) => b.count - a.count),
    http,
    packets,
  };
}

/** DNS type names for display. */
export const DNS_TYPES = {
  1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR', 15: 'MX', 16: 'TXT',
  28: 'AAAA', 33: 'SRV', 41: 'OPT', 43: 'DS', 46: 'RRSIG', 65: 'HTTPS', 255: 'ANY',
};
