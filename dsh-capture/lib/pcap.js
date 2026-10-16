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

/** Common TLS cipher suites, for readable output. */
const TLS_CIPHERS = {
  0x1301: 'TLS_AES_128_GCM_SHA256',
  0x1302: 'TLS_AES_256_GCM_SHA384',
  0x1303: 'TLS_CHACHA20_POLY1305_SHA256',
  0x1304: 'TLS_AES_128_CCM_SHA256',
  0x1305: 'TLS_AES_128_CCM_8_SHA256',
  0xc02b: 'ECDHE_ECDSA_AES128_GCM_SHA256',
  0xc02c: 'ECDHE_ECDSA_AES256_GCM_SHA384',
  0xc02f: 'ECDHE_RSA_AES128_GCM_SHA256',
  0xc030: 'ECDHE_RSA_AES256_GCM_SHA384',
  0xcca8: 'ECDHE_RSA_CHACHA20_POLY1305',
  0xcca9: 'ECDHE_ECDSA_CHACHA20_POLY1305',
  0x009c: 'RSA_AES128_GCM_SHA256',
  0x009d: 'RSA_AES256_GCM_SHA384',
  0x002f: 'RSA_AES128_SHA',
  0x0035: 'RSA_AES256_SHA',
};

/** TLS version names, keyed by the two-byte wire value. */
const TLS_VERSIONS = {
  0x0300: 'SSL 3.0',
  0x0301: 'TLS 1.0',
  0x0302: 'TLS 1.1',
  0x0303: 'TLS 1.2',
  0x0304: 'TLS 1.3',
};

/** TLS extension names we surface explicitly. */
const TLS_EXT_NAMES = {
  0x0000: 'server_name',
  0x000a: 'supported_groups',
  0x000b: 'ec_point_formats',
  0x000d: 'signature_algorithms',
  0x0010: 'application_layer_protocol_negotiation',
  0x0017: 'extended_master_secret',
  0x001b: 'certificate_authorities',
  0x0023: 'session_ticket',
  0x002b: 'supported_versions',
  0x002d: 'psk_key_exchange_modes',
  0x0033: 'key_share',
  0x002a: 'early_data',
  0x0029: 'pre_shared_key',
  0x0005: 'status_request',
  0x0012: 'signed_certificate_timestamp',
  0x001c: 'record_size_limit',
  0xff01: 'renegotiation_info',
};

/**
 * Format a cipher suite id.
 * @param {number} id
 * @returns {string}
 */
function cipherName(id) {
  return TLS_CIPHERS[id] || `0x${id.toString(16).padStart(4, '0')}`;
}

/**
 * Format a TLS version wire value.
 * @param {number} v
 * @returns {string}
 */
function versionName(v) {
  return TLS_VERSIONS[v] || `0x${v.toString(16).padStart(4, '0')}`;
}

/**
 * Parse a TLS ClientHello.
 *
 * Returns record version, advertised client version, SNI, the offered cipher
 * suites (bounded) and the extension ids present. All reads are bounds-checked
 * because the payload may be truncated by snaplen.
 *
 * @param {Buffer} payload
 * @returns {object|null}
 */
function tlsClientHello(payload) {
  // TLS record: content type 22 (handshake) + version(2) + length(2).
  if (payload.length < 9) return null;
  if (payload[0] !== 0x16) return null;
  const recordVersion = payload.readUInt16BE(1);
  if (payload[5] !== 0x01) return null;
  // hs len(3) @6, client version(2) @9, random(32) @11
  let p = 9;
  const clientVersion = payload.readUInt16BE(p); p += 2;
  p += 32; // random
  if (p >= payload.length) return null;
  const sidLen = payload[p]; p += 1 + sidLen;
  if (p + 2 > payload.length) return null;
  const csLen = payload.readUInt16BE(p); p += 2;
  const csEnd = Math.min(payload.length, p + csLen);
  const cipherSuites = [];
  for (let q = p; q + 1 < csEnd && cipherSuites.length < 32; q += 2) {
    cipherSuites.push(cipherName(payload.readUInt16BE(q)));
  }
  p = csEnd;
  if (p + 1 > payload.length) return null;
  const compLen = payload[p]; p += 1 + compLen;
  if (p + 2 > payload.length) {
    return { recordVersion, recordVersionName: versionName(recordVersion), clientVersion, clientVersionName: versionName(clientVersion), sni: null, cipherSuites, extensions: [], truncated: true };
  }
  const extTotal = payload.readUInt16BE(p); p += 2;
  const end = Math.min(payload.length, p + extTotal);
  let sni = null;
  let supportedVersions = [];
  const extensions = [];
  while (p + 4 <= end) {
    const type = payload.readUInt16BE(p);
    const len = payload.readUInt16BE(p + 2);
    const body = p + 4;
    extensions.push(TLS_EXT_NAMES[type] || `0x${type.toString(16).padStart(4, '0')}`);
    if (type === 0x0000 && body + 5 <= payload.length) {
      // server_name list: list len(2), entry type(1), entry len(2), name
      if (payload[body + 2] === 0x00) {
        const nlen = payload.readUInt16BE(body + 3);
        if (body + 5 + nlen <= payload.length) {
          sni = payload.toString('latin1', body + 5, body + 5 + nlen);
        }
      }
    } else if (type === 0x002b && body + 1 <= payload.length) {
      // supported_versions: list len(1) + 2-byte versions
      const vLen = payload[body];
      const vEnd = Math.min(payload.length, body + 1 + vLen);
      for (let q = body + 1; q + 1 < vEnd; q += 2) supportedVersions.push(versionName(payload.readUInt16BE(q)));
    }
    p = body + len;
  }
  return {
    recordVersion,
    recordVersionName: versionName(recordVersion),
    clientVersion,
    clientVersionName: versionName(clientVersion),
    supportedVersions,
    sni,
    cipherSuites,
    extensions,
    truncated: false,
  };
}

/**
 * Parse a TLS ServerHello to recover the negotiated version and cipher suite.
 * Only plaintext (non-encrypted) handshakes are visible, i.e. the first flight.
 * @param {Buffer} payload
 * @returns {object|null}
 */
function tlsServerHello(payload) {
  if (payload.length < 11) return null;
  if (payload[0] !== 0x16) return null;
  if (payload[5] !== 0x02) return null;
  let p = 9;
  const serverVersion = payload.readUInt16BE(p); p += 2;
  p += 32; // random
  if (p >= payload.length) return null;
  const sidLen = payload[p]; p += 1 + sidLen;
  if (p + 3 > payload.length) return null;
  const cipher = payload.readUInt16BE(p);
  // TLS 1.3 pins the real version in the supported_versions extension; scan for it.
  let negotiated = null;
  const extSearchStart = p + 2;
  for (let q = extSearchStart; q + 4 <= payload.length; q++) {
    if (payload.readUInt16BE(q) === 0x002b && payload.readUInt16BE(q + 2) === 2 && q + 6 <= payload.length) {
      negotiated = payload.readUInt16BE(q + 4);
      break;
    }
  }
  const v = negotiated ?? serverVersion;
  return {
    serverVersion,
    serverVersionName: versionName(serverVersion),
    negotiatedVersion: v,
    negotiatedVersionName: versionName(v),
    cipherSuite: cipherName(cipher),
    cipherSuiteId: `0x${cipher.toString(16).padStart(4, '0')}`,
  };
}

/**
 * Backwards-compatible SNI-only helper.
 * @param {Buffer} payload
 * @returns {string|null}
 */
function tlsSni(payload) {
  const hello = tlsClientHello(payload);
  return hello ? hello.sni : null;
}

/**
 * Read the `if_tsresol` option (code 9) from an Interface Description Block.
 *
 * The option value is one byte: if the high bit is clear, the remaining bits
 * are a power of ten (6 = microseconds, 9 = nanoseconds); if the high bit is
 * set, the remaining bits are a power of two. Missing option means the spec
 * default of microseconds.
 *
 * @param {Buffer} buf
 * @param {number} start first option byte (right after snaplen)
 * @param {number} end end of the block body (before the trailing length)
 * @returns {number} timestamp units per second
 */
function readTsResolution(buf, start, end) {
  let p = start;
  // Bound the walk: a hostile capture could otherwise loop forever.
  let guard = 0;
  while (p + 4 <= end && guard++ < 64) {
    const code = buf.readUInt16LE(p);
    const len = buf.readUInt16LE(p + 2);
    if (code === 0) break; // opt_endofopt
    if (p + 4 + len > end) break;
    if (code === 9 && len >= 1) {
      const raw = buf[p + 4];
      if (raw & 0x80) {
        // Power of two.
        const exp = raw & 0x7f;
        return exp < 64 ? Math.pow(2, exp) : 1e6;
      }
      const exp = raw;
      return exp <= 18 ? Math.pow(10, exp) : 1e6;
    }
    // Options are padded to a 4-byte boundary.
    p += 4 + len + ((4 - (len % 4)) % 4);
  }
  return 1e6; // pcapng default: microseconds
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
      // Kept for the reassembly pass; decodeByLinkType turns this into a
      // non-enumerable property so it never reaches JSON output.
      payload,
    };
    if (payload.length) {
      const hello = tlsClientHello(payload);
      if (hello) {
        tcp.tls = { ...hello, role: 'client' };
        if (hello.sni) tcp.sni = hello.sni;
      } else {
        const sh = tlsServerHello(payload);
        if (sh) tcp.tls = { ...sh, role: 'server' };
      }
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
    return parsePcapng(buf, maxPackets, opts);
  }
  if (first === PCAP_MAGIC_LE || first === PCAP_MAGIC_BE) {
    return parsePcapClassic(buf, maxPackets, opts);
  }
  throw new Error('无法识别的抓包格式（既不是 pcap 也不是 pcapng）');
}

/**
 * Classic libpcap format.
 * @param {Buffer} buf
 * @param {number} maxPackets
 * @returns {object}
 */
function parsePcapClassic(buf, maxPackets, opts = {}) {
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
  return assemble(packets, stats, { format: 'pcap', linkType, truncatedOrig: 0 }, opts);
}

/**
 * pcapng format (what `pktmon etl2pcap` writes).
 * @param {Buffer} buf
 * @param {number} maxPackets
 * @returns {object}
 */
function parsePcapng(buf, maxPackets, opts = {}) {
  // Every section has its own endianness; the SHB magic tells us which.
  let off = 0;
  const packets = [];
  const stats = { malformed: 0, truncated: 0, unsupportedLink: 0, blocks: 0 };
  const linkTypes = [];
  /** Per-interface timestamp units per second (from if_tsresol). */
  const tsResolutions = [];
  /** Version from the most recent Section Header Block (informational). */
  let sectionVersion = null;

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
      // The SHB carries no link type: its layout is
      //   type(4) len(4) byte-order-magic(4) major(2) minor(2)
      //   section-length(8) options…
      // Reading a link type here would land in the options area and yield
      // garbage. The real link type lives in each Interface Description Block.
      const major = le ? buf.readUInt16LE(off + 12) : buf.readUInt16BE(off + 12);
      const minor = le ? buf.readUInt16LE(off + 14) : buf.readUInt16BE(off + 14);
      sectionVersion = { major, minor };
      // A new section resets the per-interface link types.
      linkTypes.length = 0;
      tsResolutions.length = 0;
      stats.blocks++;
      off += totalLen;
      continue;
    }
    if (blockType === 0x00000001) {
      // Interface Description Block:
      //   type(4) len(4) linktype(2@8) reserved(2@10) snaplen(4@12) options…
      const totalLen = buf.readUInt32LE(off + 4);
      if (!Number.isFinite(totalLen) || totalLen < 20 || off + totalLen > buf.length) {
        stats.truncated++;
        break;
      }
      const linkType = buf.readUInt16LE(off + 8);
      linkTypes.push(linkType);
      // Option 9 (if_tsresol) gives the timestamp resolution. Its absence means
      // the pcapng default of 10^-6 (microseconds) — but dumpcap/Npcap write
      // nanoseconds, so reading this is required for correct wall-clock times.
      tsResolutions.push(readTsResolution(buf, off + 16, off + totalLen - 4));
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
      // Convert with the interface's own resolution (dumpcap writes nanoseconds;
      // the pcapng default is microseconds).
      const units = tsResolutions[tsResolutions.length - 1] || 1e6;
      const tsSec = (tsHigh * 4294967296 + tsLow) / units;
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
    } else if (blockType === 0x00000005 || blockType === 0x00000004) {
      // Interface Statistics / Name Resolution: nothing to decode here.
      stats.blocks++;
    } else {
      stats.blocks++;
    }
    off += totalLen;
  }
  return assemble(packets, stats, {
    format: 'pcapng',
    linkType: linkTypes[linkTypes.length - 1] ?? null,
    version: sectionVersion,
    tsResolution: tsResolutions[tsResolutions.length - 1] ?? 1e6,
  }, opts);
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
  // Keep the transport payload for the reassembly pass without exposing it in
  // JSON output (routes.js serialises whole packets).
  if (decoded.payload != null && Buffer.isBuffer(decoded.payload)) {
    Object.defineProperty(decoded, 'payloadBuf', { value: decoded.payload, enumerable: false });
    delete decoded.payload;
  }
  return decoded;
}

/* ------------------------------------------------------------------ *
 * TCP stream reassembly + HTTP/TLS transaction extraction
 * ------------------------------------------------------------------ */

/** Content types whose bodies are worth keeping as text. */
const TEXTUAL_CT = /^(text\/|application\/(json|xml|x-www-form-urlencoded|javascript|graphql|problem\+json))/i;

/**
 * Reassemble one direction's TCP payload segments into a single buffer.
 * Sequence numbers wrap at 2^32; offsets are computed modulo that, relative to
 * the earliest segment seen, which keeps ordering monotonic within a bounded
 * stream window.
 *
 * @param {Array<{seq:number, data:Buffer}>} segments
 * @param {number} cap maximum bytes to place
 * @returns {{buf:Buffer, gaps:number, duplicateBytes:number, truncated:boolean}}
 */
function reassembleDirection(segments, cap) {
  if (!segments.length) return { buf: Buffer.alloc(0), gaps: 0, duplicateBytes: 0, truncated: false };
  // Sequence numbers are 32-bit and wrap. Offsets are computed relative to the
  // first captured segment, then any offset in the "negative" half of the
  // modulo space is read as a segment that started *earlier* — this keeps
  // out-of-order captures ordered correctly.
  const base0 = segments[0].seq;
  const rel = segments.map((s) => ({ s, off: ((s.seq - base0) >>> 0) }));
  for (const r of rel) if (r.off > 0x80000000) r.off -= 0x100000000;
  const shift = Math.min(...rel.map((r) => r.off));
  const placed = [];
  let maxEnd = 0;
  let beyond = false;
  for (const r of rel) {
    const off = r.off - shift;
    if (off >= cap) { beyond = true; continue; } // beyond the retained window
    const end = Math.min(off + r.s.data.length, cap);
    placed.push({ off, end, data: r.s.data });
    if (end > maxEnd) maxEnd = end;
  }
  placed.sort((a, b) => a.off - b.off);
  const out = Buffer.alloc(maxEnd);
  const covered = new Uint8Array(maxEnd);
  let gaps = 0;
  let duplicateBytes = 0;
  for (const seg of placed) {
    for (let i = seg.off; i < seg.end; i++) {
      if (covered[i]) { duplicateBytes++; continue; }
      out[i] = seg.data[i - seg.off];
      covered[i] = 1;
    }
  }
  let run = 0;
  for (let i = 0; i < maxEnd; i++) {
    if (!covered[i]) { run++; if (run === 1) gaps++; } else run = 0;
  }
  return { buf: out, gaps, duplicateBytes, truncated: beyond };
}

/**
 * Split an HTTP message head from its body.
 * @param {Buffer} buf
 * @returns {{head:string, headers:object, bodyOffset:number, contentLength:number|null, chunked:boolean}|null}
 */
function httpHead(buf) {
  const limit = Math.min(buf.length, 16384);
  const text = buf.toString('latin1', 0, limit);
  const idx = text.indexOf('\r\n\r\n');
  if (idx < 0) return null;
  const head = text.slice(0, idx);
  const headers = {};
  for (const line of head.split('\r\n').slice(1)) {
    const m = /^([^:]+):\s*(.*)$/.exec(line);
    if (m) headers[m[1].toLowerCase()] = m[2];
  }
  const cl = headers['content-length'] != null ? Number(headers['content-length']) : null;
  return {
    head,
    headers,
    bodyOffset: idx + 4,
    contentLength: Number.isFinite(cl) ? cl : null,
    chunked: /chunked/i.test(headers['transfer-encoding'] || ''),
  };
}

/**
 * Extract an HTTP request from a reassembled client→server buffer.
 * @param {Buffer} buf
 * @param {number} cap body preview cap
 * @returns {object|null}
 */
function extractHttpRequest(buf, cap) {
  const h = httpHead(buf);
  if (!h) return null;
  const m = /^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|TRACE) (\S+) HTTP\/1\.[01]$/.exec(h.head.split('\r\n')[0]);
  if (!m) return null;
  const out = {
    method: m[1],
    path: m[2],
    host: h.headers.host || null,
    userAgent: h.headers['user-agent'] || null,
    contentType: h.headers['content-type'] || null,
    contentLength: h.contentLength,
    headers: h.headers,
    bodyPreview: null,
    bodyBytes: null,
    bodyTruncated: false,
  };
  if (h.contentLength != null && h.contentLength > 0 && TEXTUAL_CT.test(h.headers['content-type'] || '')) {
    const avail = buf.length - h.bodyOffset;
    const take = Math.max(0, Math.min(avail, cap, h.contentLength));
    out.bodyPreview = buf.toString('utf8', h.bodyOffset, h.bodyOffset + take);
    out.bodyBytes = h.contentLength;
    out.bodyTruncated = take < h.contentLength;
  }
  return out;
}

/**
 * Extract an HTTP response from a reassembled server→client buffer.
 * @param {Buffer} buf
 * @param {number} cap body preview cap
 * @returns {object|null}
 */
function extractHttpResponse(buf, cap) {
  const h = httpHead(buf);
  if (!h) return null;
  const m = /^HTTP\/1\.[01] (\d{3}) ?([^\r\n]*)$/.exec(h.head.split('\r\n')[0]);
  if (!m) return null;
  const out = {
    status: Number(m[1]),
    reason: m[2].trim(),
    contentType: h.headers['content-type'] || null,
    contentLength: h.contentLength,
    server: h.headers.server || null,
    chunked: h.chunked,
    headers: h.headers,
    bodyPreview: null,
    bodyBytes: null,
    bodyTruncated: false,
  };
  const ct = h.headers['content-type'] || '';
  if (!h.chunked && h.contentLength != null && h.contentLength > 0 && TEXTUAL_CT.test(ct)) {
    const avail = buf.length - h.bodyOffset;
    const take = Math.max(0, Math.min(avail, cap, h.contentLength));
    out.bodyPreview = buf.toString('utf8', h.bodyOffset, h.bodyOffset + take);
    out.bodyBytes = h.contentLength;
    out.bodyTruncated = take < h.contentLength;
  } else if (h.chunked) {
    out.bodyPreview = null;
    out.bodyBytes = null;
  }
  return out;
}

/**
 * Group TCP packets into per-flow, per-direction streams and reassemble them.
 *
 * Bounded on purpose: a hostile or huge capture must not blow up memory.
 *
 * @param {Array<object>} packets
 * @param {{maxStreams?:number, maxDirs?:number, streamCap?:number, bodyCap?:number}} [opts]
 * @returns {object} {streams, http, tls, stats}
 */
function buildStreams(packets, opts = {}) {
  const maxStreams = opts.maxStreams ?? 2000;
  const maxDirs = opts.maxDirs ?? 4000;
  const streamCap = opts.streamCap ?? 262144;   // 256 KiB retained per direction
  const bodyCap = opts.bodyCap ?? 4096;         // body preview per message
  const flows = new Map();
  let dirs = 0;
  let skippedFlows = 0;

  for (const p of packets) {
    if (p.proto !== 'TCP') continue;
    if (!p.src || !p.dst) continue;
    const a = `${p.src}:${p.sport}`;
    const b = `${p.dst}:${p.dport}`;
    const [lo, hi] = a < b ? [a, b] : [b, a];
    const key = `${lo}|${hi}`;
    let f = flows.get(key);
    if (!f) {
      if (flows.size >= maxStreams) { skippedFlows++; continue; }
      f = { key, dirs: new Map(), packets: 0, bytes: 0 };
      flows.set(key, f);
    }
    let d = f.dirs.get(a);
    if (!d) {
      if (dirs >= maxDirs) { skippedFlows++; continue; }
      d = { from: a, segments: [], bytes: 0, dropped: false };
      f.dirs.set(a, d);
      dirs++;
    }
    f.packets++;
    f.bytes += p.payloadLen || 0;
    const pl = p.payloadBuf;
    if (pl && pl.length) {
      if (d.bytes < streamCap) d.segments.push({ seq: p.seq >>> 0, data: pl });
      else d.dropped = true; // beyond the retained window
      d.bytes += pl.length;
    }
  }

  const streams = [];
  const httpTransactions = [];
  const tlsHandshakes = [];
  let reassembledBytes = 0;
  let gapsTotal = 0;

  for (const f of flows.values()) {
    const dirList = [...f.dirs.values()].map((d) => {
      const r = reassembleDirection(d.segments, streamCap);
      return { from: d.from, raw: d.bytes, dropped: d.dropped, ...r, truncated: r.truncated || d.dropped };
    });
    // Identify the client side: the endpoint that sent the first payload byte,
    // or — failing that — the one with the higher ephemeral port.
    const withData = dirList.filter((d) => d.buf.length);
    if (!withData.length) {
      streams.push({ key: f.key, packets: f.packets, bytes: f.bytes, truncated: false, directions: [] });
      continue;
    }
    let client = withData[0];
    let server = dirList.find((d) => d !== client) || null;
    const firstPayloadTs = (() => {
      for (const p of packets) {
        if (p.proto !== 'TCP' || !p.payloadLen || !p.src) continue;
        if (`${p.src}:${p.sport}` === client.from) return p.ts;
      }
      return null;
    })();
    // Prefer the direction that starts with an HTTP request or a ClientHello.
    const looksClient = (d) => /^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|TRACE) /.test(d.buf.toString('latin1', 0, 8)) || d.buf[0] === 0x16;
    if (!looksClient(client)) {
      const alt = dirList.find((d) => d !== client && looksClient(d));
      if (alt) { server = client; client = alt; }
    }

    let httpReq = null, httpRes = null;
    if (client.buf.length) httpReq = extractHttpRequest(client.buf, bodyCap);
    if (server && server.buf.length) httpRes = extractHttpResponse(server.buf, bodyCap);
    let tls = null;
    const tlsBuf = client.buf.length && client.buf[0] === 0x16 ? client.buf : (server && server.buf.length && server.buf[0] === 0x16 ? server.buf : null);
    if (tlsBuf) {
      const ch = tlsClientHello(tlsBuf);
      const sh = ch ? null : tlsServerHello(tlsBuf);
      tls = ch || sh;
      if (ch) tls.role = 'client';
      else if (sh) tls.role = 'server';
    }

    reassembledBytes += client.buf.length + (server ? server.buf.length : 0);
    gapsTotal += client.gaps + (server ? server.gaps : 0);

    const entry = {
      key: f.key,
      client: client.from,
      server: server ? server.from : null,
      packets: f.packets,
      bytes: f.bytes,
      gaps: client.gaps + (server ? server.gaps : 0),
      truncated: client.truncated || (server ? server.truncated : false),
      firstTs: firstPayloadTs,
      requestBytes: client.buf.length,
      responseBytes: server ? server.buf.length : 0,
      http: httpReq || httpRes ? { request: httpReq, response: httpRes } : null,
      tls: tls || null,
    };
    streams.push(entry);
    if (entry.http) {
      httpTransactions.push({
        ts: firstPayloadTs,
        stream: f.key,
        client: client.from,
        server: server ? server.from : null,
        method: httpReq ? httpReq.method : null,
        path: httpReq ? httpReq.path : null,
        host: httpReq ? httpReq.host : null,
        status: httpRes ? httpRes.status : null,
        reason: httpRes ? httpRes.reason : null,
        requestContentType: httpReq ? httpReq.contentType : null,
        responseContentType: httpRes ? httpRes.contentType : null,
        responseBytes: httpRes ? httpRes.contentLength : null,
        requestBody: httpReq ? httpReq.bodyPreview : null,
        responseBody: httpRes ? httpRes.bodyPreview : null,
        responseBodyTruncated: httpRes ? httpRes.bodyTruncated : false,
      });
    }
    if (tls) {
      tlsHandshakes.push({ ts: firstPayloadTs, stream: f.key, sni: tls.sni ?? null, ...tls });
    }
  }

  return {
    streams,
    http: httpTransactions,
    tls: tlsHandshakes,
    stats: { streams: streams.length, skippedFlows, reassembledBytes, gaps: gapsTotal, streamCap, bodyCap },
  };
}

/**
 * Fold decoded packets into capture-level stats and derived flows.
 * @param {Array<object>} packets
 * @param {object} stats
 * @param {object} meta
 * @returns {object}
 */
function assemble(packets, stats, meta, opts = {}) {
  const talkers = new Map();
  const ports = new Map();
  const dns = [];
  const sni = new Map();
  const http = [];
  const tls = [];
  let tcpPackets = 0, udpPackets = 0, bytes = 0;
  const firstTs = packets.length ? packets[0].ts : null;
  const lastTs = packets.length ? packets[packets.length - 1].ts : null;

  for (const p of packets) {
    bytes += p.bytes || 0;
    if (p.proto === 'TCP') {
      tcpPackets++;
      if (p.dport) ports.set(p.dport, (ports.get(p.dport) || 0) + 1);
      if (p.sni) sni.set(p.sni, (sni.get(p.sni) || 0) + 1);
      if (p.tls) {
        tls.push({ ts: p.ts, src: p.src, dst: p.dst, sport: p.sport, dport: p.dport, ...p.tls });
      }
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

  const streams = opts.reassemble === false
    ? { streams: [], http: [], tls: [], stats: { streams: 0, skippedFlows: 0, reassembledBytes: 0, gaps: 0, disabled: true } }
    : buildStreams(packets, opts);

  return {
    meta: {
      ...meta,
      packets: packets.length,
      bytes,
      tcpPackets,
      udpPackets,
      firstTs,
      lastTs,
      firstTime: isoTime(firstTs),
      lastTime: isoTime(lastTs),
    },
    stats,
    reassembly: streams.stats,
    talkers: [...talkers.values()].sort((a, b) => b.bytes - a.bytes).slice(0, 100),
    topPorts: [...ports.entries()].map(([port, count]) => ({ port, count })).sort((a, b) => b.count - a.count).slice(0, 50),
    dns,
    sni: [...sni.entries()].map(([name, count]) => ({ name, count })).sort((a, b) => b.count - a.count),
    http,
    tls: tls.slice(0, 500),
    streams: streams.streams.slice(0, 500),
    httpTransactions: streams.http.slice(0, 500),
    packets,
  };
}

/**
 * Convert epoch seconds to an ISO-8601 UTC string.
 * @param {number|null} ts
 * @returns {string|null}
 */
export function isoTime(ts) {
  if (ts == null || !Number.isFinite(ts)) return null;
  try { return new Date(ts * 1000).toISOString().replace('.000Z', 'Z'); } catch { return null; }
}

/** DNS type names for display. */
export const DNS_TYPES = {
  1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR', 15: 'MX', 16: 'TXT',
  28: 'AAAA', 33: 'SRV', 41: 'OPT', 43: 'DS', 46: 'RRSIG', 65: 'HTTPS', 255: 'ANY',
};
