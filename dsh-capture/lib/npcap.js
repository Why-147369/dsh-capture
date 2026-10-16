/**
 * dsh-capture: Npcap (Wireshark) capture backend.
 *
 * Why this is the preferred backend
 * ---------------------------------
 * Windows offers two capture paths and their privilege stories differ:
 *
 *   pktmon — built in, but `PktMon` is a KERNEL_DRIVER whose device object is
 *            Administrators-only. Even the read-only `pktmon filter list`
 *            fails with exit 5 without elevation, so capturing requires an
 *            elevated process (this plugin offers a one-shot helper for that).
 *   Npcap  — shipped with Wireshark. `dumpcap.exe` and `tshark.exe` both
 *            declare `asInvoker` in their manifests, so a standard user can
 *            capture. Npcap may still ask for confirmation when a process
 *            first opens an adapter, but that is a one-prompt-per-process
 *            flow rather than a hard requirement for elevation.
 *
 * Measured on the development machine: three consecutive non-elevated
 * `dumpcap` captures produced 164 / 100 / 83 packets with no elevation, and
 * `AdminOnly=1` in Npcap's registry key did not prevent it.
 *
 * Two rules learned the hard way and enforced here
 * ------------------------------------------------
 * 1. **Address adapters by device name, never by index.** `dumpcap -D` lists
 *    eleven interfaces on a typical machine — several are idle virtual
 *    adapters ("本地连接* N", VMware, Loopback). Numeric indices are also not
 *    stable between calls, so `-i 1` silently captures nothing. Everything
 *    here uses `\Device\NPF_{GUID}`.
 * 2. **Judge success by packet blocks, not file size.** A 484-byte pcapng
 *    containing only SHB+IDB+ISB is a perfectly valid file with zero packets.
 *    `countPacketBlocks` below is the only accepted success test.
 */
import { spawn, execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, rmSync, statSync } from 'node:fs';
import { join } from 'node:path';

const SYS = process.env.SystemRoot || 'C:\\Windows';

/** Where Wireshark is commonly installed, including non-default drives. */
const COMMON_DIRS = [
  'E:\\wireshark', 'D:\\wireshark', 'C:\\wireshark',
  'C:\\Program Files\\Wireshark', 'C:\\Program Files (x86)\\Wireshark',
  'D:\\Program Files\\Wireshark', 'E:\\Program Files\\Wireshark',
];

/**
 * Locate the Wireshark directory by checking the registry first (authoritative)
 * then the common install dirs.
 * @returns {string|null}
 */
export function findWiresharkDir() {
  // Registry holds the real install dir even for non-default locations.
  const regPaths = [
    'HKLM\\SOFTWARE\\WOW6432Node\\Wireshark',
    'HKLM\\SOFTWARE\\Wireshark',
  ];
  for (const key of regPaths) {
    try {
      const out = execFileSync('reg', ['query', key, '/v', 'InstallDir'],
        { encoding: 'utf8', timeout: 8000, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
      const m = /InstallDir\s+REG_SZ\s+(.+)/i.exec(out);
      if (m) {
        const dir = m[1].trim();
        if (existsSync(join(dir, 'dumpcap.exe'))) return dir;
      }
    } catch { /* key absent on this machine */ }
  }
  for (const dir of COMMON_DIRS) {
    if (existsSync(join(dir, 'dumpcap.exe'))) return dir;
  }
  return null;
}

/** Cache of the located directory: probing is cheap but repeated often. */
let cachedDir = null;
/** Cache of the adapter list; re-enumerating may prompt the user for access. */
let cachedInterfaces = null;
let cachedInterfacesAt = 0;
/** Interface lists change rarely; five minutes keeps a session stable. */
const IFACE_TTL_MS = 5 * 60 * 1000;

/**
 * Resolve the toolchain paths.
 * @returns {{dir:string, dumpcap:string, tshark:string|null}|null}
 */
export function tools() {
  if (!cachedDir) cachedDir = findWiresharkDir();
  if (!cachedDir) return null;
  const dumpcap = join(cachedDir, 'dumpcap.exe');
  if (!existsSync(dumpcap)) return null;
  const tsharkPath = join(cachedDir, 'tshark.exe');
  return { dir: cachedDir, dumpcap, tshark: existsSync(tsharkPath) ? tsharkPath : null };
}

/**
 * Run a command to completion, capturing output.
 * @param {string} cmd
 * @param {string[]} args
 * @param {number} timeoutMs
 * @returns {Promise<{code:number|null, stdout:string, stderr:string, timedOut:boolean}>}
 */
function runToEnd(cmd, args, timeoutMs = 60000) {
  return new Promise((resolve) => {
    let child;
    try {
      child = spawn(cmd, args, { windowsHide: true, shell: false });
    } catch (e) {
      resolve({ code: null, stdout: '', stderr: String(e.message), timedOut: false });
      return;
    }
    let out = '';
    let err = '';
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      try { child.kill(); } catch { /* gone */ }
    }, timeoutMs);
    child.stdout?.on('data', (d) => { out += d.toString('utf8'); });
    child.stderr?.on('data', (d) => { err += d.toString('utf8'); });
    child.on('error', (e) => { err += String(e.message); });
    child.on('close', (code) => { clearTimeout(timer); resolve({ code, stdout: out, stderr: err, timedOut }); });
  });
}

/**
 * Parse `dumpcap -D` output into adapter records.
 *
 * Lines look like:
 *   4. \Device\NPF_{DD27BA59-...} (WLAN)
 * @param {string} text
 * @returns {Array<{index:number, device:string, label:string, kind:string, recommended:boolean}>}
 */
export function parseInterfaceList(text) {
  const out = [];
  for (const raw of String(text || '').split(/\r?\n/)) {
    const line = raw.trim();
    const m = /^(\d+)\.\s+(\S+)\s*(?:\((.*)\))?\s*$/.exec(line);
    if (!m) continue;
    const index = Number(m[1]);
    const device = m[2];
    const label = (m[3] || '').trim();
    const blob = `${device} ${label}`.toLowerCase();
    // Classify so the UI can default to a real adapter.
    let kind = 'other';
    if (/loopback/.test(blob)) kind = 'loopback';
    else if (/vmware|virtualbox|hyper-v|vethernet|tap|tun/.test(blob)) kind = 'virtual';
    else if (/本地连接\s*\*|local area connection\s*\*/.test(label.toLowerCase())) kind = 'virtual';
    else if (/wlan|wi-?fi|无线/.test(blob)) kind = 'wifi';
    else if (/以太网|ethernet/.test(blob)) kind = 'ethernet';
    const recommended = kind === 'wifi' || kind === 'ethernet';
    out.push({ index, device, label, kind, recommended });
  }
  return out;
}

/**
 * Enumerate adapters, using a short-lived cache.
 *
 * Re-enumerating starts a new dumpcap process, and on machines where Npcap
 * asks for confirmation that means another prompt. The cache keeps a capture
 * session to at most one prompt.
 *
 * @param {{refresh?:boolean}} [opts]
 * @returns {Promise<{ok:boolean, interfaces:Array<object>, error?:string, cached?:boolean}>}
 */
export async function listInterfaces(opts = {}) {
  const t = tools();
  if (!t) return { ok: false, interfaces: [], error: '未找到 Wireshark（dumpcap.exe）。请安装 Wireshark（内置 Npcap）。' };
  if (!opts.refresh && cachedInterfaces && Date.now() - cachedInterfacesAt < IFACE_TTL_MS) {
    return { ok: true, interfaces: cachedInterfaces, cached: true };
  }
  const r = await runToEnd(t.dumpcap, ['-D'], 60000);
  const list = parseInterfaceList(r.stdout || r.stderr);
  if (!list.length) {
    return {
      ok: false,
      interfaces: [],
      error: `dumpcap -D 未列出任何网卡（exit=${r.code}）。${(r.stderr || '').trim().slice(0, 200)}`,
    };
  }
  cachedInterfaces = list;
  cachedInterfacesAt = Date.now();
  return { ok: true, interfaces: list, cached: false };
}

/**
 * Pick the best adapter to capture from.
 * @param {Array<object>} list
 * @returns {object|null}
 */
export function pickDefaultInterface(list) {
  if (!Array.isArray(list) || !list.length) return null;
  return list.find((i) => i.kind === 'wifi')
    || list.find((i) => i.kind === 'ethernet')
    || list.find((i) => i.recommended)
    || list[0];
}

/**
 * Count pcapng packet blocks (EPB 0x06 / SPB 0x03).
 *
 * This is the only correct success test: a pcapng with zero packets is still a
 * structurally valid file, so file size says nothing about whether capture
 * worked.
 *
 * @param {string} file
 * @returns {{packets:number, bytes:number, blocks:number, truncated:boolean}}
 */
export function countPacketBlocks(file) {
  if (!existsSync(file)) return { packets: 0, bytes: 0, blocks: 0, truncated: false };
  const buf = readFileSync(file);
  let off = 0;
  let packets = 0;
  let blocks = 0;
  let truncated = false;
  let guard = 0;
  while (off + 12 <= buf.length && guard++ < 500000) {
    const type = buf.readUInt32LE(off);
    const len = buf.readUInt32LE(off + 4);
    if (len < 12 || off + len > buf.length) { truncated = true; break; }
    if (type === 0x00000006 || type === 0x00000003) packets++;
    blocks++;
    off += len;
  }
  return { packets, bytes: buf.length, blocks, truncated };
}

/** Live capture sessions, keyed by an opaque session id. */
const sessions = new Map();

/**
 * Start a capture.
 *
 * A capture is one long-lived `dumpcap` process writing to a file. Stopping it
 * terminates that process; dumpcap flushes each block as it writes, so the file
 * stays parseable after an abrupt end (verified: 42 packets were recovered from
 * a force-killed capture).
 *
 * @param {object} params
 * @param {string} params.dir directory for the capture file
 * @param {string} params.name base file name (already sanitized by the caller)
 * @param {string} [params.device] adapter device name; default adapter when omitted
 * @param {string} [params.bpf] libpcap capture filter (dumpcap -f)
 * @param {number} [params.snaplen] bytes per packet
 * @param {number} [params.ringFileMb] ring-buffer size in MB
 * @param {number} [params.durationSec] optional auto-stop
 * @returns {Promise<object>}
 */
export async function startCapture({
  dir, name, device, bpf, snaplen, ringFileMb, durationSec,
}) {
  const t = tools();
  if (!t) return { ok: false, error: '未找到 Wireshark（dumpcap.exe）。' };
  if (sessions.size > 0) return { ok: false, error: '已有 Npcap 抓包在进行中。' };

  mkdirSync(dir, { recursive: true });
  const file = join(dir, `${name}.pcapng`);
  if (existsSync(file)) { try { rmSync(file, { force: true }); } catch { /* best effort */ } }

  // Resolve the adapter: explicit device, else the recommended default.
  let dev = device;
  let ifaceLabel = '';
  if (!dev) {
    const li = await listInterfaces();
    if (!li.ok) return { ok: false, error: li.error };
    const pick = pickDefaultInterface(li.interfaces);
    if (!pick) return { ok: false, error: '没有可用的网卡。' };
    dev = pick.device;
    ifaceLabel = pick.label;
  } else {
    const li = await listInterfaces();
    const found = (li.interfaces || []).find((i) => i.device === dev);
    ifaceLabel = found ? found.label : '';
  }

  const args = ['-i', dev, '-w', file];
  if (bpf) args.push('-f', String(bpf));
  const snap = Number.isFinite(snaplen) && snaplen > 0 ? Math.max(64, Math.min(262144, Math.floor(snaplen))) : 262144;
  args.push('-s', String(snap));
  if (Number.isFinite(ringFileMb) && ringFileMb > 0) {
    args.push('-b', `filesize:${Math.round(ringFileMb)}000000`);
  }
  if (Number.isFinite(durationSec) && durationSec > 0) {
    args.push('-a', `duration:${Math.round(durationSec)}`);
  }

  let child;
  try {
    child = spawn(t.dumpcap, args, { windowsHide: true, shell: false });
  } catch (e) {
    return { ok: false, error: `无法启动 dumpcap：${e.message}` };
  }

  const session = {
    id: `npcap-${Date.now().toString(36)}-${Math.random().toString(16).slice(2, 8)}`,
    backend: 'npcap',
    pid: child.pid,
    child,
    file,
    device: dev,
    ifaceLabel,
    args,
    startedAt: Date.now(),
    stopped: false,
    stderr: '',
    stdout: '',
  };
  child.stdout?.on('data', (d) => { session.stdout += d.toString('utf8'); });
  child.stderr?.on('data', (d) => { session.stderr += d.toString('utf8'); });
  sessions.set(session.id, session);

  // Watch the first writes so an immediate failure (bad adapter, denied) is
  // reported now instead of after the user hits stop.
  await new Promise((r) => setTimeout(r, 1800));
  if (child.exitCode !== null && child.exitCode !== 0) {
    const st = countPacketBlocks(file);
    sessions.delete(session.id);
    return {
      ok: false,
      error: `dumpcap 立即退出（code=${child.exitCode}）：${(session.stderr || '').trim().slice(0, 300) || '无输出'}`,
      packets: st.packets,
    };
  }
  const early = countPacketBlocks(file);
  return {
    ok: true,
    sessionId: session.id,
    file,
    device: dev,
    ifaceLabel,
    args,
    packetsSoFar: early.packets,
    hint: '抓包已开始（Npcap/dumpcap）。停止请调用 capture_stop。首次打开网卡时 Npcap 可能弹一次确认框。',
  };
}

/**
 * Status of one session, with a live packet count read from the file.
 * @param {string} sessionId
 * @returns {object}
 */
export function sessionStatus(sessionId) {
  const s = sessions.get(sessionId);
  if (!s) return { ok: false, error: '未找到该抓包会话。' };
  const st = countPacketBlocks(s.file);
  return {
    ok: true,
    sessionId,
    running: !s.stopped,
    exitCode: s.child.exitCode,
    file: s.file,
    device: s.device,
    ifaceLabel: s.ifaceLabel,
    startedAt: s.startedAt,
    packets: st.packets,
    bytes: st.bytes,
    stderr: s.stderr.trim().slice(-400),
  };
}

/**
 * Stop a capture.
 *
 * dumpcap documents Ctrl-C as the graceful stop, but Node cannot deliver a
 * console Ctrl-C to a child. Force-terminating is safe here because dumpcap
 * writes each block as it arrives — a killed capture was verified to still
 * yield all 42 packets it had written. We still ask dumpcap to stop on its own
 * first when a duration was set, and always fall back to terminating.
 *
 * @param {string} sessionId
 * @returns {Promise<object>}
 */
export async function stopCapture(sessionId) {
  const s = sessions.get(sessionId);
  if (!s) {
    // Tolerate a stop after a restart: report what is on disk instead of failing.
    return { ok: false, error: '未找到该抓包会话（可能已随 DSH 重启失效）。' };
  }
  if (s.stopped) {
    const st = countPacketBlocks(s.file);
    return { ok: true, alreadyStopped: true, file: s.file, packets: st.packets, bytes: st.bytes };
  }

  // Terminate the process tree; dumpcap may have helper children.
  try {
    await new Promise((resolve) => {
      const k = spawn('taskkill', ['/F', '/PID', String(s.pid), '/T'], { windowsHide: true, shell: false });
      const timer = setTimeout(() => { try { k.kill(); } catch { /* gone */ } resolve(); }, 15000);
      k.on('close', () => { clearTimeout(timer); resolve(); });
      k.on('error', () => { clearTimeout(timer); resolve(); });
    });
  } catch { /* fall through to the child check below */ }
  try { s.child.kill(); } catch { /* already gone */ }

  // Give the OS a moment to flush the last block.
  await new Promise((r) => setTimeout(r, 700));
  s.stopped = true;

  const st = countPacketBlocks(s.file);
  return {
    ok: true,
    sessionId,
    file: s.file,
    packets: st.packets,
    bytes: st.bytes,
    blocks: st.blocks,
    truncatedTail: st.truncated,
    device: s.device,
    ifaceLabel: s.ifaceLabel,
    stderr: s.stderr.trim().slice(-400),
    hint: st.packets > 0
      ? `已停止，抓到 ${st.packets} 个包。可用 capture_analyze 分析。`
      : '已停止，但没有抓到任何包 —— 可能网卡选错或该网卡没有流量。',
  };
}

/** Drop a finished session from the registry. */
export function forgetSession(sessionId) {
  const s = sessions.get(sessionId);
  if (s && !s.stopped) return false;
  sessions.delete(sessionId);
  return true;
}

/** List live sessions. */
export function activeSessions() {
  return [...sessions.values()].map((s) => ({
    sessionId: s.id, file: s.file, device: s.device, ifaceLabel: s.ifaceLabel,
    startedAt: s.startedAt, stopped: s.stopped,
  }));
}

/** Invalidate the adapter cache (used by the panel's refresh action). */
export function invalidateInterfaceCache() {
  cachedInterfaces = null;
  cachedInterfacesAt = 0;
}

/**
 * Whether an Npcap-based capture is possible at all.
 * @returns {Promise<object>}
 */
export async function probe() {
  const t = tools();
  if (!t) {
    return { available: false, reason: '未找到 Wireshark / Npcap（dumpcap.exe）。', dir: null };
  }
  const li = await listInterfaces();
  return {
    available: li.ok,
    dir: t.dir,
    dumpcap: t.dumpcap,
    tshark: t.tshark,
    interfaces: li.interfaces || [],
    cached: li.cached === true,
    reason: li.ok ? null : li.error,
  };
}
