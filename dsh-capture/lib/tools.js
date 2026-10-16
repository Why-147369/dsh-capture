/**
 * dsh-capture: capture flows shared by the HTTP panel and the agent tools.
 *
 * Kept separate from index.js so the tool surface stays small and the
 * scan/resolve logic has exactly one implementation.
 *
 * Two backends are supported and selected by `perm.js`:
 *
 *   npcap  — `dumpcap.exe` writing a pcapng. No elevation. This is the
 *            preferred path; a live session is one long-lived child process.
 *   pktmon — Windows' built-in capture. Requires an elevated process, so the
 *            start/stop actions are delegated to a one-shot helper (elevate.js)
 *            that exits immediately; DSH itself stays non-elevated.
 *
 * Capture ids are opaque hashes over the file name, so a crafted id can never
 * escape the capture directory.
 */
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { basename, join } from 'node:path';
import { homedir } from 'node:os';
import { probeBackend, setFilters, clearFilters, startCapture, stopCapture, etl2pcap } from './pktmon.js';
import { runElevatedCapture, elevationSupported } from './elevate.js';
import { probeEnvironment } from './perm.js';
import {
  startCapture as npcapStart,
  stopCapture as npcapStop,
  forgetSession as npcapForget,
  activeSessions as npcapActiveSessions,
  countPacketBlocks,
} from './npcap.js';

/**
 * The directory every capture lives in.
 * @returns {string}
 */
export function captureDir() {
  const home = process.env.DSH_HOME ?? join(homedir(), '.dsh');
  return join(home, 'dsh-capture');
}

function statePath() {
  return join(captureDir(), 'state.json');
}

/**
 * Read the capture session state (advisory; never throws).
 * @returns {object}
 */
export function readState() {
  try {
    return JSON.parse(readFileSync(statePath(), 'utf8'));
  } catch {
    return { running: false, backend: null, sessionId: null, file: null, name: null, startedAt: null, log: [] };
  }
}

/**
 * Persist the capture session state.
 * @param {object} next
 */
export function writeState(next) {
  try {
    mkdirSync(captureDir(), { recursive: true });
    writeFileSync(statePath(), JSON.stringify(next, null, 2), 'utf8');
  } catch { /* state is advisory */ }
}

/**
 * List saved captures with opaque ids.
 * @returns {Array<{id:string,name:string,size:number,kind:string,mtime:number,packets:number|null}>}
 */
export function listCaptures() {
  const dir = captureDir();
  const out = [];
  if (!existsSync(dir)) return out;
  for (const name of readdirSync(dir)) {
    if (!/\.(pcapng|pcap|etl)$/i.test(name)) continue;
    const full = join(dir, name);
    let st;
    try { st = statSync(full); } catch { continue; }
    if (!st.isFile()) continue;
    let packets = null;
    // Only pcapng gets a packet count; counting is a cheap block walk.
    if (/\.pcapng$/i.test(name)) {
      try { packets = countPacketBlocks(full).packets; } catch { packets = null; }
    }
    out.push({
      id: createHash('sha256').update(name).digest('hex').slice(0, 16),
      name,
      size: st.size,
      kind: name.toLowerCase().endsWith('.etl') ? 'etl'
        : name.toLowerCase().endsWith('.pcap') ? 'pcap' : 'pcapng',
      mtime: st.mtimeMs,
      packets,
    });
  }
  return out.sort((a, b) => b.mtime - a.mtime);
}

/**
 * Resolve an opaque id to a real path inside the capture directory, or null.
 * @param {string} id
 * @returns {string|null}
 */
export function resolveCaptureId(id) {
  if (!id || typeof id !== 'string' || !/^[a-f0-9]{8,64}$/i.test(id)) return null;
  const hit = listCaptures().find((c) => c.id === id);
  if (!hit) return null;
  const full = join(captureDir(), hit.name);
  // Defense in depth: the resolved path must stay inside the capture dir.
  if (!full.toLowerCase().startsWith(captureDir().toLowerCase())) return null;
  if (!existsSync(full)) return null;
  return full;
}

/**
 * Sanitize a user-supplied capture name into a safe base name.
 * @param {unknown} raw
 * @returns {string}
 */
export function safeName(raw) {
  const s = String(raw ?? '');
  if (/^[A-Za-z0-9._-]{1,48}$/.test(s) && !s.startsWith('.')) return s;
  return `capture-${new Date().toISOString().replace(/[:.]/g, '-')}`;
}

/**
 * Translate the panel/tool filter shape into a libpcap BPF expression for
 * dumpcap's `-f`. Returns '' when nothing can be expressed.
 *
 * The tool accepts either a raw `bpf` string (used verbatim) or the structured
 * `filters` array shared with the pktmon path.
 *
 * @param {Array<object>} filters
 * @returns {string}
 */
export function filtersToBpf(filters) {
  if (!Array.isArray(filters) || !filters.length) return '';
  const clauses = [];
  for (const f of filters) {
    if (!f) continue;
    const parts = [];
    if (f.ip) parts.push(`host ${f.ip}`);
    if (Number.isFinite(Number(f.port))) parts.push(`port ${Number(f.port)}`);
    if (f.protocol) {
      const p = String(f.protocol).toLowerCase();
      if (['tcp', 'udp', 'icmp'].includes(p)) parts.push(p);
    }
    if (parts.length) clauses.push(parts.join(' and '));
  }
  // Multiple filters are alternatives, matching the pktmon filter semantics.
  return clauses.length ? `(${clauses.join(') or (')})` : '';
}

/**
 * Start a capture end to end.
 *
 * @param {object} opts
 * @param {string} [opts.name] base file name
 * @param {Array<object>} [opts.filters] structured filters
 * @param {string} [opts.bpf] raw BPF override (npcap only)
 * @param {string} [opts.device] adapter device name (npcap only)
 * @param {number} [opts.snaplen] bytes per packet (npcap)
 * @param {number} [opts.ringFileMb] ring buffer size (npcap)
 * @param {number} [opts.durationSec] auto-stop (npcap)
 * @param {number} [opts.maxPktSize] pktmon per-packet size
 * @param {boolean} [opts.elevate] allow the one-shot elevation prompt
 * @returns {Promise<object>}
 */
export async function startCaptureFlow(opts = {}) {
  const state = readState();
  if (state.running) {
    return { ok: false, error: '已有抓包在进行中。先调用 capture_stop 结束当前抓包。', state };
  }

  const env = await probeEnvironment();
  if (!env.isWindows) {
    return { ok: false, error: `当前平台 ${env.platform} 不受支持。`, env };
  }
  if (!env.backend) {
    return { ok: false, error: '本机没有可用的抓包后端。', notes: env.notes, env };
  }

  const dir = captureDir();
  const name = safeName(opts.name);
  const filters = Array.isArray(opts.filters)
    ? opts.filters.filter((f) => f && (f.ip || Number.isFinite(Number(f.port)) || f.protocol)).slice(0, 16)
    : [];

  if (env.backend === 'npcap') {
    return await startNpcapFlow(dir, name, filters, opts, env);
  }
  return await startPktmonFlow(dir, name, filters, opts, env);
}

/**
 * Start through Npcap/dumpcap. No elevation is involved.
 * @returns {Promise<object>}
 */
async function startNpcapFlow(dir, name, filters, opts, env) {
  const bpf = typeof opts.bpf === 'string' && opts.bpf.trim()
    ? opts.bpf.trim()
    : filtersToBpf(filters);

  const started = await npcapStart({
    dir,
    name,
    device: opts.device,
    bpf: bpf || undefined,
    snaplen: Number(opts.snaplen) || undefined,
    ringFileMb: Number(opts.ringFileMb) || undefined,
    durationSec: Number(opts.durationSec) || undefined,
  });
  if (!started.ok) {
    return { ok: false, error: started.error, env };
  }

  const next = {
    running: true,
    backend: 'npcap',
    sessionId: started.sessionId,
    file: started.file,
    etl: null,
    pcapng: null,
    name,
    device: started.device,
    ifaceLabel: started.ifaceLabel,
    bpf: bpf || null,
    startedAt: Date.now(),
    elevated: false,
    log: [`dumpcap ${started.args.join(' ')}`],
  };
  writeState(next);
  return {
    ok: true,
    state: next,
    dir,
    backend: 'npcap',
    device: started.device,
    ifaceLabel: started.ifaceLabel,
    bpf: bpf || null,
    packetsSoFar: started.packetsSoFar ?? 0,
    note: '首次打开网卡时 Npcap 可能弹一次确认框；停止请调用 capture_stop。',
    hint: started.hint,
  };
}

/**
 * Start through pktmon, delegating to the one-shot elevated helper when the
 * current process is not elevated.
 * @returns {Promise<object>}
 */
async function startPktmonFlow(dir, name, filters, opts, env) {
  const p = await probeBackend();
  if (!p.pktmonExists) {
    return { ok: false, error: '本机没有 pktmon（Windows 10 1809+ / 11 自带）。', env };
  }

  if (p.needsElevation && opts.elevate !== false) {
    const elevated = await startElevated(dir, name, filters, opts, env);
    // A declined UAC prompt is a user decision, not a failure; report it as
    // such so the panel explains instead of retrying.
    if (elevated.ok || elevated.declined) return elevated;
    env.elevationError = elevated.error;
  }

  if (p.needsElevation) {
    return {
      ok: false,
      error: 'pktmon 需要管理员权限，且未通过提权助手启动。可选：'
        + '①本轮改用 Npcap（安装 Wireshark 即可，本插件会自动优选）；'
        + '②以管理员身份运行 DSH；'
        + '③允许提权助手弹一次 UAC。',
      elevationError: env.elevationError,
      env,
    };
  }

  const filterResult = await setFilters(filters);
  const startResult = await startCapture({
    dir,
    name,
    maxPktSize: Number(opts.maxPktSize) || undefined,
    maxFileMb: Number(opts.maxFileMb) || undefined,
    components: Array.isArray(opts.components) ? opts.components : undefined,
  });
  if (!startResult.ok) {
    await clearFilters();
    return { ok: false, error: '启动 pktmon 抓包失败。', filterLog: filterResult.log, log: startResult.log, env };
  }
  const next = {
    running: true,
    backend: 'pktmon',
    sessionId: null,
    etl: startResult.etl,
    pcapng: null,
    name,
    filters,
    startedAt: Date.now(),
    elevated: false,
    log: [...filterResult.log, ...startResult.log].slice(-40),
  };
  writeState(next);
  return { ok: true, state: next, dir, backend: 'pktmon', hint: '抓包已开始。完成后调用 capture_stop。' };
}

/**
 * Start a pktmon capture through the one-shot elevated helper.
 *
 * The helper performs `pktmon start` with administrator rights and exits; DSH
 * stays non-elevated. Conversion (`etl2pcap`) and parsing need no privilege.
 *
 * @param {string} dir
 * @param {string} name
 * @param {Array<object>} filters
 * @param {object} opts
 * @param {object} env
 * @returns {Promise<object>}
 */
async function startElevated(dir, name, filters, opts, env) {
  const job = await runElevatedCapture({
    captureDir: dir,
    action: 'start',
    payload: {
      dir,
      name,
      filters,
      pktSize: Number(opts.maxPktSize) || 256,
      maxFileMb: Number(opts.maxFileMb) || undefined,
    },
  });

  if (!job.ok) {
    const declined = job.declined === true;
    return {
      ok: false,
      declined,
      error: declined
        ? '提权请求被取消（UAC），未开始抓包。若想免去提权，安装 Wireshark（自带 Npcap）后本插件会优先用 Npcap。'
        : `提权抓包失败：${job.error || '未知原因'}`,
      log: job.log,
      env,
    };
  }

  const etl = job.result?.data?.etl;
  if (!etl) {
    return { ok: false, error: '提权助手未返回 ETL 路径。', log: job.log, env };
  }
  const next = {
    running: true,
    backend: 'pktmon',
    sessionId: null,
    etl,
    pcapng: null,
    name,
    filters,
    startedAt: Date.now(),
    elevated: true,
    log: [...job.log, ...(Array.isArray(job.result?.data?.filters) ? job.result.data.filters : [])].slice(-40),
  };
  writeState(next);
  return {
    ok: true,
    state: next,
    dir,
    backend: 'pktmon',
    elevated: true,
    hint: '抓包已以提权方式开始（助手已退出，DSH 仍是普通权限）。完成后调用 capture_stop。',
  };
}

/**
 * Stop the running capture, regardless of backend.
 * @param {{elevate?:boolean}} [opts]
 * @returns {Promise<object>}
 */
export async function stopCaptureFlow(opts = {}) {
  const state = readState();
  if (!state.running) {
    return { ok: false, error: '当前没有正在进行的抓包。', state };
  }

  if (state.backend === 'npcap' && state.sessionId) {
    return await stopNpcapFlow(state, opts);
  }
  return await stopPktmonFlow(state, opts);
}

/**
 * Stop an Npcap/dumpcap capture. Terminating the child is safe: dumpcap writes
 * each block as it arrives, and a killed capture was verified to keep every
 * packet it had already written.
 * @returns {Promise<object>}
 */
async function stopNpcapFlow(state, opts) {
  const stopped = await npcapStop(state.sessionId);
  if (!stopped.ok) {
    // Session lost (e.g. DSH restarted): report whatever the file holds.
    const st = state.file && existsSync(state.file)
      ? countPacketBlocks(state.file)
      : { packets: 0, bytes: 0, blocks: 0, truncated: false };
    writeState({ ...state, running: false, stoppedAt: Date.now() });
    return {
      ok: false,
      error: `${stopped.error || '停止失败'} 文件仍保留：${state.file || '(无)'}，含 ${st.packets} 个包。`,
      state,
    };
  }
  npcapForget(state.sessionId);

  const file = stopped.file || state.file;
  const hit = file ? listCaptures().find((c) => c.name === basename(file)) : null;
  const next = {
    ...state,
    running: false,
    pcapng: file,
    stoppedAt: Date.now(),
    log: [...(state.log || []), `stop: ${stopped.packets} packets`].slice(-60),
  };
  writeState(next);

  return {
    ok: true,
    backend: 'npcap',
    state: next,
    capture: hit,
    file,
    packets: stopped.packets,
    bytes: stopped.bytes,
    device: stopped.device,
    ifaceLabel: stopped.ifaceLabel,
    truncatedTail: stopped.truncatedTail,
    hint: hit
      ? `已停止，抓到 ${stopped.packets} 个包。用 capture_analyze 传入 id="${hit.id}" 查看摘要。`
      : stopped.hint,
  };
}

/**
 * Stop a pktmon capture, converting the ETL to pcapng.
 *
 * A capture started through the elevated helper must be stopped through it too,
 * because a non-elevated `pktmon stop` cannot reach the driver.
 * @returns {Promise<object>}
 */
async function stopPktmonFlow(state, opts) {
  let stopResult;
  let clearResult;
  let elevatedUsed = false;

  const needsElevatedStop = state.elevated === true && elevationSupported();
  if (needsElevatedStop && opts.elevate !== false) {
    const job = await runElevatedCapture({ captureDir: captureDir(), action: 'stop' });
    elevatedUsed = job.ok;
    if (job.ok) {
      stopResult = { ok: true, log: job.log };
      clearResult = { ok: true, log: [] };
    } else {
      stopResult = { ok: false, log: [...job.log, job.error ? `错误：${job.error}` : ''] };
      clearResult = { ok: false, log: [] };
    }
  } else {
    stopResult = await stopCapture();
    clearResult = await clearFilters();
  }

  // Conversion and parsing need no privilege at all.
  let convert = { ok: false, out: null, size: null, log: [] };
  if (state.etl && existsSync(state.etl)) {
    convert = await etl2pcap(state.etl, state.etl.replace(/\.etl$/i, '.pcapng'));
  }
  const next = {
    ...state,
    running: false,
    pcapng: convert.out || null,
    stoppedAt: Date.now(),
    log: [...(state.log || []), ...stopResult.log, ...clearResult.log, ...convert.log].slice(-60),
  };
  writeState(next);
  const hit = convert.out ? listCaptures().find((c) => c.name === basename(convert.out)) : null;
  if (!convert.ok || !hit) {
    return {
      ok: false,
      error: '已停止抓包，但未生成可分析的 pcapng。若原本没有正在进行的抓包，属正常情况。',
      state: next,
      stopLog: stopResult.log,
      convertLog: convert.log,
    };
  }
  return {
    ok: true,
    backend: 'pktmon',
    state: next,
    capture: { ...hit },
    file: convert.out,
    sizeBytes: convert.size,
    elevatedStop: elevatedUsed,
    hint: `转换完成。用 capture_analyze 传入 id="${hit.id}" 查看流量摘要。`,
  };
}

/**
 * Live status of the running capture, for the panel's polling view.
 * @returns {object}
 */
export function liveStatus() {
  const state = readState();
  if (!state.running) return { running: false, state };
  if (state.backend === 'npcap' && state.file && existsSync(state.file)) {
    const st = countPacketBlocks(state.file);
    return {
      running: true,
      backend: 'npcap',
      state,
      packets: st.packets,
      bytes: st.bytes,
      file: state.file,
      device: state.device,
      ifaceLabel: state.ifaceLabel,
    };
  }
  if (state.backend === 'pktmon') {
    // The ETL is being written by an elevated process; its size shows progress.
    let bytes = 0;
    if (state.etl && existsSync(state.etl)) {
      try { bytes = statSync(state.etl).size; } catch { bytes = 0; }
    }
    return { running: true, backend: 'pktmon', state, etlBytes: bytes, file: state.etl };
  }
  return { running: true, backend: state.backend, state };
}

/** Expose active npcap sessions (diagnostics). */
export function sessions() {
  return npcapActiveSessions();
}
