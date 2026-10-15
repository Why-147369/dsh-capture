/**
 * dsh-capture: helpers shared by the HTTP routes and the agent tools.
 *
 * Kept separate from index.js so the tool surface stays small and the file
 * scan/resolve logic has exactly one implementation. Capture ids are opaque
 * hashes over the file name, so a crafted id can never escape the capture
 * directory.
 */
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { basename, join } from 'node:path';
import { homedir } from 'node:os';
import { probeBackend, setFilters, clearFilters, startCapture, stopCapture, etl2pcap } from './pktmon.js';

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
    return { running: false, etl: null, pcapng: null, startedAt: null, filters: [], log: [] };
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
 * @returns {Array<{id:string,name:string,size:number,kind:string,mtime:number}>}
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
    out.push({
      id: createHash('sha256').update(name).digest('hex').slice(0, 16),
      name,
      size: st.size,
      kind: name.toLowerCase().endsWith('.etl') ? 'etl' : 'capture',
      mtime: st.mtimeMs,
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
 * Start a capture end to end: probe, set filters, start pktmon.
 * @param {{name?:string, filters?:Array<object>, maxPktSize?:number, maxFileMb?:number, components?:string[]}} opts
 * @returns {Promise<object>}
 */
export async function startCaptureFlow(opts = {}) {
  const state = readState();
  if (state.running && state.etl) {
    return { ok: false, error: '已有抓包在进行中。先调用 capture_stop 结束当前抓包。', state };
  }
  const probe = await probeBackend();
  if (!probe.pktmonExists) {
    return { ok: false, error: '本机没有 pktmon（Windows 10 1809+ / 11 自带）。无法抓包。', probe };
  }
  if (probe.needsElevation) {
    return {
      ok: false,
      error: 'pktmon 需要管理员权限，而 DSH 当前是非提权进程。可选做法：以管理员身份运行 DSH，或先用提权终端手动抓包后改用 capture_analyze 做离线分析。',
      probe,
    };
  }

  const dir = captureDir();
  const name = safeName(opts.name);
  const filters = Array.isArray(opts.filters)
    ? opts.filters.filter((f) => f && (f.ip || Number.isFinite(Number(f.port)) || f.protocol)).slice(0, 16)
    : [];
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
    return { ok: false, error: '启动 pktmon 抓包失败。', filterLog: filterResult.log, log: startResult.log, probe };
  }
  const next = {
    running: true,
    etl: startResult.etl,
    pcapng: null,
    startedAt: Date.now(),
    name,
    filters,
    log: [...filterResult.log, ...startResult.log].slice(-40),
  };
  writeState(next);
  return { ok: true, state: next, dir, hint: '抓包已开始。完成后调用 capture_stop 结束并转换为 pcapng。' };
}

/**
 * Stop the capture, clear filters, and convert ETL to pcapng.
 * @returns {Promise<object>}
 */
export async function stopCaptureFlow() {
  const state = readState();
  const stopResult = await stopCapture();
  const clearResult = await clearFilters();
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
    state: next,
    capture: { ...hit },
    sizeBytes: convert.size,
    hint: `转换完成。用 capture_analyze 传入 id="${hit.id}" 查看流量摘要。`,
  };
}
