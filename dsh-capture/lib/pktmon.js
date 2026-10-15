/**
 * dsh-capture: capture backends.
 *
 * Primary backend is Windows' built-in `pktmon`, which needs no third-party
 * install. Flow:
 *   1. `pktmon filter remove` then optional `pktmon filter add` rules
 *   2. `pktmon start --capture --comp nics --pkt-size N --file-name <etl>`
 *   3. `pktmon stop`
 *   4. `pktmon etl2pcap <etl> --out <pcapng>`
 *   5. `pktmon filter remove` (cleanup)
 *
 * All child processes are spawned with shell:false and argv arrays so no
 * user-supplied string is ever interpolated into a shell command.
 *
 * A small capability probe reports whether pktmon exists and whether we can
 * run it, so the UI can explain the failure instead of showing an empty list.
 */
import { spawn } from 'node:child_process';
import { existsSync, mkdirSync, rmSync, statSync } from 'node:fs';
import { join } from 'node:path';

const PKTMON = join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'PktMon.exe');

/**
 * Run a command and capture stdout/stderr with a timeout.
 * @param {string} cmd
 * @param {string[]} args
 * @param {{timeoutMs?: number}} [opts]
 * @returns {Promise<{code:number|null, stdout:string, stderr:string, timedOut:boolean}>}
 */
export function run(cmd, args, opts = {}) {
  const timeoutMs = Number.isFinite(opts.timeoutMs) ? opts.timeoutMs : 30000;
  return new Promise((resolve) => {
    let child;
    try {
      child = spawn(cmd, args, { windowsHide: true, shell: false });
    } catch (err) {
      resolve({ code: null, stdout: '', stderr: String(err && err.message), timedOut: false, spawnError: true });
      return;
    }
    let out = '';
    let err = '';
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      try { child.kill(); } catch { /* already gone */ }
    }, timeoutMs);
    child.stdout?.on('data', (d) => { out += d.toString('utf8'); });
    child.stderr?.on('data', (d) => { err += d.toString('utf8'); });
    child.on('error', (e) => { err += String(e && e.message); });
    child.on('close', (code) => {
      clearTimeout(timer);
      resolve({ code, stdout: out, stderr: err, timedOut });
    });
  });
}

/**
 * Probe what capture capability this machine has.
 * @returns {Promise<object>}
 */
export async function probeBackend() {
  const hasPktmon = existsSync(PKTMON);
  const result = {
    pktmonPath: PKTMON,
    pktmonExists: hasPktmon,
    pktmonVersion: null,
    canRun: false,
    needsElevation: false,
    backend: null,
    notes: [],
  };
  if (!hasPktmon) {
    result.notes.push('未找到 pktmon（Windows 自带的抓包组件）。需要 Windows 10 1809+ / Windows 11。');
    return result;
  }
  const v = await run(PKTMON, ['--version'], { timeoutMs: 8000 });
  // pktmon --version is unsupported on some builds; the help banner is enough.
  result.pktmonVersion = (v.stdout + v.stderr).trim().slice(0, 300) || null;

  // `pktmon filter list` is read-only and tells us whether we can talk to the driver.
  const f = await run(PKTMON, ['filter', 'list'], { timeoutMs: 15000 });
  const text = `${f.stdout}\n${f.stderr}`;
  if (/access is denied|拒绝访问|需要提升|管理员/i.test(text)) {
    result.needsElevation = true;
    result.notes.push('pktmon 需要管理员权限（DSH 当前是非提权进程）。');
    result.notes.push('可选做法：以管理员身份运行 DSH，或先用提权终端手动抓包再由本插件做离线分析。');
  } else if (f.code === 0 || /filter|筛选|Filter/i.test(text)) {
    result.canRun = true;
    result.backend = 'pktmon';
    result.notes.push('pktmon 可用，支持实时抓包。');
  } else {
    result.notes.push(`pktmon 探测返回 code=${f.code}：${text.trim().slice(0, 200) || '(无输出)'}`);
  }
  return result;
}

/**
 * Replace the driver's filter set with the requested rules.
 * @param {Array<{ip?:string, port?:number, protocol?:string}>} filters
 * @returns {Promise<{ok:boolean, log:string[]}>}
 */
export async function setFilters(filters) {
  const log = [];
  const clear = await run(PKTMON, ['filter', 'remove'], { timeoutMs: 15000 });
  log.push(`filter remove -> code=${clear.code}`);
  for (const f of filters || []) {
    const args = ['filter', 'add', '--name', `dsh-capture-${Date.now()}`];
    if (f.ip) args.push('--ip', String(f.ip));
    if (Number.isFinite(f.port)) args.push('--port', String(f.port));
    if (f.protocol && ['TCP', 'UDP', 'ICMP'].includes(String(f.protocol).toUpperCase())) {
      args.push('--transport', String(f.protocol).toUpperCase());
    }
    const r = await run(PKTMON, args, { timeoutMs: 15000 });
    log.push(`filter add ${args.slice(3).join(' ')} -> code=${r.code} ${(r.stdout || r.stderr).trim().slice(0, 120)}`);
  }
  return { ok: true, log };
}

/**
 * Clear all pktmon filters (cleanup after a session).
 * @returns {Promise<{ok:boolean, log:string[]}>}
 */
export async function clearFilters() {
  const r = await run(PKTMON, ['filter', 'remove'], { timeoutMs: 15000 });
  return { ok: r.code === 0, log: [`filter remove -> code=${r.code} ${(r.stdout || r.stderr).trim().slice(0, 120)}`] };
}

/**
 * Stop any capture already in progress. Safe to call when none is running.
 * @returns {Promise<{ok:boolean, log:string[]}>}
 */
export async function stopCapture() {
  const r = await run(PKTMON, ['stop'], { timeoutMs: 30000 });
  const text = `${r.stdout}\n${r.stderr}`;
  const notRunning = /no.*(session|trace)|没有|未在/i.test(text);
  return {
    ok: r.code === 0 || notRunning,
    log: [`pktmon stop -> code=${r.code} ${text.trim().slice(0, 200)}`],
  };
}

/**
 * Start a capture writing an ETL file.
 * @param {{dir:string, name:string, maxPktSize?:number, maxFileMb?:number, components?:string[]}} opts
 * @returns {Promise<{ok:boolean, etl:string, log:string[]}>}
 */
export async function startCapture(opts) {
  const dir = opts.dir;
  mkdirSync(dir, { recursive: true });
  const etl = join(dir, `${opts.name || 'capture'}.etl`);
  // A previous run's file would make pktmon refuse; remove it first.
  if (existsSync(etl)) {
    try { rmSync(etl, { force: true }); } catch { /* best effort */ }
  }
  const pktSize = Number.isFinite(opts.maxPktSize) ? Math.max(64, Math.min(0x40000, opts.maxPktSize)) : 0x100;
  const components = Array.isArray(opts.components) && opts.components.length ? opts.components : ['nics'];
  const args = ['start', '--capture', '--comp', components.join(','), '--pkt-size', String(pktSize), '--file-name', etl];
  if (Number.isFinite(opts.maxFileMb) && opts.maxFileMb > 0) {
    args.push('--file-size', String(Math.round(opts.maxFileMb)));
  }
  const r = await run(PKTMON, args, { timeoutMs: 45000 });
  const text = `${r.stdout}\n${r.stderr}`.trim();
  const ok = r.code === 0 && !/error|失败|denied/i.test(text);
  return { ok, etl, log: [`pktmon ${args.join(' ')} -> code=${r.code}`, text.slice(0, 400)] };
}

/**
 * Convert an ETL to pcapng.
 * @param {string} etl
 * @param {string} out
 * @returns {Promise<{ok:boolean, out:string, log:string[], size:number|null}>}
 */
export async function etl2pcap(etl, out) {
  if (existsSync(out)) {
    try { rmSync(out, { force: true }); } catch { /* best effort */ }
  }
  const r = await run(PKTMON, ['etl2pcap', etl, '--out', out], { timeoutMs: 180000 });
  const text = `${r.stdout}\n${r.stderr}`.trim();
  let size = null;
  if (existsSync(out)) {
    try { size = statSync(out).size; } catch { size = null; }
  }
  return { ok: r.code === 0 && size !== null, out, size, log: [`pktmon etl2pcap -> code=${r.code}`, text.slice(0, 400)] };
}

/**
 * Read the current pktmon status text (useful for diagnosing a stuck session).
 * @returns {Promise<string>}
 */
export async function status() {
  const r = await run(PKTMON, ['filter', 'list'], { timeoutMs: 15000 });
  return (r.stdout || r.stderr || '').trim().slice(0, 500);
}
