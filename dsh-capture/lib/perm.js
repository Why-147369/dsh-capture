/**
 * dsh-capture: capture capability and permission detection.
 *
 * Windows offers two packet-capture paths, and both are gated by the kernel:
 *
 *   pktmon   — built into Windows 10 1809+ / 11. `PktMon` is a KERNEL_DRIVER
 *              whose device object is Administrators-only, so even the
 *              read-only `pktmon filter list` returns exit 5 ("cannot
 *              communicate with the PktMon driver; access denied") without
 *              elevation.
 *   Npcap    — a third-party driver. When installed with "Restrict Npcap
 *              driver's access to Administrators only" (the installer's
 *              default), HKLM\SOFTWARE\WOW6432Node\Npcap\AdminOnly = 1 and
 *              non-elevated processes cannot open an adapter either. Setting
 *              it to 0 lets a standard user capture, at the cost of letting
 *              *every* local user capture.
 *
 * This module reports exactly which situation the machine is in and what the
 * user can do about it, so the panel and the agent tools can explain a failure
 * instead of showing an empty list. It never writes to the registry and never
 * demands elevation on its own.
 */
import { existsSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { run } from './pktmon.js';
import { runElevatedCapture, elevationSupported } from './elevate.js';

const SYS = process.env.SystemRoot || 'C:\\Windows';
const PKTMON = join(SYS, 'System32', 'PktMon.exe');
const NPCAP_DIRS = [
  join(SYS, 'System32', 'Npcap'),
  join(SYS, 'System32'),
];
/** Npcap writes its options under the 32-bit view of HKLM. */
const NPCAP_KEY_WOW = 'HKLM\\SOFTWARE\\WOW6432Node\\Npcap';
const NPCAP_KEY_NATIVE = 'HKLM\\SOFTWARE\\Npcap';

/**
 * Read a single registry value, returning null when absent.
 * @param {string} key
 * @param {string} name
 * @returns {Promise<string|null>}
 */
async function regQuery(key, name) {
  const r = await run('reg', ['query', key, '/v', name], { timeoutMs: 8000 });
  if (r.code !== 0) return null;
  // Output shape: "    Name    REG_TYPE    value"
  const m = new RegExp(`${name}\\s+REG_\\w+\\s+(.+)`, 'i').exec(r.stdout);
  return m ? m[1].trim() : null;
}

/**
 * Locate the Npcap runtime directory, if Npcap is installed.
 * @returns {string|null}
 */
export function npcapDir() {
  for (const dir of NPCAP_DIRS) {
    if (existsSync(join(dir, 'wpcap.dll'))) return dir;
  }
  return null;
}

/**
 * Describe the Npcap installation: presence, driver state, AdminOnly flag.
 * @returns {Promise<object>}
 */
export async function probeNpcap() {
  const dir = npcapDir();
  const out = {
    installed: dir !== null,
    dir,
    hasWpcap: false,
    hasPacket: false,
    hasHelper: false,
    driverRunning: false,
    adminOnly: null,
    clickableCapture: false,
    notes: [],
  };
  if (!dir) {
    out.notes.push('未检测到 Npcap。');
    return out;
  }
  out.hasWpcap = existsSync(join(dir, 'wpcap.dll'));
  out.hasPacket = existsSync(join(dir, 'Packet.dll'));
  out.hasHelper = existsSync(join(dir, 'NpcapHelper.exe'));

  // Driver state. `sc query npcap` is readable without elevation.
  const sc = await run('sc', ['query', 'npcap'], { timeoutMs: 8000 });
  out.driverRunning = /STATE\s*:\s*4/.test(sc.stdout);

  // AdminOnly lives in the 32-bit view on 64-bit Windows; check both.
  let raw = await regQuery(NPCAP_KEY_WOW, 'AdminOnly');
  if (raw === null) raw = await regQuery(NPCAP_KEY_NATIVE, 'AdminOnly');
  if (raw !== null) {
    // "0x1" or "1"
    const n = /^0x/i.test(raw) ? parseInt(raw, 16) : Number(raw);
    out.adminOnly = Number.isFinite(n) ? n : null;
  }

  if (!out.driverRunning) {
    out.notes.push('Npcap 驱动未运行（服务 npcap 不是 RUNNING 状态）。');
  } else if (out.adminOnly === 1) {
    out.clickableCapture = false;
    out.notes.push('Npcap 已安装但设置了「仅管理员可访问」（AdminOnly=1），非提权进程打不开网卡。');
    out.notes.push('若要免管理员抓包，以管理员身份执行一次：');
    out.notes.push(`  reg add "${NPCAP_KEY_WOW}" /v AdminOnly /t REG_DWORD /d 0 /f`);
    out.notes.push('注意：这会让本机所有用户都能抓包，请自行权衡。');
  } else if (out.adminOnly === 0) {
    out.clickableCapture = out.hasWpcap && out.hasPacket;
    out.notes.push('Npcap 已放宽权限（AdminOnly=0），标准用户即可抓包。');
  } else {
    out.notes.push('Npcap 已安装，未能读取 AdminOnly（可能未设置或权限不足）。');
  }
  return out;
}

/**
 * Whether a third-party CLI the plugin could delegate to is present.
 * Wireshark/tshark would give a ready-made capture path when Npcap is usable.
 * @returns {Promise<object>}
 */
export async function probeCliTools() {
  const tools = ['tshark', 'dumpcap'];
  const found = {};
  for (const t of tools) {
    const r = await run('where', [t], { timeoutMs: 6000 });
    found[t] = r.code === 0 ? (r.stdout.split('\n')[0] || '').trim() : null;
  }
  return found;
}

/**
 * Full environment report. This is the single source of truth for the panel,
 * the `capture_probe` tool, and the start/stop flows.
 * @returns {Promise<object>}
 */
export async function probeEnvironment() {
  const pktmonExists = existsSync(PKTMON);
  const result = {
    platform: process.platform,
    isWindows: process.platform === 'win32',
    pktmonPath: PKTMON,
    pktmonExists,
    pktmonUsable: false,
    pktmonNeedsElevation: false,
    npcap: null,
    cli: null,
    elevation: null,
    /** True when at least one path can capture without prompting the user. */
    canCapture: false,
    /** True when a capture is possible only after a one-time elevation. */
    canCaptureWithElevation: false,
    notes: [],
  };

  if (!result.isWindows) {
    result.notes.push(`当前平台 ${process.platform} 不受支持：本插件目前仅适配 Windows（pktmon / Npcap）。`);
    return result;
  }

  // --- pktmon ---
  if (!pktmonExists) {
    result.notes.push('未找到 pktmon（需要 Windows 10 1809+ / Windows 11）。');
  } else {
    // `filter list` is the cheap read-only probe; it also reveals elevation.
    const f = await run(PKTMON, ['filter', 'list'], { timeoutMs: 12000 });
    const text = `${f.stdout}\n${f.stderr}`;
    if (/access is denied|拒绝访问|无法与 PktMon 驱动程序通信/i.test(text)) {
      result.pktmonNeedsElevation = true;
      result.notes.push('pktmon 需管理员权限（PktMon 是内核驱动，设备对象只对管理员开放）。');
    } else if (f.code === 0) {
      result.pktmonUsable = true;
      result.canCapture = true;
      result.notes.push('pktmon 可用，可直接实时抓包。');
    } else {
      result.notes.push(`pktmon 探测返回 code=${f.code}：${text.trim().slice(0, 200) || '(无输出)'}`);
    }
  }

  // --- Npcap ---
  result.npcap = await probeNpcap();
  if (result.npcap.clickableCapture) {
    result.canCapture = true;
  }

  // --- 可委派的第三方 CLI ---
  result.cli = await probeCliTools();
  const tsharkPath = result.cli.tshark;
  if (tsharkPath) {
    result.notes.push(`检测到 tshark：${tsharkPath}（可作为抓包后端）。`);
  }

  // --- 提权代理可用性 ---
  result.elevation = {
    supported: elevationSupported(),
    mechanism: 'runas-helper',
    detail: result.pktmonExists
      ? '可经 UAC 提权一次性启动抓包助手，无需让 DSH 常驻管理员。'
      : '缺少 pktmon，提权也无后端可用。',
  };
  if (!result.canCapture && result.pktmonExists && elevationSupported()) {
    result.canCaptureWithElevation = true;
  }

  if (!result.canCapture && !result.canCaptureWithElevation) {
    result.notes.push('当前没有可用的抓包路径。');
  }
  return result;
}
