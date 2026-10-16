/**
 * dsh-capture: capture backend selection and environment reporting.
 *
 * Windows offers two capture paths with very different privilege stories.
 * This module picks one and explains the choice, so the panel and the agent
 * tools never have to guess why a capture failed.
 *
 *   npcap   — preferred. Shipped with Wireshark; `dumpcap.exe` declares
 *             `asInvoker`, so a standard user captures without elevation.
 *             Npcap may ask for confirmation once per process that opens an
 *             adapter (an NpcapHelper prompt, not a UAC prompt), which is why
 *             the adapter list is cached.
 *   pktmon  — fallback. `PktMon` is a KERNEL_DRIVER whose device object is
 *             Administrators-only: even the read-only `pktmon filter list`
 *             returns exit 5 without elevation. Capturing therefore needs an
 *             elevated process; `elevate.js` provides a one-shot helper so the
 *             whole DSH does not have to run elevated.
 *
 * Measured on the development machine: `AdminOnly=1` in Npcap's registry key
 * did NOT prevent non-elevated capture, and three consecutive captures yielded
 * 164 / 100 / 83 packets without elevation. An earlier conclusion that
 * "capture requires administrator rights" was wrong — it generalised from
 * pktmon alone.
 */
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { run } from './pktmon.js';
import { elevationSupported } from './elevate.js';
import { probe as probeNpcap, listInterfaces, pickDefaultInterface, invalidateInterfaceCache } from './npcap.js';

const SYS = process.env.SystemRoot || 'C:\\Windows';
const PKTMON = join(SYS, 'System32', 'PktMon.exe');
const NPCAP_KEY_WOW = 'HKLM\\SOFTWARE\\WOW6432Node\\Npcap';
const NPCAP_KEY_NATIVE = 'HKLM\\SOFTWARE\\Npcap';

/**
 * Read one registry value, or null when absent.
 * @param {string} key
 * @param {string} name
 * @returns {Promise<string|null>}
 */
async function regQuery(key, name) {
  const r = await run('reg', ['query', key, '/v', name], { timeoutMs: 8000 });
  if (r.code !== 0) return null;
  const m = new RegExp(`${name}\\s+REG_\\w+\\s+(.+)`, 'i').exec(r.stdout);
  return m ? m[1].trim() : null;
}

/**
 * Npcap's own configuration, reported for diagnostics.
 *
 * `AdminOnly` is surfaced informationally: it did not gate capture on the
 * test machine, so the module never treats it as a hard blocker.
 * @returns {Promise<object>}
 */
export async function probeNpcapConfig() {
  const out = { adminOnly: null, winPcapCompatible: null, dir: null };
  let raw = await regQuery(NPCAP_KEY_WOW, 'AdminOnly');
  if (raw === null) raw = await regQuery(NPCAP_KEY_NATIVE, 'AdminOnly');
  if (raw !== null) {
    const n = /^0x/i.test(raw) ? parseInt(raw, 16) : Number(raw);
    out.adminOnly = Number.isFinite(n) ? n : null;
  }
  const wc = await regQuery(NPCAP_KEY_WOW, 'WinPcapCompatible')
    ?? await regQuery(NPCAP_KEY_NATIVE, 'WinPcapCompatible');
  if (wc !== null) {
    const n = /^0x/i.test(wc) ? parseInt(wc, 16) : Number(wc);
    out.winPcapCompatible = Number.isFinite(n) ? n : null;
  }
  out.dir = await regQuery(NPCAP_KEY_WOW, '')
    ?? null;
  return out;
}

/**
 * Whether pktmon exists and whether it is usable without elevation.
 * @returns {Promise<object>}
 */
export async function probePktmon() {
  const exists = existsSync(PKTMON);
  const out = { path: PKTMON, exists, usable: false, needsElevation: false, note: null };
  if (!exists) {
    out.note = '未找到 pktmon（需要 Windows 10 1809+ / Windows 11）。';
    return out;
  }
  // `filter list` is the cheap read-only probe; the error text distinguishes
  // "not elevated" from other failures.
  const f = await run(PKTMON, ['filter', 'list'], { timeoutMs: 12000 });
  const text = `${f.stdout}\n${f.stderr}`;
  if (/access is denied|拒绝访问|无法与 PktMon 驱动程序通信/i.test(text)) {
    out.needsElevation = true;
    out.note = 'pktmon 需管理员权限（PktMon 是内核驱动，设备对象只对管理员开放）。';
  } else if (f.code === 0) {
    out.usable = true;
    out.note = 'pktmon 可用（当前进程已提权）。';
  } else {
    out.note = `pktmon 探测返回 code=${f.code}：${text.trim().slice(0, 200) || '(无输出)'}`;
  }
  return out;
}

/**
 * Choose the backend for this machine.
 *
 * Preference order is npcap → pktmon + elevation → none, because npcap needs
 * no elevation at all. `refreshInterfaces` forces a re-enumeration (which may
 * cost one Npcap confirmation prompt).
 *
 * @param {{refreshInterfaces?:boolean}} [opts]
 * @returns {Promise<object>}
 */
export async function probeEnvironment(opts = {}) {
  const result = {
    platform: process.platform,
    isWindows: process.platform === 'win32',
    backend: null,
    canCapture: false,
    /** True when a capture is only possible through the elevation prompt. */
    needsElevation: false,
    npcap: null,
    npcapConfig: null,
    pktmon: null,
    interfaces: [],
    defaultInterface: null,
    elevation: null,
    notes: [],
  };

  if (!result.isWindows) {
    result.notes.push(`当前平台 ${process.platform} 不受支持：本插件目前仅适配 Windows。`);
    return result;
  }

  // --- Npcap (preferred: no elevation) ---
  if (opts.refreshInterfaces) invalidateInterfaceCache();
  const np = await probeNpcap();
  result.npcap = {
    available: np.available,
    dir: np.dir,
    dumpcap: np.dumpcap || null,
    tshark: np.tshark || null,
    interfaceCount: (np.interfaces || []).length,
    reason: np.reason || null,
  };
  result.npcapConfig = await probeNpcapConfig();
  if (np.available) {
    result.interfaces = np.interfaces || [];
    result.defaultInterface = pickDefaultInterface(result.interfaces);
    result.backend = 'npcap';
    result.canCapture = true;
    result.notes.push(`Npcap 可用（Wireshark: ${np.dir}），无需管理员权限抓包。`);
    if (!result.defaultInterface) {
      result.canCapture = false;
      result.backend = null;
      result.notes.push('Npcap 可用但未找到物理网卡（只有虚拟/环回适配器）。');
    } else {
      result.notes.push(`默认网卡：${result.defaultInterface.label}（${result.defaultInterface.kind}）。`);
    }
    if (result.npcapConfig.adminOnly === 1) {
      result.notes.push('注：Npcap 的 AdminOnly=1，但实测不阻止非提权抓包；首次打开网卡可能弹一次 Npcap 确认框。');
    }
  } else {
    result.notes.push(`Npcap 不可用：${np.reason || '未检测到 Wireshark / dumpcap.exe'}。`);
  }

  // --- pktmon (fallback, needs elevation) ---
  result.pktmon = await probePktmon();
  if (result.pktmon.note) result.notes.push(result.pktmon.note);

  // --- elevation helper availability ---
  result.elevation = {
    supported: elevationSupported(),
    mechanism: 'runas-helper',
    detail: '经 UAC 启动一次性抓包助手，DSH 本身保持普通权限。',
  };

  // Only offer the pktmon path when Npcap is unusable.
  if (!result.canCapture && result.pktmon.exists) {
    if (result.pktmon.usable) {
      result.backend = 'pktmon';
      result.canCapture = true;
      result.notes.push('将使用 pktmon（当前进程已提权）。');
    } else if (result.pktmon.needsElevation) {
      result.needsElevation = true;
      if (result.elevation.supported) {
        result.backend = 'pktmon';
        result.canCapture = true;
        result.notes.push('将使用 pktmon + 一次性提权助手（会弹一次 UAC）。');
        result.notes.push('若希望完全免提权：安装 Wireshark（自带 Npcap），本插件会自动改用它。');
      } else {
        result.notes.push('pktmon 需提权，但提权助手不可用（缺少 run-elevated.ps1）。');
      }
    }
  }

  if (!result.canCapture) {
    result.notes.push('当前没有可用的抓包路径。');
  }
  return result;
}

/**
 * Backend summary for a UI badge.
 * @param {object} env result of probeEnvironment
 * @returns {string}
 */
export function backendLabel(env) {
  if (!env) return '未知';
  if (env.backend === 'npcap') return 'Npcap (dumpcap)';
  if (env.backend === 'pktmon') return env.needsElevation ? 'pktmon (需提权)' : 'pktmon';
  return '不可用';
}
