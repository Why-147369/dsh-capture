/**
 * dsh-capture: one-shot elevated capture helper.
 *
 * Why this exists
 * ---------------
 * `PktMon` is a kernel driver whose device object is Administrators-only, so a
 * non-elevated DSH cannot start a capture at all. Making the whole desktop app
 * run as administrator just to capture packets is a poor trade: every plugin,
 * tool and child process in that session inherits the elevated token.
 *
 * Instead this module delegates *only* the capture actions to a short-lived
 * elevated helper process:
 *
 *   1. DSH (non-elevated) writes a small JSON job file.
 *   2. It launches `powershell.exe -File run-elevated.ps1 <job>` with
 *      `Start-Process -Verb RunAs`, which shows the normal UAC prompt.
 *   3. The helper runs pktmon start/stop and writes a JSON result file.
 *   4. DSH reads the result file. Nothing stays elevated afterwards.
 *
 * The helper is invoked with an argument array and `shell: false`; the job file
 * path is the only variable, and it lives under the plugin's own directory.
 * The PowerShell script itself performs no string interpolation of caller data
 * (it reads the job file with Get-Content and passes values as argv to pktmon).
 *
 * When the user declines UAC, or the platform is not Windows, the caller falls
 * back to the plain non-elevated path and reports the limitation honestly.
 */
import { spawn } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const HERE = dirname(fileURLToPath(import.meta.url));
const HELPER = join(HERE, 'run-elevated.ps1');

/** Generous ceiling: UAC interaction is human-paced. */
const ELEVATED_TIMEOUT_MS = 120000;

/**
 * Whether an elevated helper can be attempted on this machine.
 * @returns {boolean}
 */
export function elevationSupported() {
  return process.platform === 'win32' && existsSync(HELPER);
}

/**
 * Job scratch directory: kept beside the capture files so cleanup is easy.
 * @param {string} base capture directory owned by the plugin
 * @returns {string}
 */
function jobDir(base) {
  const dir = join(base, '.jobs');
  mkdirSync(dir, { recursive: true });
  return dir;
}

/**
 * Run one elevated job.
 *
 * @param {object} params
 * @param {string} params.captureDir plugin capture directory
 * @param {'start'|'stop'|'probe'} params.action what the helper should do
 * @param {object} [params.payload] action-specific fields (name, filters, …)
 * @returns {Promise<{ok:boolean, declined?:boolean, result?:object, error?:string, log:string[]}>}
 */
export function runElevatedCapture({ captureDir, action, payload = {} }) {
  return new Promise((resolve) => {
    const log = [];
    if (!elevationSupported()) {
      resolve({ ok: false, error: '本机不支持提权助手（非 Windows 或缺少 run-elevated.ps1）。', log });
      return;
    }

    const dir = jobDir(captureDir);
    const stamp = `${Date.now()}-${Math.random().toString(16).slice(2, 8)}`;
    const jobPath = join(dir, `job-${stamp}.json`);
    const resPath = join(dir, `res-${stamp}.json`);

    try {
      writeFileSync(jobPath, JSON.stringify({ action, payload, resultPath: resPath }, null, 2), 'utf8');
    } catch (e) {
      resolve({ ok: false, error: `无法写入任务文件：${e.message}`, log });
      return;
    }

    // -Verb RunAs triggers the UAC prompt. -Wait blocks until the helper exits
    // so we read a complete result file. PowerShell is invoked with an argv
    // array and shell:false, so no caller data reaches a shell parser.
    const args = [
      '-NoProfile',
      '-ExecutionPolicy', 'Bypass',
      '-Command',
      `Start-Process -FilePath 'powershell.exe' -Verb RunAs -Wait -WindowStyle Hidden ` +
      `-ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File','${HELPER.replace(/'/g, "''")}','${jobPath.replace(/'/g, "''")}')`,
    ];

    let child;
    try {
      child = spawn('powershell.exe', args, { windowsHide: true, shell: false });
    } catch (e) {
      cleanup(jobPath);
      resolve({ ok: false, error: `无法启动提权助手：${e.message}`, log });
      return;
    }

    let stderr = '';
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      try { child.kill(); } catch { /* already gone */ }
      cleanup(jobPath);
      resolve({ ok: false, declined: true, error: '提权助手等待超时（可能 UAC 被拒绝或未响应）。', log });
    }, ELEVATED_TIMEOUT_MS);

    child.stderr?.on('data', (d) => { stderr += d.toString('utf8'); });
    child.on('error', (e) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      cleanup(jobPath);
      resolve({ ok: false, error: `提权助手启动失败：${e.message}`, log });
    });
    child.on('close', () => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);

      // UAC denial surfaces as a non-zero exit with a specific message.
      const denied = /1223|已取消|canceled|cancelled|拒绝/i.test(stderr);
      let result = null;
      if (existsSync(resPath)) {
        try { result = JSON.parse(readFileSync(resPath, 'utf8')); } catch { result = null; }
      }
      cleanup(jobPath, resPath);

      if (denied) {
        log.push('UAC 被拒绝或取消。');
        resolve({ ok: false, declined: true, error: '用户拒绝了提权请求（UAC）。实时抓包已跳过。', log });
        return;
      }
      if (!result) {
        log.push(`未收到助手结果（stderr: ${stderr.trim().slice(0, 200) || '空'}）。`);
        resolve({ ok: false, error: '提权助手未返回结果。', log });
        return;
      }
      log.push(`助手 action=${action} ok=${result.ok}`);
      resolve({ ok: result.ok === true, result, error: result.ok ? undefined : (result.error || '助手执行失败'), log });
    });
  });
}

/**
 * Best-effort removal of scratch files.
 * @param {...string} paths
 */
function cleanup(...paths) {
  for (const p of paths) {
    try { if (p && existsSync(p)) rmSync(p, { force: true }); } catch { /* best effort */ }
  }
}
