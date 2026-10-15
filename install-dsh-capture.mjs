/**
 * 把本仓库的 dsh-capture 安装到 DSH 的 desktop profile。
 *
 * 打包来源：https://github.com/Why-147369/dsh-capture
 * 状态：**未开发完成，测试阶段** —— 仅建议在本地开发环境使用。
 *
 * 流程（与 dshmarket / 其他社区插件一致）：
 *   备份 package.json + pnpm-lock.yaml + pnpm-workspace.yaml
 *   → 改 dependencies（file: 本仓库内的插件目录）
 *   → dsh.profile.bundles 加入 dsh-capture
 *   → 用 DSH 自带 pnpm install
 *   → 校验安装结果，失败自动还原三文件
 *
 * 用法:
 *   node install-dsh-capture.mjs                     安装
 *   node install-dsh-capture.mjs --dry-run           只检查不写
 *   node install-dsh-capture.mjs --restore "<备份目录>"  回滚
 *
 * 注意：desktop profile 由 Electron App 独占管理，`dsh plugin --profile desktop`
 * 会被拒，所以只能走文件方式；装完需完全退出并重启 DSH App 才生效。
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

// 仓库根 = 本脚本所在目录；插件源码固定在其下的 dsh-capture/
const REPO_ROOT = path.dirname(fileURLToPath(import.meta.url));
const SRC = path.join(REPO_ROOT, 'dsh-capture');
const PKG_NAME = 'dsh-capture';

/** profile 目录：优先环境变量，其次默认路径，最后允许命令行传入。 */
function resolveProfile() {
  const fromArg = process.argv.find((a) => a.startsWith('--profile='));
  if (fromArg) return fromArg.slice('--profile='.length);
  if (process.env.DSH_PROFILE_DIR) return process.env.DSH_PROFILE_DIR;
  const home = process.env.DSH_HOME || path.join(process.env.USERPROFILE || '', '.dsh');
  return path.join(home, 'profiles', 'desktop');
}
const PROFILE = resolveProfile();

/** DSH 自带 pnpm；找不到时回退到 PATH 上的 pnpm。 */
function resolvePnpm() {
  const candidates = [
    process.env.DSH_PNPM,
    'E:\\dsh\\resources\\runtime\\pnpm\\bin\\pnpm.cjs',
    path.join(process.env.ProgramFiles || 'C:\\Program Files', 'DeepSeek Harness', 'resources', 'runtime', 'pnpm', 'bin', 'pnpm.cjs'),
  ].filter(Boolean);
  for (const c of candidates) if (fs.existsSync(c)) return c;
  return null;
}

const THREE = ['package.json', 'pnpm-lock.yaml', 'pnpm-workspace.yaml'];
const lines = [];
const say = (s) => { lines.push(s); console.log(s); };
const dry = process.argv.includes('--dry-run');

const stamp = new Date().toISOString().replace(/[-:T]/g, '').slice(0, 14);
const backup = path.join(REPO_ROOT, 'backup-dsh-capture-' + stamp);

// ---- 回滚模式 ----
if (process.argv[2] === '--restore') {
  const from = process.argv[3];
  if (!from || !fs.existsSync(from)) {
    console.error('用法: node install-dsh-capture.mjs --restore "<备份目录>"');
    process.exit(1);
  }
  for (const f of THREE) {
    const s = path.join(from, f);
    if (fs.existsSync(s)) { fs.copyFileSync(s, path.join(PROFILE, f)); console.log('restored ' + f); }
    else console.log('skip (not in backup): ' + f);
  }
  console.log('已回滚。重启 DSH App 生效。');
  process.exit(0);
}

say(`START ${PKG_NAME} -> ${PROFILE}`);
say(`SOURCE=${SRC}`);
say(`dry-run=${dry}`);

// ---- 前置检查 ----
if (!fs.existsSync(path.join(SRC, 'package.json'))) {
  say('FAILED: 找不到 dsh-capture/package.json —— 请在仓库根目录运行本脚本。');
  process.exit(1);
}
if (!fs.existsSync(PROFILE)) {
  say(`FAILED: profile 目录不存在：${PROFILE}`);
  say('如果 DSH 装在别处，用 --profile=<路径> 或设置 DSH_PROFILE_DIR。');
  process.exit(1);
}
const srcPkg = JSON.parse(fs.readFileSync(path.join(SRC, 'package.json'), 'utf8'));
if (srcPkg.name !== PKG_NAME) { say(`FAILED: package.json name=${srcPkg.name}，期望 ${PKG_NAME}`); process.exit(1); }
if (!srcPkg.dsh?.bundle?.patch) { say('FAILED: package.json 缺少 dsh.bundle.patch'); process.exit(1); }
if (!fs.existsSync(path.join(SRC, 'lib', 'index.js'))) { say('FAILED: 缺少 lib/index.js'); process.exit(1); }
if (!fs.existsSync(path.join(SRC, 'client', 'client.js'))) { say('WARN: 缺少 client/client.js（设置页面板将不加载）'); }
say(`源包校验通过: ${srcPkg.name}@${srcPkg.version}  patch=${srcPkg.dsh.bundle.patch}`);

const pnpm = resolvePnpm();
say(`pnpm: ${pnpm || '未找到（尝试 PATH 上的 pnpm）'}`);

// ---- 已装则拒绝，避免重复 patch ----
const profilePkgPath = path.join(PROFILE, 'package.json');
const pj = JSON.parse(fs.readFileSync(profilePkgPath, 'utf8'));
if (pj.dependencies && pj.dependencies[PKG_NAME]) {
  say(`ALREADY_PRESENT ${PKG_NAME}=${pj.dependencies[PKG_NAME]}（profile 未改动）`);
  say('如需升级：先移除该依赖或改路径，再重跑本脚本；也可用 sync-dsh-capture.mjs 只同步源码。');
  process.exit(0);
}
say(`profile bundles 现有 ${(pj.dsh?.profile?.bundles || []).length} 项`);

if (dry) {
  say('DRY-RUN：将写入的依赖值 = file:' + SRC);
  say(`DRY-RUN：将把 ${PKG_NAME} 加入 dsh.profile.bundles`);
  say('DRY-RUN 结束，未改动任何文件。');
  fs.writeFileSync(path.join(REPO_ROOT, 'install-dsh-capture.log'), lines.join('\n') + '\n', 'utf8');
  process.exit(0);
}

let backupDone = false;
try {
  // 1) 备份
  fs.mkdirSync(backup, { recursive: true });
  for (const f of THREE) {
    const s = path.join(PROFILE, f);
    if (fs.existsSync(s)) fs.copyFileSync(s, path.join(backup, f));
  }
  backupDone = true;
  say('BACKUP -> ' + backup);

  // 2) 改 package.json
  pj.dependencies = pj.dependencies || {};
  pj.dependencies[PKG_NAME] = 'file:' + SRC;
  const sorted = {};
  for (const k of Object.keys(pj.dependencies).sort()) sorted[k] = pj.dependencies[k];
  pj.dependencies = sorted;
  pj.dsh = pj.dsh || {};
  pj.dsh.profile = pj.dsh.profile || {};
  pj.dsh.profile.bundles = pj.dsh.profile.bundles || [];
  if (!pj.dsh.profile.bundles.includes(PKG_NAME)) pj.dsh.profile.bundles.push(PKG_NAME);
  fs.writeFileSync(profilePkgPath, JSON.stringify(pj, null, 2) + '\n', 'utf8');

  const back = JSON.parse(fs.readFileSync(profilePkgPath, 'utf8'));
  if (!back.dependencies[PKG_NAME] || !back.dsh.profile.bundles.includes(PKG_NAME)) throw new Error('PATCH_VERIFY_FAILED');
  say(`patched: dep=${back.dependencies[PKG_NAME]}`);
  say(`patched: bundles=${back.dsh.profile.bundles.length} 含 ${PKG_NAME}`);

  // 3) pnpm install（输出写文件，避开管道 EPERM 与 pwsh 吞输出）
  const outLog = path.join(backup, 'pnpm.out.log');
  const errLog = path.join(backup, 'pnpm.err.log');
  const outFd = fs.openSync(outLog, 'w');
  const errFd = fs.openSync(errLog, 'w');
  const args = pnpm
    ? [pnpm, 'install']
    : ['install'];
  const r = spawnSync(pnpm ? process.execPath : 'pnpm', args, {
    cwd: PROFILE, stdio: ['ignore', outFd, errFd], shell: !pnpm,
  });
  fs.closeSync(outFd); fs.closeSync(errFd);
  const out = fs.readFileSync(outLog, 'utf8');
  const err = fs.readFileSync(errLog, 'utf8');
  say(`pnpm exit=${r.status}`);
  for (const l of (out + err).trim().split('\n').slice(-16)) say('  | ' + l.slice(0, 170));
  if (r.status !== 0) throw new Error('pnpm install failed exit=' + r.status);

  // 4) 校验安装结果
  const instDir = path.join(PROFILE, 'node_modules', PKG_NAME);
  if (!fs.existsSync(path.join(instDir, 'package.json'))) throw new Error('node_modules/' + PKG_NAME + ' 不存在');
  const ver = JSON.parse(fs.readFileSync(path.join(instDir, 'package.json'), 'utf8')).version;
  say('INSTALLED_VERSION=' + ver);
  const check = ['lib/index.js', 'lib/routes.js', 'lib/pcap.js', 'lib/pktmon.js', 'lib/tools.js', 'client/client.js', 'cordis.patch.yml', 'icon.svg', 'package.json'];
  let missing = 0;
  for (const f of check) {
    const p = path.join(instDir, f);
    if (fs.existsSync(p)) say(`  ${f} OK ${(fs.statSync(p).size / 1024).toFixed(1)}KB`);
    else { say(`  ${f} MISSING`); missing++; }
  }
  if (missing) throw new Error(`${missing} 个文件未安装成功`);

  say('');
  say('INSTALL_OK —— 需完全退出并重启 DSH App 才生效');
  say('重启后：设置 → 「抓包 Capture」分区可见；或用 agent 工具 capture_probe 检查能力。');
  say('提示：本插件为测试阶段版本，实时抓包需管理员权限。');
} catch (e) {
  say('FAILED: ' + e.message);
  if (backupDone) {
    for (const f of THREE) {
      const s = path.join(backup, f);
      if (fs.existsSync(s)) fs.copyFileSync(s, path.join(PROFILE, f));
    }
    say('已从备份还原 profile 三文件');
    say('回滚: node install-dsh-capture.mjs --restore "' + backup + '"');
  } else {
    say('备份未完成，profile 未被修改');
  }
  fs.writeFileSync(path.join(REPO_ROOT, 'install-dsh-capture.log'), lines.join('\n') + '\n', 'utf8');
  process.exit(1);
}

fs.writeFileSync(path.join(REPO_ROOT, 'install-dsh-capture.log'), lines.join('\n') + '\n', 'utf8');
say('LOG=' + path.join(REPO_ROOT, 'install-dsh-capture.log'));
say('回滚: node install-dsh-capture.mjs --restore "' + backup + '"');
