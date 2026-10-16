/**
 * 把 desktop profile 里 dsh-capture 的依赖指向从「陈旧副本」改到「仓库真身」，
 * 然后重跑 pnpm install，让 pnpm-lock 也一起收敛。
 *
 * 背景：profile 里的依赖原先是
 *   "dsh-capture": "file:E:\\dsh工作区\\capture-plugin\\dsh-capture"
 * 那个目录停在 0.1.1（缺 lib/npcap.js 等），现在安装副本内容正确只是因为
 * 走过 sync-dsh-capture.mjs 手动拷贝；**下一次 pnpm install 会按依赖重新解析，
 * 把安装副本回退到 0.1.1**。本脚本把依赖改到仓库真身并重装，堵住这个回退。
 *
 * 用法:
 *   node repoint-dsh-capture.mjs --check      只比较，不写
 *   node repoint-dsh-capture.mjs              备份 + 改依赖 + pnpm install + 校验
 *   node repoint-dsh-capture.mjs --restore "<备份目录>"   回滚
 *
 * 安全：改动前备份 profile 的 package.json / pnpm-lock.yaml / pnpm-workspace.yaml；
 * 任何一步失败自动还原三文件。
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync, execFileSync } from 'node:child_process';
import crypto from 'node:crypto';

const REPO_ROOT = path.dirname(fileURLToPath(import.meta.url));
const SRC = path.join(REPO_ROOT, 'dsh-capture');
const PKG_NAME = 'dsh-capture';
const NEW_SPEC = 'file:' + SRC;

/** 期望被替换掉的旧依赖值（规范化后比较，避免反斜杠/斜杠差异）。 */
const STALE_HINTS = ['capture-plugin'];

function norm(p) { return String(p).replace(/\\/g, '/').replace(/^file:/, '').toLowerCase(); }

function resolveProfile() {
  const fromArg = process.argv.find((a) => a.startsWith('--profile='));
  if (fromArg) return fromArg.slice('--profile='.length);
  if (process.env.DSH_PROFILE_DIR) return process.env.DSH_PROFILE_DIR;
  const home = process.env.DSH_HOME || path.join(process.env.USERPROFILE || '', '.dsh');
  return path.join(home, 'profiles', 'desktop');
}
const PROFILE = resolveProfile();

function resolvePnpm() {
  for (const c of [
    process.env.DSH_PNPM,
    'E:\\dsh\\resources\\runtime\\pnpm\\bin\\pnpm.cjs',
  ].filter(Boolean)) if (fs.existsSync(c)) return c;
  return null;
}

const THREE = ['package.json', 'pnpm-lock.yaml', 'pnpm-workspace.yaml'];
const dryOrCheck = process.argv.includes('--dry-run') || process.argv.includes('--check');
const lines = [];
const say = (s) => { lines.push(s); console.log(s); };

const stamp = new Date().toISOString().replace(/[-:T]/g, '').slice(0, 14);
const BACKUP = path.join(REPO_ROOT, 'backup-repoint-' + stamp);
const LOG = path.join(REPO_ROOT, 'repoint-dsh-capture.log');
function flush() { fs.writeFileSync(LOG, lines.join('\n') + '\n', 'utf8'); }

// ---- 回滚模式 ----
if (process.argv[2] === '--restore') {
  const from = process.argv[3];
  if (!from || !fs.existsSync(from)) { console.error('用法: node repoint-dsh-capture.mjs --restore "<备份目录>"'); process.exit(1); }
  for (const f of THREE) {
    const s = path.join(from, f);
    if (fs.existsSync(s)) { fs.copyFileSync(s, path.join(PROFILE, f)); console.log('restored ' + f); }
    else console.log('skip (not in backup): ' + f);
  }
  console.log('已回滚三文件。再跑一次 pnpm install 才会同步 node_modules。');
  process.exit(0);
}

say(`=== dsh-capture 依赖指向修正 ===`);
say(`PROFILE = ${PROFILE}`);
say(`SRC     = ${SRC}`);
say(`NEW_SPEC= ${NEW_SPEC}`);
say(`mode    = ${dryOrCheck ? '只检查' : '实改'}`);

// ---- 前置检查 ----
if (!fs.existsSync(path.join(SRC, 'package.json'))) { say('FAILED: 仓库里没有 dsh-capture/package.json'); flush(); process.exit(1); }
const srcPkg = JSON.parse(fs.readFileSync(path.join(SRC, 'package.json'), 'utf8'));
say(`源包: ${srcPkg.name}@${srcPkg.version}`);

const profilePkgPath = path.join(PROFILE, 'package.json');
const lockPath = path.join(PROFILE, 'pnpm-lock.yaml');
const wsPath = path.join(PROFILE, 'pnpm-workspace.yaml');
if (!fs.existsSync(profilePkgPath)) { say(`FAILED: 找不到 ${profilePkgPath}`); flush(); process.exit(1); }

const pj = JSON.parse(fs.readFileSync(profilePkgPath, 'utf8'));
const cur = pj.dependencies?.[PKG_NAME];
say(`当前依赖: ${JSON.stringify(cur)}`);
if (!cur) { say(`FAILED: profile 里没有 ${PKG_NAME} 依赖，请先跑 install-dsh-capture.mjs`); flush(); process.exit(1); }

const alreadyOk = norm(cur) === norm(NEW_SPEC);
say(`是否已指向真身: ${alreadyOk ? '是' : '否'}`);

if (alreadyOk) {
  say('无需改动 package.json。');
}

// 锁文件里的解析结果
let lockMentions = [];
if (fs.existsSync(lockPath)) {
  const lock = fs.readFileSync(lockPath, 'utf8');
  lockMentions = [...new Set(lock.match(/[^\s'"]*capture-plugin[^\s'"]*|[^\s'"]*dsh-capture-repo[^\s'"]*/g) || [])];
  say(`pnpm-lock 里的相关片段（去重 ${lockMentions.length} 条）:`);
  lockMentions.slice(0, 10).forEach((m) => say('  ' + m));
}

if (dryOrCheck) {
  say('');
  say('DRY-RUN 结束，未改动任何文件。');
  flush();
  process.exit(0);
}

if (alreadyOk) {
  say('依赖已正确，仅执行一次 pnpm install 以确保 node_modules 与锁文件收敛。');
}

// ---- 备份 ----
fs.mkdirSync(BACKUP, { recursive: true });
for (const f of THREE) {
  const s = path.join(PROFILE, f);
  if (fs.existsSync(s)) fs.copyFileSync(s, path.join(BACKUP, f));
}
say(`BACKUP -> ${BACKUP}`);

let patched = false;
try {
  // ---- 改依赖 ----
  if (!alreadyOk) {
    pj.dependencies[PKG_NAME] = NEW_SPEC;
    const sorted = {};
    for (const k of Object.keys(pj.dependencies).sort()) sorted[k] = pj.dependencies[k];
    pj.dependencies = sorted;
    fs.writeFileSync(profilePkgPath, JSON.stringify(pj, null, 2) + '\n', 'utf8');
    const back = JSON.parse(fs.readFileSync(profilePkgPath, 'utf8'));
    if (norm(back.dependencies[PKG_NAME]) !== norm(NEW_SPEC)) throw new Error('PATCH_VERIFY_FAILED');
    patched = true;
    say(`已改依赖: ${back.dependencies[PKG_NAME]}`);
  }

  // 确认 bundles 仍在
  const bundles = pj.dsh?.profile?.bundles || [];
  say(`bundles 含 ${PKG_NAME}: ${bundles.includes(PKG_NAME)}（共 ${bundles.length} 项）`);

  // ---- pnpm install ----
  const pnpm = resolvePnpm();
  say(`pnpm: ${pnpm || 'PATH 上的 pnpm'}`);
  const outLog = path.join(BACKUP, 'pnpm.out.log');
  const errLog = path.join(BACKUP, 'pnpm.err.log');
  const outFd = fs.openSync(outLog, 'w');
  const errFd = fs.openSync(errLog, 'w');
  const r = spawnSync(pnpm ? process.execPath : 'pnpm', pnpm ? [pnpm, 'install'] : ['install'], {
    cwd: PROFILE, stdio: ['ignore', outFd, errFd], shell: !pnpm, timeout: 300000,
  });
  fs.closeSync(outFd); fs.closeSync(errFd);
  const pout = fs.readFileSync(outLog, 'utf8') + fs.readFileSync(errLog, 'utf8');
  say(`pnpm exit=${r.status}`);
  pout.trim().split('\n').slice(-14).forEach((l) => say('  | ' + l.slice(0, 170)));
  if (r.status !== 0) throw new Error('pnpm install failed exit=' + r.status);

  // ---- 校验：安装副本与仓库源码逐文件哈希一致 ----
  const instDir = path.join(PROFILE, 'node_modules', PKG_NAME);
  if (!fs.existsSync(path.join(instDir, 'package.json'))) throw new Error('node_modules/' + PKG_NAME + ' 不存在');
  const instVer = JSON.parse(fs.readFileSync(path.join(instDir, 'package.json'), 'utf8')).version;
  say(`安装版本 = ${instVer}（源 ${srcPkg.version}）`);

  const sha = (p) => crypto.createHash('sha256').update(fs.readFileSync(p)).digest('hex').slice(0, 12);
  const FILES = [
    'package.json', 'cordis.patch.yml', 'icon.svg', 'README.md',
    'types/index.d.ts',
    'locale/en.json', 'locale/zh.json',
    'lib/index.js', 'lib/routes.js', 'lib/pcap.js', 'lib/pktmon.js', 'lib/tools.js',
    'lib/perm.js', 'lib/elevate.js', 'lib/npcap.js', 'lib/run-elevated.ps1',
    'client/client.js',
  ];
  let same = 0, diff = 0, missing = 0;
  for (const f of FILES) {
    const a = path.join(SRC, f), b = path.join(instDir, f);
    if (!fs.existsSync(a)) { say(`  ${f}  源缺失`); missing++; continue; }
    if (!fs.existsSync(b)) { say(`  ${f}  安装副本缺失`); missing++; continue; }
    const ha = sha(a), hb = sha(b);
    if (ha === hb) { same++; say(`  ${f}  SAME ${ha}`); }
    else { diff++; say(`  ${f}  DIFF 源=${ha} 装=${hb}`); }
  }
  say(`文件比对: 一致 ${same} / 差异 ${diff} / 缺失 ${missing}`);
  if (diff || missing) throw new Error(`安装副本与源码不一致（差异 ${diff} 缺失 ${missing}）`);
  if (instVer !== srcPkg.version) throw new Error(`版本不一致：装 ${instVer} vs 源 ${srcPkg.version}`);

  // ---- 校验：锁文件已指向真身 ----
  const lockNow = fs.readFileSync(lockPath, 'utf8');
  const stillStale = lockNow.includes('capture-plugin');
  const hasReal = lockNow.includes('dsh-capture-repo');
  say(`锁文件仍含 capture-plugin: ${stillStale}`);
  say(`锁文件含 dsh-capture-repo: ${hasReal}`);
  if (stillStale) throw new Error('锁文件里仍残留旧路径 capture-plugin');

  say('');
  say('REPOINT_OK —— 依赖已指向仓库真身，安装副本与源码逐文件一致，锁文件已收敛。');
  say('已清除「下次 pnpm install 回退到 0.1.1」的隐患。');
  say('重启 DSH App 后生效（运行中的进程仍是旧版本）。');
  say('');
  say(`回滚: node repoint-dsh-capture.mjs --restore "${BACKUP}"`);
} catch (e) {
  say('FAILED: ' + e.message);
  for (const f of THREE) {
    const s = path.join(BACKUP, f);
    if (fs.existsSync(s)) fs.copyFileSync(s, path.join(PROFILE, f));
  }
  say('已从备份还原 profile 三文件' + (patched ? '（含回退依赖指向）' : ''));
  say(`回滚备份: ${BACKUP}`);
  flush();
  process.exit(1);
}

say(`BACKUP_LOG=${BACKUP}`);
say(`LOG=${LOG}`);
flush();
