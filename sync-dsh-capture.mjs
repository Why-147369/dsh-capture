/**
 * 把本仓库的 dsh-capture 源码同步到已安装的 profile 副本。
 *
 * 为什么需要：profile 的 node_modules/dsh-capture 是 pnpm 从 file: 依赖
 * 拷出来的**副本**，不是符号链接。改源码不会自动生效，必须重新同步。
 *
 * 只同步源码与元数据，不动 node_modules。
 *
 * 用法:
 *   node sync-dsh-capture.mjs            同步并校验
 *   node sync-dsh-capture.mjs --check    只比较差异，不写
 *   node sync-dsh-capture.mjs --profile=<路径>   指定 profile
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO_ROOT = path.dirname(fileURLToPath(import.meta.url));
const SRC = path.join(REPO_ROOT, 'dsh-capture');
const PKG_NAME = 'dsh-capture';

const fromArg = process.argv.find((a) => a.startsWith('--profile='));
const PROFILE = fromArg
  ? fromArg.slice('--profile='.length)
  : (process.env.DSH_PROFILE_DIR
    || path.join(process.env.DSH_HOME || path.join(process.env.USERPROFILE || '', '.dsh'), 'profiles', 'desktop'));
const DST = path.join(PROFILE, 'node_modules', PKG_NAME);

const checkOnly = process.argv.includes('--check');

/** 需要保持同步的文件（相对路径）。 */
const FILES = [
  'package.json',
  'cordis.patch.yml',
  'icon.svg',
  'README.md',
  'locale/zh.json',
  'lib/index.js',
  'lib/routes.js',
  'lib/pcap.js',
  'lib/pktmon.js',
  'lib/tools.js',
  'client/client.js',
];

const lines = [];
const say = (s) => { lines.push(s); console.log(s); };
let changed = 0;
let bad = 0;

if (!fs.existsSync(DST)) {
  console.error(`目标不存在：${DST}\n先运行 install-dsh-capture.mjs 安装。`);
  process.exit(1);
}

say(`同步 ${SRC}\n  -> ${DST}${checkOnly ? '  (--check 只比较)' : ''}\n`);

for (const rel of FILES) {
  const s = path.join(SRC, rel);
  const d = path.join(DST, rel);
  if (!fs.existsSync(s)) { say(`  缺失源文件 ${rel}`); bad++; continue; }
  const sBuf = fs.readFileSync(s);
  let same = false;
  if (fs.existsSync(d)) {
    const dBuf = fs.readFileSync(d);
    same = sBuf.length === dBuf.length && sBuf.equals(dBuf);
  }
  if (same) { say(`  相同 ${rel}`); continue; }
  changed++;
  if (checkOnly) {
    say(`  差异 ${rel}  (源 ${sBuf.length}B${fs.existsSync(d) ? ` / 装 ${fs.statSync(d).size}B` : ' / 未安装'})`);
  } else {
    fs.mkdirSync(path.dirname(d), { recursive: true });
    fs.copyFileSync(s, d);
    const after = fs.readFileSync(d);
    const ok = after.length === sBuf.length && after.equals(sBuf);
    say(`  ${ok ? '已同步' : '写入校验失败'} ${rel}  (${sBuf.length}B)`);
    if (!ok) bad++;
  }
}

say('');
if (bad) say(`${bad} 个文件有问题，需人工处理。`);
else if (checkOnly) say(changed ? `${changed} 个文件有差异（未写盘）。去掉 --check 即同步。` : '全部一致，无需同步。');
else {
  say(changed ? `已同步 ${changed} 个文件。重启 DSH App 生效。` : '全部一致，未做改动。');
  if (changed) say('提示：Host 侧改动需重启；Client（client.js）改动在 dev:web 运行时可能热更新。');
}

fs.writeFileSync(path.join(REPO_ROOT, 'sync.log'), lines.join('\n') + '\n', 'utf8');
process.exit(bad ? 1 : 0);
