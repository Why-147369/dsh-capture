/**
 * 图标与 manifest 契约验证：
 *   1. icon 字段已声明，且指向的文件存在
 *   2. icon 体积在宿主限制内（SVG/PNG/JPEG/WebP ≤ 256 KiB）
 *   3. icon 路径不是绝对路径 / URL，也不逃出包目录
 *   4. exports 里声明的每个子路径都真实存在
 *   5. meta.title / meta.description 非空
 *   6. dsh.bundle.patch 与 dsh.client 声明完好
 *
 * 默认校验已安装副本；加 --src 则校验本仓库源码目录。
 * 用法: node verify-icon.cjs [--src] [--profile=<profile目录>]
 */
const fs = require('fs');
const path = require('path');

const useSrc = process.argv.includes('--src');
const fromArg = process.argv.find((a) => a.startsWith('--profile='));
const PROFILE = fromArg
  ? fromArg.slice('--profile='.length)
  : (process.env.DSH_PROFILE_DIR
    || path.join(process.env.DSH_HOME || path.join(process.env.USERPROFILE || '', '.dsh'), 'profiles', 'desktop'));

const DIR = useSrc
  ? path.join(__dirname, 'dsh-capture')
  : path.join(PROFILE, 'node_modules', 'dsh-capture');

const lines = [];
let fail = 0;
const ok = (name, good, detail = '') => {
  lines.push(`${good ? 'PASS' : 'FAIL'}  ${name}${detail ? '  — ' + detail : ''}`);
  if (!good) fail++;
};

if (!fs.existsSync(path.join(DIR, 'package.json'))) {
  console.error(`找不到 package.json：${DIR}`);
  process.exit(1);
}
const pkg = JSON.parse(fs.readFileSync(path.join(DIR, 'package.json'), 'utf8'));

// 1) icon 声明
ok('icon 字段已声明', typeof pkg.icon === 'string' && pkg.icon.length > 0, String(pkg.icon));
if (typeof pkg.icon !== 'string') { console.log(lines.join('\n')); process.exit(1); }

// 2) icon 路径合法性（宿主的拒绝规则）
ok('icon 不是绝对路径', !path.isAbsolute(pkg.icon));
ok('icon 不是 URL', !/^[a-z]+:\/\//i.test(pkg.icon));
ok('icon 不逃出包目录', !pkg.icon.split(/[\\/]/).includes('..'));

// 3) icon 存在、体积、可解析
const iconPath = path.resolve(DIR, pkg.icon);
ok('icon 文件存在', fs.existsSync(iconPath), iconPath);
if (fs.existsSync(iconPath)) {
  const st = fs.statSync(iconPath);
  ok('icon 体积 ≤ 256 KiB', st.size <= 256 * 1024, `${(st.size / 1024).toFixed(1)} KB`);
  const head = fs.readFileSync(iconPath, 'utf8').slice(0, 200);
  ok('icon 是 SVG 且可解析', /<svg[\s>]/i.test(head));
}

// 4) exports 每个子路径都要真实存在
const ex = pkg.exports || {};
for (const [key, val] of Object.entries(ex)) {
  const rel = typeof val === 'string' ? val : (val && val.default);
  if (typeof rel !== 'string') { ok(`exports["${key}"] 形式合法`, false, JSON.stringify(val)); continue; }
  const target = path.resolve(DIR, rel);
  ok(`exports["${key}"] → ${rel} 存在`, fs.existsSync(target));
}

// 5) meta 文案
ok('meta.title 非空', !!(pkg.meta && pkg.meta.title && pkg.meta.title.trim()));
ok('meta.description 非空', !!(pkg.meta && pkg.meta.description && pkg.meta.description.trim()));

// 6) dsh 声明
ok('dsh.bundle.patch 已声明', !!(pkg.dsh && pkg.dsh.bundle && pkg.dsh.bundle.patch));
ok('dsh.client.platform = web', !!(pkg.dsh && pkg.dsh.client && pkg.dsh.client.platform === 'web'));

console.log(`校验目录: ${DIR}${useSrc ? '  (源码)' : '  (安装副本)'}`);
console.log(lines.join('\n'));
console.log('');
console.log(fail === 0 ? `全部通过（${lines.filter((l) => l.startsWith('PASS')).length} 项）` : `有 ${fail} 项失败`);
process.exit(fail === 0 ? 0 : 1);
