/**
 * 复核 dsh-capture 对原「22 项缺失清单」的实际完成度。
 *
 * 只读：读取仓库内源码/文件，逐项给命中证据行，不做推测。
 * 文件存在性检查用 exists()，避免"写了但关键词不匹配"的假阴性。
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// fileURLToPath 而不是手写 pathname 转换：路径含中文时 pathname 是百分号编码的。
const REPO_ROOT = path.dirname(fileURLToPath(import.meta.url));
const DIR = process.env.CAPTURE_SRC || path.join(REPO_ROOT, 'dsh-capture');
const read = (p) => { try { return fs.readFileSync(path.join(DIR, p), 'utf8'); } catch { return ''; } };
const exists = (p) => fs.existsSync(path.join(DIR, p));

const F = {
  index: read('lib/index.js'),
  routes: read('lib/routes.js'),
  pcap: read('lib/pcap.js'),
  pktmon: read('lib/pktmon.js'),
  npcap: read('lib/npcap.js'),
  perm: read('lib/perm.js'),
  tools: read('lib/tools.js'),
  client: read('client/client.js'),
  pkg: read('package.json'),
  readme: read('README.md'),
};
const all = Object.values(F).join('\n');

/** 打印关键词命中的行（缩进展示） */
function hits(label, text, re, limit = 3) {
  const lines = text.split('\n');
  const found = [];
  for (let i = 0; i < lines.length && found.length < limit; i++) {
    if (re.test(lines[i])) found.push(`      L${i + 1}: ${lines[i].trim().slice(0, 120)}`);
  }
  console.log(`    ${label}`);
  if (!found.length) console.log('      （无命中）');
  else found.forEach((l) => console.log(l));
}

const checks = [
  ['1  后端: Npcap 支持', () => F.npcap.length > 500, () => hits('npcap.js', F.npcap, /export function|dumpcap/, 2)],
  ['2  后端: 抓包中实时读取（流式）', () => /countPacketBlocks|liveCount|packetBlocks/.test(F.npcap + F.routes), () => hits('实时计数', F.npcap + F.routes, /countPacketBlocks|packetBlocks|live/, 3)],
  ['3  解析: TCP 流重组', () => /reassembl|tcpStream|streamReassembl/i.test(F.pcap), () => hits('流重组', F.pcap, /reassembl|tcpStream/i, 3)],
  ['4  解析: HTTP 请求体/响应体提取', () => /content-length|httpBody|body\s*[:=]/i.test(F.pcap), () => hits('HTTP body', F.pcap, /content-length|body/i, 3)],
  ['5  解析: TLS 握手版本/密码套件', () => /cipherSuite|tlsVersion|recordVersion|supported_versions/i.test(F.pcap), () => hits('TLS 版本', F.pcap, /cipher|version|sni/i, 3)],
  ['6  解析: 时间戳格式化', () => /toISOString|formatTs|new Date\(/i.test(F.pcap), () => hits('时间戳', F.pcap, /Date\(|ISOString|ts/i, 3)],
  ['7  导出: CSV', () => /csv/i.test(F.routes + F.tools), () => hits('CSV', F.routes, /csv/i, 3)],
  ['8  过滤: BPF 风格表达式', () => /bpf/i.test(F.routes + F.tools + F.npcap), () => hits('BPF', F.routes + F.npcap, /bpf|-f\b/i, 3)],
  ['9  搜索: 正则', () => /new RegExp|pattern/i.test(F.routes + F.tools), () => hits('正则', F.routes, /RegExp|pattern/, 3)],
  ['10 UI: 包列表浏览', () => /packets|packetList|packet-page/i.test(F.client), () => hits('包列表', F.client, /packet/i, 3)],
  ['11 UI: 导出按钮', () => /export/i.test(F.client), () => hits('导出按钮', F.client, /export/i, 3)],
  ['12 工具: 抓包时实时看（不停止）', () => /capture_status|capture_live/i.test(F.index), () => hits('实时工具', F.index, /capture_status|capture_live/, 3)],
  ['13 工具: capture_export', () => /capture_export/.test(F.index), () => hits('导出工具', F.index, /capture_export/, 3)],
  ['14 权限: Npcap AdminOnly 检测', () => /AdminOnly|adminOnly/.test(F.perm), () => hits('AdminOnly', F.perm, /adminOnly/i, 3)],
  ['15 权限: 引导改注册表', () => /reg add|reg\.exe|注册表|registry/i.test(F.perm + F.readme + F.client), () => hits('注册表引导', F.perm + F.readme, /reg add|注册表|AdminOnly=0/i, 3)],
  ['16 工程: 路由测试', () => exists('test/routes.test.mjs'), () => hits('路由测试文件', F.pkg, /routes\.test|test\//i, 3)],
  ['17 工程: CI 配置', () => CI_PRESENT(), () => console.log('      （.github/workflows 下无 yml —— CI 文件仍待推送）')],
  ['18 工程: TypeScript 类型', () => exists('types/index.d.ts') && /"types"/.test(F.pkg), () => hits('TS 声明', F.pkg, /types/i, 2)],
  ['19 工程: Config schema', () => /schemastery|Config\s*=|z\.object/.test(F.index), () => hits('Config', F.index, /schemastery|Config/, 3)],
  ['20 工程: 日志 ctx.logger', () => /ctx\.logger|makeLogger/i.test(F.index), () => hits('日志', F.index, /logger/i, 3)],
  ['21 工程: i18n 双语', () => /locale\/en\.json|en\.json/.test(F.pkg), () => hits('i18n', F.pkg, /locale/i, 3)],
  ['22 边界: 大文件流式解析', () => /parseCaptureStream/.test(F.pcap) && /ChunkReader/.test(F.pcap),
    () => hits('流式解析', F.pcap, /ChunkReader|readFileSync/, 3)],
];

/** CI 工作流是否已真正落在 .github/workflows 下（而非 .pending 待推）。 */
function CI_PRESENT() {
  const wfDir = path.join(path.dirname(DIR), '.github', 'workflows');
  try {
    return fs.readdirSync(wfDir).some((f) => /\.ya?ml$/i.test(f));
  } catch { return false; }
}

let done = 0, open = 0;
const still = [];
console.log('=== dsh-capture 对原 22 项缺失清单的复核 ===\n');
for (const [name, has, ev] of checks) {
  const ok = has();
  if (ok) done++; else { open++; still.push(name); }
  console.log(`  [${ok ? '有' : '无'}] ${name}`);
  if (!ok) ev();
}
console.log(`\n合计：有 ${done} 项 / 无 ${open} 项`);
console.log('\n=== 仍未完成 ===');
still.forEach((s) => console.log('  - ' + s));
