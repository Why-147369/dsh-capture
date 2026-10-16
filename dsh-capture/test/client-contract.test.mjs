/**
 * 客户端 bundle 契约测试。
 *
 * 为什么必须有：本轮开发里 client.js 出过 4 个只有"重启 DSH 用眼睛看"才能发现的
 * bug —— 裸 return 而非 module.exports、slot 选错、缺 icon 字段、缺 locale 文件。
 * 装机验证（verify-installed.mjs）只测 Host 侧路由，完全覆盖不到这些。
 *
 * 本测试把 client.js 放进沙箱真执行一遍：
 *   - 校验 __ModuleLoader__.load 的 id 与 factory 的 CommonJS 导出契约
 *   - 校验 inject 声明与 settings.section 的注册形状
 *   - 真渲染面板组件（用最小 React 替身），并检查渲染出的文本
 *   - 校验它只 require('react')，不碰宿主内部模块
 */
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const CLIENT = join(HERE, '..', 'client', 'client.js');

/* ---------------------- 最小 React 替身 ---------------------- */

function createElement(type, props, ...children) {
  return { type, props: { ...(props || {}), children: children.length <= 1 ? children[0] : children } };
}

const ReactShim = {
  createElement,
  useState(init) { return [typeof init === 'function' ? init() : init, () => {}]; },
  useEffect() { /* effects don't run in a bare render */ },
  useLayoutEffect() {},
  useMemo(fn) { return fn(); },
  useCallback(fn) { return fn; },
  useRef(v) { return { current: v === undefined ? null : v }; },
  Fragment: Symbol('Fragment'),
};

/* ---------------------- 沙箱：执行 client.js ---------------------- */

const loaded = [];
const requiredModules = [];
const globalWindow = {
  __ModuleLoader__: {
    load(entry) { loaded.push(entry); },
  },
};

globalThis.window = globalWindow;

await import(pathToFileURL(CLIENT).href);

assert.equal(loaded.length, 1, `应恰好调用一次 __ModuleLoader__.load，实际 ${loaded.length}`);
const entry = loaded[0];
assert.equal(entry.id, 'dsh-capture', `bundle id 应为包名，实际 ${entry.id}`);
assert.equal(typeof entry.factory, 'function', 'factory 必须是函数');

const exportsObj = entry.factory(function fakeRequire(name) {
  requiredModules.push(name);
  if (name === 'react') return ReactShim;
  throw new Error(`客户端不应 require 宿主内部模块，却 require 了 "${name}"`);
});

/* ---------------------- 契约断言 ---------------------- */

const checks = [];
const check = (name, cond, detail = '') => {
  checks.push({ name, ok: !!cond });
  console.log(`  [${cond ? 'PASS' : 'FAIL'}] ${name}${detail ? '  — ' + detail : ''}`);
};

check('factory 返回 module.exports（而非裸对象）',
  exportsObj && typeof exportsObj === 'object'
    && exportsObj[Symbol.toStringTag] === 'Module',
  `Symbol.toStringTag=${String(exportsObj && exportsObj[Symbol.toStringTag])}`);
check('导出 apply 函数', typeof exportsObj.apply === 'function');
check('导出 inject 且声明 slots', Array.isArray(exportsObj.inject)
  && exportsObj.inject.includes('slots'), JSON.stringify(exportsObj.inject));
check('只 require("react")', requiredModules.length === 1 && requiredModules[0] === 'react',
  JSON.stringify(requiredModules));

/* ---------------------- slot 注册契约 ---------------------- */

let injectedSlot = null;
let registered = null;
const fakeCtx = {
  slots: {
    inject(slotName, cb) { injectedSlot = slotName; cb(); },
    register(spec, component) { registered = { spec, component }; return () => {}; },
  },
};
exportsObj.apply(fakeCtx);

check('注册到 settings.section',
  injectedSlot === 'settings.section' && registered?.spec?.name === 'settings.section',
  `inject=${injectedSlot} spec.name=${registered?.spec?.name}`);
check('slot 用 id（不是 key）作为标识',
  registered?.spec?.id === 'dsh-capture',
  `spec=${JSON.stringify(registered?.spec && { id: registered.spec.id, key: registered.spec.key })}`);
check('提供可读 label', typeof registered?.spec?.label === 'function'
  && String(registered.spec.label()).length > 0, String(registered?.spec?.label?.()));
check('注册的是组件函数', typeof registered?.component === 'function');

/* ---------------------- 真渲染 ---------------------- */

/**
 * 最小渲染器：递归求值函数组件，收集宿主元素的文本子节点。
 * 不实现协调/hooks 语义 —— 只验证「组件能在空状态下渲染出内容」。
 */
function render(node, depth = 0) {
  if (node == null || node === false || node === true) return [];
  if (typeof node === 'string' || typeof node === 'number') return [String(node)];
  if (Array.isArray(node)) return node.flatMap((n) => render(n, depth));
  if (depth > 40) return []; // 防御：组件递归自引用
  if (typeof node.type === 'function') {
    return render(node.type(node.props || {}), depth + 1);
  }
  return render(node.props ? node.props.children : null, depth + 1);
}

let tree = null;
let renderErr = null;
try {
  // 注册时包了一层 (ownerProps) => h(CapturePanel, ownerProps || {})
  tree = registered.component({});
} catch (e) {
  renderErr = e;
}
check('面板组件能渲染（空状态不抛）', !renderErr && tree != null,
  renderErr ? String(renderErr.message) : 'ok');

const rendered = renderErr ? '' : render(tree).join(' ');
check('渲染内容含面板标题', /抓包/.test(rendered),
  rendered.slice(0, 90).replace(/\s+/g, ' '));
check('渲染内容含抓包控制入口', /开始抓包|停止/.test(rendered),
  [...new Set(rendered.match(/开始抓包|停止抓包|停止/g) || [])].join(','));

/* ---------------------- 源码级防御：只用宿主真实存在的 token ---------------------- */

/**
 * 宿主的主题 token 全集。
 *
 * 来源：`E:\dsh\resources\app\dsh\node_modules\@deepseek-ai\dsh-client-ui-theme\lib\client.js`
 * （107 个 `--dsw-alias-*`，用正则抽取去重）。实测教训：`--dsw-alias-bg-secondary`
 * / `text-primary` / `border-secondary` 这类"看起来该有"的名字**宿主根本没定义**，
 * 用了它们就只会落到写死的回退色 —— 等于硬编码深色主题，浅色模式下必然难看。
 */
const HOST_TOKENS = new Set([
  'bg-base', 'bg-document-preview', 'bg-document-selection', 'bg-layer-1', 'bg-layer-2',
  'bg-layer-3', 'bg-mask-1', 'bg-mask-2', 'bg-mask-3', 'bg-mask-drop', 'bg-mask-photo',
  'bg-module-platform', 'bg-multi-select', 'bg-overlay', 'bg-skeleton',
  'border-inverted', 'border-inverted2', 'border-l1', 'border-l2', 'border-l2-darkmode-thin',
  'border-l3', 'border-l4',
  'brand-primary', 'brand-primary-invert', 'brand-primary-new-colorprimary-new-color', 'brand-text',
  'button-contrast-fill', 'button-elevated-fill', 'button-floating-fill', 'button-floating-hover',
  'button-ghost-active-border', 'button-ghost-active-fill', 'button-ghost-active-hover',
  'button-info-fill', 'button-info-hover', 'button-primary-dimmed', 'button-primary-fill',
  'button-primary-hover', 'button-tool-bar-fill', 'button-tool-bar-fill-invisible', 'button-tool-bar-hover',
  'code-diff-added', 'code-diff-deleted',
  'file-diff-added-bg', 'file-diff-added-gutter', 'file-diff-added-marker',
  'file-diff-deleted-bg', 'file-diff-deleted-gutter', 'file-diff-deleted-marker',
  'interactive-bg-active', 'interactive-bg-hover', 'interactive-bg-hover-accent',
  'interactive-bg-hover-danger', 'interactive-bg-hover-solid',
  'label-caption', 'label-deep-diving', 'label-deep-diving-shimmer', 'label-dimmed',
  'label-document-preview', 'label-primary', 'label-primary-bluish', 'label-primary-dimmed',
  'label-primary-foreground', 'label-primary-inverted', 'label-secondary', 'label-shimmer', 'label-tertiary',
  'link',
  'markdown-citation', 'markdown-code-block', 'markdown-code-block-banner',
  'markdown-code-segment-selected', 'markdown-code-segment-unselected', 'markdown-inline-code',
  'markdown-placeholder', 'markdown-tag',
  'menu-group-header-fill', 'menu-icon',
  'onboarding-accent', 'onboarding-card-fill', 'onboarding-checkbox-border', 'onboarding-secondary-fill',
  'scrollbar-bg-l1', 'scrollbar-bg-l2', 'scrollbar-hover-l1', 'scrollbar-hover-l2',
  'settings-card-fill', 'settings-card-stroke',
  'state-business-primary', 'state-business-tertiary', 'state-error-primary', 'state-error-secondary',
  'state-idle-primary', 'state-success-primary', 'state-success-secondary', 'state-success-tertiary',
  'state-warn-label', 'state-warn-primary', 'state-warn-secondary', 'state-warn-tertiary',
  'switch-thumb', 'toast-bg', 'toast-label', 'tooltip-bg', 'tooltip-key-bg',
  'turn-trigger-bg', 'turn-trigger-bg-hover',
]);

const rawSrc = readFileSync(CLIENT, 'utf8');
// 扫描前先剥掉注释：文档里会**提到**错误的 token 名（作为反例），不该被当成使用
const src = rawSrc
  .replace(/\/\*[\s\S]*?\*\//g, '')
  .replace(/(^|[^:])\/\/[^\n]*/g, '$1');
const usedTokens = [...new Set([...src.matchAll(/--dsw-alias-([a-z0-9-]+)/g)].map((m) => m[1]))];
const unknown = usedTokens.filter((t) => !HOST_TOKENS.has(t));
check('只用宿主真实存在的 --dsw-alias-* token',
  unknown.length === 0 && usedTokens.length > 0,
  unknown.length ? `不存在的 token：${unknown.join(', ')}` : `用了 ${usedTokens.length} 个：${usedTokens.join(', ')}`);

// 颜色值不得写死（避免 token 缺失时静默变成另一种主题）
const colorDecls = src.match(/(?:color|background|border-color|border)\s*:\s*[^;'"}]+/gi) || [];
const hardcoded = colorDecls.filter((d) => /#fff\b|#ffffff\b|\bwhite\b|\bblack\b|#[0-9a-f]{3,6}\b|rgba?\(/i.test(d)
  && !/var\(--dsw-alias/.test(d));
check('颜色声明不写死（一律走 token，无回退色）',
  hardcoded.length === 0,
  hardcoded.length ? `写死颜色：${hardcoded.slice(0, 3).map((s) => s.trim()).join(' | ')}` : `${colorDecls.length} 处颜色声明全部走 token`);

// token 后不得带字面色回退（var(--x, #fff) 这种）
const fallbacks = [...src.matchAll(/var\(--dsw-alias-[a-z0-9-]+\s*,\s*([^)]+)\)/g)].map((m) => m[1].trim());
check('token 不带字面色回退值', fallbacks.length === 0,
  fallbacks.length ? `回退值：${[...new Set(fallbacks)].slice(0, 3).join(' | ')}` : '无');

const failed = checks.filter((c) => !c.ok);
console.log('');
if (failed.length) {
  console.log(`客户端契约测试：${checks.length - failed.length}/${checks.length} 通过，失败 ${failed.length}：`);
  for (const f of failed) console.log(`  - ${f.name}`);
  process.exit(1);
}
console.log(`客户端契约测试全部通过（${checks.length} 项）`);
