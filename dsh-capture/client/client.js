/**
 * dsh-capture client module.
 *
 * Renders a capture panel in the right sidebar: backend status, start/stop,
 * the saved-capture list, and the parsed traffic summary for the selected
 * file. All data comes from the plugin's own /dsh-capture/* HTTP routes, so
 * this module never folds session events or touches the Host internals.
 *
 * Styling uses host theme tokens only (--dsw-alias-*), so light/dark switching
 * and theme changes are inherited rather than reimplemented. No Harness Client
 * package is imported: the component is plain React from the browser module
 * table, matching the plugin-development rule that client primitives must not
 * be required as modules.
 */
window.__ModuleLoader__.load({
  id: 'dsh-capture',
  factory(require) {
    // The shell's module table hands out a CommonJS-ish shim: the bundle must
    // publish its exports on `module.exports` and hand that object back. The
    // hand-written bundles that ship with working plugins do exactly this, and
    // the loader treats a bare `return {...}` as "no exports".
    const module = { exports: {} };
    const exports = module.exports;
    Object.defineProperty(exports, Symbol.toStringTag, { value: 'Module' });

    const React = require('react');
    const h = React.createElement;
    const { useState, useEffect, useCallback, useRef } = React;

    /** Small fetch helper that always returns a parsed body or an error shape. */
    async function api(path, init) {
      try {
        const res = await fetch(path, {
          credentials: 'same-origin',
          headers: init && init.body ? { 'content-type': 'application/json' } : undefined,
          ...init,
        });
        const text = await res.text();
        let body;
        try { body = JSON.parse(text); } catch { body = { ok: false, error: text.slice(0, 200) }; }
        return body;
      } catch (err) {
        return { ok: false, error: String(err && err.message ? err.message : err) };
      }
    }

    function fmtBytes(n) {
      if (!Number.isFinite(n)) return '—';
      if (n < 1024) return `${n} B`;
      if (n < 1048576) return `${(n / 1024).toFixed(1)} KB`;
      return `${(n / 1048576).toFixed(1)} MB`;
    }

    function fmtTime(ms) {
      if (!Number.isFinite(ms)) return '—';
      try { return new Date(ms).toLocaleString(); } catch { return String(ms); }
    }

    /** One labeled metric cell. */
    function Cell({ label, value }) {
      return h('div', { className: 'dshcap-cell' },
        h('div', { className: 'dshcap-cell-label' }, label),
        h('div', { className: 'dshcap-cell-value' }, value),
      );
    }

    /** The panel body. */
    function CapturePanel() {
      const [status, setStatus] = useState(null);
      const [backend, setBackend] = useState(null);
      const [captures, setCaptures] = useState([]);
      const [selected, setSelected] = useState(null);
      const [analysis, setAnalysis] = useState(null);
      const [busy, setBusy] = useState(false);
      const [message, setMessage] = useState(null);
      const [filters, setFilters] = useState('');
      /** Packet rows for the selected capture: {total, offset, limit, rows}. */
      const [packets, setPackets] = useState(null);
      /** Currently applied packet filter, so paging keeps it. */
      const [packetFilter, setPacketFilter] = useState({ proto: '', port: '', q: '', offset: 0, limit: 100 });
      const mountedRef = useRef(true);

      useEffect(() => () => { mountedRef.current = false; }, []);

      const refreshStatus = useCallback(async () => {
        const s = await api('/dsh-capture/status');
        if (!mountedRef.current) return;
        if (s.ok) { setBackend(s.backend); setStatus(s.state); }
        else setMessage({ kind: 'error', text: s.error || '无法读取抓包状态' });
      }, []);

      const refreshList = useCallback(async () => {
        const s = await api('/dsh-capture/sessions');
        if (!mountedRef.current) return;
        if (s.ok) setCaptures(Array.isArray(s.captures) ? s.captures : []);
      }, []);

      useEffect(() => {
        refreshStatus();
        refreshList();
        const timer = setInterval(() => { refreshStatus(); refreshList(); }, 5000);
        return () => clearInterval(timer);
      }, [refreshStatus, refreshList]);

      /** Parse the filter textarea into pktmon filter objects. */
      const parseFilters = () => {
        const text = filters.trim();
        if (!text) return [];
        return text.split(/[\n,;]+/).map((line) => line.trim()).filter(Boolean).map((line) => {
          if (/^\d+$/.test(line)) return { port: Number(line) };
          if (/^(TCP|UDP|ICMP)$/i.test(line)) return { protocol: line.toUpperCase() };
          return { ip: line };
        }).slice(0, 16);
      };

      const start = async () => {
        setBusy(true); setMessage(null);
        const r = await api('/dsh-capture/start', {
          method: 'POST',
          body: JSON.stringify({ filters: parseFilters() }),
        });
        if (mountedRef.current) {
          if (r.ok) {
            setMessage({
              kind: 'ok',
              text: r.elevated
                ? '抓包已以提权方式开始（助手已退出，DSH 仍为普通权限）。复现目标操作后点「停止」。'
                : '抓包已开始。复现目标操作后点「停止」。',
            });
          } else if (r.declined) {
            // UAC 被取消是用户决定，不是故障；给出可执行的下一步而不是重试提示。
            setMessage({ kind: 'error', text: r.error || '提权请求被取消，未开始抓包。' });
          } else {
            setMessage({ kind: 'error', text: r.error || '启动失败' });
          }
          setBusy(false);
        }
        refreshStatus();
      };

      /** Fetch one page of packet rows for the selected capture. */
      const loadPackets = async (id, opts) => {
        const o = opts || {};
        const params = new URLSearchParams({ id, limit: String(o.limit || 100), offset: String(o.offset || 0) });
        if (o.proto) params.set('proto', o.proto);
        if (o.port) params.set('port', String(o.port));
        if (o.q) params.set('q', o.q);
        setBusy(true); setMessage(null);
        const r = await api(`/dsh-capture/packets?${params.toString()}`);
        if (mountedRef.current) {
          if (r.ok) {
            setPackets(r);
            setPacketFilter(o);
          } else {
            setMessage({ kind: 'error', text: r.error || '读取包列表失败' });
          }
          setBusy(false);
        }
      };

      /** Download an export through the browser. */
      const exportCapture = (id, format) => {
        // The route answers with a Content-Disposition attachment, so a plain
        // navigation is enough — no blob plumbing needed.
        const url = `/dsh-capture/export?id=${encodeURIComponent(id)}&format=${encodeURIComponent(format)}`;
        try {
          window.open(url, '_blank');
        } catch {
          setMessage({ kind: 'error', text: '无法打开下载窗口，请检查弹窗拦截设置。' });
        }
      };

      const stop = async () => {
        setBusy(true); setMessage(null);
        const r = await api('/dsh-capture/stop', { method: 'POST', body: '{}' });
        if (mountedRef.current) {
          setMessage(r.ok
            ? { kind: 'ok', text: `已停止并转换：${r.capture ? r.capture.name : ''}` }
            : { kind: 'error', text: r.error || '停止流程未产出可分析文件' });
          setBusy(false);
        }
        refreshStatus(); refreshList();
      };

      const analyze = async (id) => {
        setBusy(true); setSelected(id); setAnalysis(null); setMessage(null);
        const r = await api(`/dsh-capture/analyze?id=${encodeURIComponent(id)}`);
        if (mountedRef.current) {
          setAnalysis(r.ok ? r : null);
          if (!r.ok) setMessage({ kind: 'error', text: r.error || '分析失败' });
          setBusy(false);
        }
      };

      const remove = async (id, name) => {
        setBusy(true);
        const r = await api('/dsh-capture/delete', { method: 'POST', body: JSON.stringify({ id }) });
        if (mountedRef.current) {
          setMessage(r.ok ? { kind: 'ok', text: `已删除 ${name || ''}` } : { kind: 'error', text: r.error || '删除失败' });
          if (selected === id) { setSelected(null); setAnalysis(null); }
          setBusy(false);
        }
        refreshList();
      };

      const running = !!(status && status.running);
      const notes = backend && Array.isArray(backend.notes) ? backend.notes : [];

      return h('div', { className: 'dshcap-root' },
        // Host theme tokens only; no literal colors in containers/controls.
        h('style', null, `
          .dshcap-root { display:flex; flex-direction:column; gap:10px; padding:10px; font-size:12px; color:var(--dsw-alias-text-primary,#e6e6e6); }
          .dshcap-title { font-size:13px; font-weight:600; display:flex; align-items:center; justify-content:space-between; gap:8px; }
          .dshcap-dot { width:8px; height:8px; border-radius:50%; display:inline-block; }
          .dshcap-card { border:1px solid var(--dsw-alias-border-secondary,rgba(255,255,255,.12)); border-radius:8px; padding:8px; background:var(--dsw-alias-bg-secondary,transparent); }
          .dshcap-row { display:flex; gap:8px; flex-wrap:wrap; }
          .dshcap-cell { flex:1 1 72px; min-width:72px; }
          .dshcap-cell-label { opacity:.6; font-size:11px; }
          .dshcap-cell-value { font-variant-numeric:tabular-nums; font-size:13px; }
          .dshcap-btn { border:1px solid var(--dsw-alias-border-secondary,rgba(255,255,255,.18)); background:var(--dsw-alias-bg-primary,transparent); color:inherit; border-radius:6px; padding:4px 10px; cursor:pointer; font-size:12px; }
          .dshcap-btn:hover:not(:disabled) { background:var(--dsw-alias-bg-tertiary,rgba(255,255,255,.06)); }
          .dshcap-btn:disabled { opacity:.45; cursor:default; }
          .dshcap-btn-primary { border-color:var(--dsw-alias-brand-primary,#247bbf); color:var(--dsw-alias-brand-primary,#247bbf); }
          .dshcap-input { width:100%; box-sizing:border-box; background:var(--dsw-alias-bg-primary,transparent); color:inherit; border:1px solid var(--dsw-alias-border-secondary,rgba(255,255,255,.18)); border-radius:6px; padding:4px 6px; font-size:12px; font-family:inherit; }
          .dshcap-note { opacity:.7; font-size:11px; line-height:1.5; }
          .dshcap-msg { border-radius:6px; padding:6px 8px; font-size:11px; line-height:1.5; }
          .dshcap-msg-ok { background:var(--dsw-alias-bg-tertiary,rgba(255,255,255,.06)); }
          .dshcap-msg-error { border:1px solid var(--dsw-alias-border-danger,rgba(255,80,80,.5)); color:var(--dsw-alias-text-danger,#ff8080); }
          .dshcap-list { display:flex; flex-direction:column; gap:4px; max-height:190px; overflow:auto; }
          .dshcap-item { display:flex; align-items:center; gap:6px; padding:4px 6px; border-radius:6px; border:1px solid transparent; }
          .dshcap-item:hover { background:var(--dsw-alias-bg-tertiary,rgba(255,255,255,.05)); }
          .dshcap-item-active { border-color:var(--dsw-alias-brand-primary,#247bbf); }
          .dshcap-name { flex:1; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
          .dshcap-meta { opacity:.6; font-size:11px; }
          .dshcap-mono { font-family:ui-monospace,Menlo,Consolas,monospace; font-size:11px; word-break:break-all; }
          .dshcap-tags { display:flex; flex-wrap:wrap; gap:4px; }
          .dshcap-tag { border:1px solid var(--dsw-alias-border-secondary,rgba(255,255,255,.16)); border-radius:10px; padding:1px 7px; font-size:11px; }
        `),

        h('div', { className: 'dshcap-title' },
          h('span', null, '抓包与流量分析'),
          h('span', { style: { display: 'flex', alignItems: 'center', gap: 6 } },
            h('span', {
              className: 'dshcap-dot',
              style: { background: running ? 'var(--dsw-alias-brand-primary,#247bbf)' : 'var(--dsw-alias-text-tertiary,#888)' },
            }),
            h('span', { className: 'dshcap-meta' }, running ? '抓包中' : '空闲'),
          ),
        ),

        message ? h('div', {
          className: `dshcap-msg ${message.kind === 'error' ? 'dshcap-msg-error' : 'dshcap-msg-ok'}`,
        }, message.text) : null,

        // Environment report: explain which capture path is available and what
        // it costs (elevation prompt vs relaxed Npcap) instead of a bare "no".
        backend ? h('div', { className: 'dshcap-card' },
          h('div', { className: 'dshcap-row' },
            h(Cell, { label: 'pktmon', value: backend.pktmonExists ? (backend.pktmonUsable ? '可用' : '需提权') : '缺失' }),
            h(Cell, { label: 'Npcap', value: backend.npcap && backend.npcap.installed ? (backend.npcap.clickableCapture ? '可抓' : '受限') : '无' }),
            h(Cell, { label: '可抓包', value: backend.canCapture ? '是' : (backend.canCaptureWithElevation ? '需提权' : '否') }),
          ),
          h('div', { className: 'dshcap-row', style: { marginTop: 6 } },
            h(Cell, { label: '提权途径', value: backend.elevation && backend.elevation.supported ? '可用' : '不可用' }),
            h(Cell, { label: '平台', value: backend.platform || '?' }),
          ),
          notes.length
            ? h('div', {
                className: 'dshcap-note',
                style: { marginTop: 6, whiteSpace: 'pre-wrap' },
              }, notes.join('\n'))
            : null,
        ) : null,

        // Start / stop.
        h('div', { className: 'dshcap-card' },
          h('div', { className: 'dshcap-row', style: { alignItems: 'center' } },
            h('button', {
              className: 'dshcap-btn dshcap-btn-primary',
              // Enabled when a capture is possible either directly or through
              // the one-shot elevation prompt; disabled only when neither path
              // exists.
              disabled: busy || running || !(backend && (backend.canCapture || backend.canCaptureWithElevation)),
              title: running ? '已有抓包在进行中'
                : (backend && backend.canCapture) ? '直接开始抓包'
                  : (backend && backend.canCaptureWithElevation) ? '将弹出一次 UAC 提权请求'
                    : '当前没有可用的抓包路径',
              onClick: start,
            }, (backend && !backend.canCapture && backend.canCaptureWithElevation) ? '开始抓包（需提权）' : '开始抓包'),
            h('button', { className: 'dshcap-btn', disabled: busy || !running, onClick: stop }, '停止并转换'),
          ),
          h('div', { style: { marginTop: 6 } },
            h('input', {
              className: 'dshcap-input',
              placeholder: '过滤（每行一条）：1.1.1.1 / 443 / TCP',
              value: filters,
              onChange: (e) => setFilters(e.target.value),
            }),
          ),
          running && status && status.etl
            ? h('div', { className: 'dshcap-mono', style: { marginTop: 6 } }, `正在写入 ${status.etl}`)
            : null,
        ),

        // Saved captures.
        h('div', { className: 'dshcap-card' },
          h('div', { className: 'dshcap-meta', style: { marginBottom: 6 } }, `已保存 ${captures.length} 个抓包`),
          captures.length
            ? h('div', { className: 'dshcap-list' }, captures.slice(0, 40).map((c) => h('div', {
                key: c.id,
                className: `dshcap-item${selected === c.id ? ' dshcap-item-active' : ''}`,
              },
              h('span', { className: 'dshcap-name', title: c.name }, c.name),
              h('span', { className: 'dshcap-meta' }, fmtBytes(c.size)),
              c.kind === 'capture'
                ? h('button', { className: 'dshcap-btn', disabled: busy, onClick: () => analyze(c.id) }, '分析')
                : null,
              h('button', { className: 'dshcap-btn', disabled: busy, onClick: () => remove(c.id, c.name) }, '删除'),
            )))
            : h('div', { className: 'dshcap-note' }, '还没有抓包文件。点「开始抓包」复现一次操作，再停止。'),
        ),

        // Analysis result.
        analysis ? h('div', { className: 'dshcap-card' },
          h('div', { className: 'dshcap-meta', style: { marginBottom: 6 } }, `分析：${analysis.file}`),
          h('div', { className: 'dshcap-row' },
            h(Cell, { label: '包', value: analysis.meta?.packets ?? '—' }),
            h(Cell, { label: 'TCP', value: analysis.meta?.tcpPackets ?? 0 }),
            h(Cell, { label: 'UDP', value: analysis.meta?.udpPackets ?? 0 }),
            h(Cell, { label: '端点', value: analysis.summary?.endpoints ?? 0 }),
          ),
          h('div', { className: 'dshcap-row', style: { marginTop: 6 } },
            h(Cell, { label: 'DNS 名称', value: analysis.summary?.dnsNames ?? 0 }),
            h(Cell, { label: 'TLS 主机', value: analysis.summary?.httpsHosts ?? 0 }),
            h(Cell, { label: 'HTTP 请求', value: analysis.summary?.httpRequests ?? 0 }),
            h(Cell, { label: '字节', value: fmtBytes(analysis.sizeBytes) }),
          ),
          analysis.sni && analysis.sni.length
            ? h('div', { style: { marginTop: 8 } },
                h('div', { className: 'dshcap-cell-label' }, 'TLS SNI 主机'),
                h('div', { className: 'dshcap-tags' }, analysis.sni.slice(0, 24).map((s) => h('span', { key: s.name, className: 'dshcap-tag' }, `${s.name} (${s.count})`))),
              )
            : null,
          analysis.dns && analysis.dns.length
            ? h('div', { style: { marginTop: 8 } },
                h('div', { className: 'dshcap-cell-label' }, 'DNS 查询'),
                h('div', { className: 'dshcap-tags' }, analysis.dns.slice(0, 24).map((d, i) => h('span', { key: `${d.name}-${i}`, className: 'dshcap-tag' }, `${d.name} ${d.type || ''}`))),
              )
            : null,
          analysis.talkers && analysis.talkers.length
            ? h('div', { style: { marginTop: 8 } },
                h('div', { className: 'dshcap-cell-label' }, 'Top 会话'),
                h('div', { className: 'dshcap-list' }, analysis.talkers.slice(0, 10).map((t, i) => h('div', { key: i, className: 'dshcap-mono' }, `${t.src} → ${t.dst}  ${t.packets}包 / ${fmtBytes(t.bytes)}`))),
              )
            : null,
          analysis.topPorts && analysis.topPorts.length
            ? h('div', { style: { marginTop: 8 } },
                h('div', { className: 'dshcap-cell-label' }, 'Top 端口'),
                h('div', { className: 'dshcap-tags' }, analysis.topPorts.slice(0, 16).map((p) => h('span', { key: p.port, className: 'dshcap-tag' }, `${p.port} (${p.count})`))),
              )
            : null,
          analysis.stats && (analysis.stats.malformed || analysis.stats.truncated)
            ? h('div', { className: 'dshcap-note', style: { marginTop: 8 } }, `跳过畸形包 ${analysis.stats.malformed || 0}，截断 ${analysis.stats.truncated || 0}`)
            : null,
        ) : null,

        // Capture time of the selected file, when known.
        selected && status && status.pcapng
          ? h('div', { className: 'dshcap-note' }, `最近转换：${fmtTime(status.stoppedAt)}`)
          : null,

        // Export + packet browsing for the selected capture.
        selected && analysis ? h('div', { className: 'dshcap-card' },
          h('div', { className: 'dshcap-row', style: { alignItems: 'center' } },
            h('button', { className: 'dshcap-btn', disabled: busy, onClick: () => exportCapture(selected, 'csv') }, '导出 CSV'),
            h('button', { className: 'dshcap-btn', disabled: busy, onClick: () => exportCapture(selected, 'json') }, '导出 JSON'),
            h('button', { className: 'dshcap-btn', disabled: busy, onClick: () => loadPackets(selected, { limit: 100, offset: 0 }) }, '浏览数据包'),
          ),
          packets ? h('div', { style: { marginTop: 8 } },
            h('div', { className: 'dshcap-row', style: { alignItems: 'center', marginBottom: 6 } },
              h('span', { className: 'dshcap-meta' }, `共 ${packets.total} 个包，显示第 ${packets.offset + 1}–${Math.min(packets.offset + packets.limit, packets.total)} 个`),
            ),
            h('div', { className: 'dshcap-row', style: { alignItems: 'center' } },
              h('button', {
                className: 'dshcap-btn',
                disabled: busy || packets.offset <= 0,
                onClick: () => loadPackets(selected, { ...packetFilter, offset: Math.max(0, packets.offset - packets.limit) }),
              }, '上一页'),
              h('button', {
                className: 'dshcap-btn',
                disabled: busy || packets.offset + packets.limit >= packets.total,
                onClick: () => loadPackets(selected, { ...packetFilter, offset: packets.offset + packets.limit }),
              }, '下一页'),
            ),
            h('div', { className: 'dshcap-list', style: { marginTop: 6, maxHeight: 260 } },
              (packets.rows || []).map((r) => h('div', { key: r.index, className: 'dshcap-mono' },
                `#${r.index} ${r.proto} ${r.src || '?'}${r.sport ? ':' + r.sport : ''} → ${r.dst || '?'}${r.dport ? ':' + r.dport : ''}`
                + ` ${r.bytes}B`
                + (r.sni ? ` SNI=${r.sni}` : '')
                + (r.dns ? ` DNS=${r.dns.join(',')}` : '')
                + (r.http ? ` ${r.http}` : ''),
              )),
            ),
          ) : null,
        ) : null,

        h('div', { className: 'dshcap-note' },
          '分析在本地完成，不联网。抓包需要管理员权限：插件会在需要时请求一次 UAC 提权（可拒绝），'
          + '无权限时仍可对已有 pcapng 做离线分析。',
        ),
      );
    }

    const inject = ['slots'];
    const name = 'dsh-capture';

    function apply(ctx) {
      // `settings.section` is the settings-page section slot. This is the same
      // registration shape the shipping dsh-wallpaper-engine bundle uses, so it
      // is known to be accepted by the host's slot contract:
      //   { name, id, order, label() }  →  component receives ownerProps.
      // NOTE: `sidebar.right.pane.tab` was the wrong target: it renders the
      // body of a right-pane tab that must first be declared through
      // `sidebarRightTabs.register()`, so a bare register there never shows.
      ctx.slots.inject('settings.section', () => ctx.slots.register({
        name: 'settings.section',
        id: 'dsh-capture',
        order: 80,
        label: () => '抓包 Capture',
      }, (ownerProps) => h(CapturePanel, ownerProps || {})));
    }

    exports.apply = apply;
    exports.inject = inject;
    exports.name = name;
    return module.exports;
  },
});
