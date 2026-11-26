import http from 'node:http';
import path from 'node:path';
import { readAuditLogs, summarizeAuditLogs } from './audit.js';
import { loadPolicy } from './policy.js';

const DASHBOARD_HTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>mcp-guard — Audit Inspector</title>
  <style>
    :root {
      --bg: #0b0f17;
      --panel: #131a26;
      --border: #232f44;
      --text: #e6edf7;
      --muted: #8b9bb4;
      --accent: #38bdf8;
      --ok: #34d399;
      --warn: #fbbf24;
      --bad: #f87171;
      --mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.5;
    }
    header {
      border-bottom: 1px solid var(--border);
      padding: 16px 24px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      background: var(--panel);
    }
    .brand { display: flex; align-items: center; gap: 10px; font-weight: 700; font-size: 18px; }
    .badge {
      font-size: 12px;
      padding: 2px 8px;
      border-radius: 999px;
      border: 1px solid var(--border);
      color: var(--accent);
      font-family: var(--mono);
    }
    main { max-width: 1180px; margin: 0 auto; padding: 24px; }
    .cards {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 14px;
      margin-bottom: 20px;
    }
    .card {
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 16px;
    }
    .card-label { font-size: 12px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.05em; }
    .card-value { font-size: 28px; font-weight: 700; margin-top: 6px; font-family: var(--mono); }
    .controls {
      display: flex;
      gap: 10px;
      flex-wrap: wrap;
      margin-bottom: 14px;
      align-items: center;
    }
    input, select, button {
      background: var(--panel);
      border: 1px solid var(--border);
      color: var(--text);
      padding: 8px 12px;
      border-radius: 8px;
      font-size: 14px;
    }
    button { cursor: pointer; }
    button:hover { border-color: var(--accent); }
    .table-wrap {
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 10px;
      overflow-x: auto;
    }
    table { width: 100%; border-collapse: collapse; font-size: 13px; }
    th, td { padding: 10px 12px; text-align: left; border-bottom: 1px solid var(--border); vertical-align: top; }
    th { color: var(--muted); font-weight: 600; font-size: 12px; text-transform: uppercase; }
    .mono { font-family: var(--mono); }
    .pill {
      display: inline-block;
      padding: 2px 8px;
      border-radius: 999px;
      font-size: 11px;
      font-weight: 600;
      font-family: var(--mono);
    }
    .allow { background: rgba(52, 211, 153, 0.14); color: var(--ok); }
    .deny { background: rgba(248, 113, 113, 0.16); color: var(--bad); }
    .would_block { background: rgba(251, 191, 36, 0.16); color: var(--warn); }
    .redact { background: rgba(56, 189, 248, 0.15); color: var(--accent); margin-right: 4px; }
    .muted { color: var(--muted); }
    .preview { max-width: 360px; word-break: break-all; color: var(--muted); font-size: 12px; }
  </style>
</head>
<body>
  <header>
    <div class="brand">
      <span>mcp-guard</span>
      <span class="badge" id="modeBadge">mode: —</span>
    </div>
    <div class="muted mono" style="font-size: 12px;" id="metaInfo">Loading...</div>
  </header>
  <main>
    <section class="cards">
      <div class="card"><div class="card-label">Total Events</div><div class="card-value" id="statTotal">0</div></div>
      <div class="card"><div class="card-label">Allowed</div><div class="card-value" style="color: var(--ok)" id="statAllowed">0</div></div>
      <div class="card"><div class="card-label">Blocked</div><div class="card-value" style="color: var(--bad)" id="statDenied">0</div></div>
      <div class="card"><div class="card-label">Secrets Redacted</div><div class="card-value" style="color: var(--accent)" id="statRedacted">0</div></div>
      <div class="card"><div class="card-label">Avg Latency</div><div class="card-value" id="statLatency">0 ms</div></div>
    </section>

    <section class="controls">
      <input id="searchInput" type="search" placeholder="Filter by tool, rule, or args..." style="min-width: 240px;" />
      <select id="decisionFilter">
        <option value="">All Decisions</option>
        <option value="deny">Denied Only</option>
        <option value="would_block">Would Block (Audit)</option>
        <option value="allow">Allowed Only</option>
      </select>
      <button id="refreshBtn" type="button">Refresh</button>
      <label class="muted" style="font-size: 13px; margin-left: auto;">
        <input type="checkbox" id="autoRefresh" checked /> Auto-refresh (2s)
      </label>
    </section>

    <section class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Time</th>
            <th>Tool</th>
            <th>Decision</th>
            <th>Redactions</th>
            <th>Latency</th>
            <th>Details / Args Preview</th>
          </tr>
        </thead>
        <tbody id="logBody">
          <tr><td colspan="6" class="muted">No audit events recorded yet.</td></tr>
        </tbody>
      </table>
    </section>
  </main>

  <script>
    const els = {
      modeBadge: document.getElementById('modeBadge'),
      metaInfo: document.getElementById('metaInfo'),
      statTotal: document.getElementById('statTotal'),
      statAllowed: document.getElementById('statAllowed'),
      statDenied: document.getElementById('statDenied'),
      statRedacted: document.getElementById('statRedacted'),
      statLatency: document.getElementById('statLatency'),
      searchInput: document.getElementById('searchInput'),
      decisionFilter: document.getElementById('decisionFilter'),
      refreshBtn: document.getElementById('refreshBtn'),
      autoRefresh: document.getElementById('autoRefresh'),
      logBody: document.getElementById('logBody'),
    };

    function esc(str) {
      return String(str ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
    }

    let cachedData = null;

    function render() {
      if (!cachedData) return;
      const { summary, records, policy } = cachedData;
      els.modeBadge.textContent = 'mode: ' + (policy?.mode ?? 'enforce');
      els.metaInfo.textContent = cachedData.auditFile || '';
      els.statTotal.textContent = summary.total;
      els.statAllowed.textContent = summary.allowed;
      els.statDenied.textContent = summary.denied + (summary.wouldBlock ? ' (+' + summary.wouldBlock + ')' : '');
      els.statRedacted.textContent = summary.totalSecretsRedacted;
      els.statLatency.textContent = summary.avgLatencyMs + ' ms';

      const q = els.searchInput.value.trim().toLowerCase();
      const dec = els.decisionFilter.value;

      const filtered = records
        .slice()
        .reverse()
        .filter((r) => {
          if (dec && r.decision !== dec) return false;
          if (!q) return true;
          const hay = [r.tool, r.rule, r.reason, r.argsPreview].join(' ').toLowerCase();
          return hay.includes(q);
        })
        .slice(0, 200);

      if (filtered.length === 0) {
        els.logBody.innerHTML = '<tr><td colspan="6" class="muted">No matching audit events.</td></tr>';
        return;
      }

      els.logBody.innerHTML = filtered
        .map((r) => {
          const time = r.timestamp ? new Date(r.timestamp).toLocaleTimeString() : '—';
          const redBadges = (r.redactions || [])
            .map((x) => '<span class="pill redact">' + esc(x.type) + ' ×' + esc(x.count) + '</span>')
            .join('');
          const detail = [r.reason ? 'Rule: ' + r.reason : '', r.argsPreview || '']
            .filter(Boolean)
            .join(' | ');
          return (
            '<tr>' +
            '<td class="mono muted">' + esc(time) + '</td>' +
            '<td class="mono">' + esc(r.tool || r.method) + '</td>' +
            '<td><span class="pill ' + esc(r.decision) + '">' + esc(r.decision) + '</span></td>' +
            '<td>' + (redBadges || '<span class="muted">—</span>') + '</td>' +
            '<td class="mono muted">' + (typeof r.durationMs === 'number' ? r.durationMs + 'ms' : '—') + '</td>' +
            '<td class="mono preview">' + esc(detail || '—') + '</td>' +
            '</tr>'
          );
        })
        .join('');
    }

    async function load() {
      try {
        const res = await fetch('/api/logs');
        cachedData = await res.json();
        render();
      } catch (err) {
        els.metaInfo.textContent = 'Error refreshing logs';
      }
    }

    els.refreshBtn.addEventListener('click', load);
    els.searchInput.addEventListener('input', render);
    els.decisionFilter.addEventListener('change', render);

    load();
    setInterval(() => {
      if (els.autoRefresh.checked) load();
    }, 2000);
  </script>
</body>
</html>
`;

/**
 * Creates a zero-dependency local HTTP server for inspecting mcp-guard audit logs.
 */
export function createUiServer({ auditFile, policyPath, cwd = process.cwd() } = {}) {
  const { policy } = loadPolicy(policyPath, cwd);
  const resolvedAudit = path.resolve(cwd, auditFile ?? policy.audit.file);

  const server = http.createServer((req, res) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1');

    if (url.pathname === '/' || url.pathname === '/index.html') {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(DASHBOARD_HTML);
      return;
    }

    if (url.pathname === '/api/logs') {
      const records = readAuditLogs(resolvedAudit, { cwd });
      const summary = summarizeAuditLogs(records);
      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
      res.end(
        JSON.stringify({
          auditFile: resolvedAudit,
          summary,
          records,
          policy: {
            mode: policy.mode,
            hideDeniedTools: policy.hideDeniedTools,
            rateLimit: policy.rateLimit,
          },
        })
      );
      return;
    }

    res.writeHead(404, { 'Content-Type': 'application/json; charset=utf-8' });
    res.end(JSON.stringify({ error: 'Not found' }));
  });

  return server;
}
