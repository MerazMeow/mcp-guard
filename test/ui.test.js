import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { AuditLogger } from '../src/audit.js';
import { createUiServer } from '../src/ui.js';

test('UI server serves dashboard HTML and /api/logs JSON', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-guard-ui-'));
  const logger = new AuditLogger({ cwd: tmpDir });
  logger.log({
    method: 'tools/call',
    tool: 'read_file',
    decision: 'allow',
    redactions: [{ type: 'GITHUB_TOKEN', count: 1 }],
    durationMs: 18,
  });

  const server = createUiServer({ cwd: tmpDir });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));

  try {
    const { port } = server.address();
    const htmlRes = await fetch(`http://127.0.0.1:${port}/`);
    assert.equal(htmlRes.status, 200);
    const html = await htmlRes.text();
    assert.match(html, /mcp-guard — Audit Inspector/);

    const apiRes = await fetch(`http://127.0.0.1:${port}/api/logs`);
    assert.equal(apiRes.status, 200);
    const data = await apiRes.json();
    assert.equal(data.summary.total, 1);
    assert.equal(data.summary.totalSecretsRedacted, 1);
    assert.equal(data.records[0].tool, 'read_file');
  } finally {
    await new Promise((resolve) => server.close(resolve));
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});
