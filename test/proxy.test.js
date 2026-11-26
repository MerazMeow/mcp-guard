import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { readAuditLogs } from '../src/audit.js';
import { attachLineJsonReader } from '../src/proxy.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const BIN_PATH = path.resolve(__dirname, '../bin/mcp-guard.js');
const MOCK_SERVER_PATH = path.resolve(__dirname, './fixtures/mock-mcp-server.js');

test('E2E stdio proxy filters tools/list, blocks denied calls, redacts secrets, and logs audit events', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-guard-e2e-'));
  const policyPath = path.join(tmpDir, 'mcp-guard.json');
  const auditPath = path.join(tmpDir, '.mcp-guard', 'audit.jsonl');

  fs.writeFileSync(
    policyPath,
    JSON.stringify({
      version: 1,
      mode: 'enforce',
      hideDeniedTools: true,
      tools: { allow: ['*'], deny: ['delete_*', 'run_shell'] },
      paths: { allow: ['.'], deny: ['**/.env'] },
      redaction: { enabled: true, redactResponses: true },
      audit: { enabled: true, file: auditPath },
    })
  );

  const proc = spawn(
    process.execPath,
    [BIN_PATH, 'proxy', '--policy', policyPath, '--', process.execPath, MOCK_SERVER_PATH],
    { cwd: tmpDir, stdio: ['pipe', 'pipe', 'pipe'] }
  );

  const responses = new Map();
  const waiters = new Map();

  attachLineJsonReader(proc.stdout, (msg) => {
    if (msg.id !== undefined) {
      responses.set(msg.id, msg);
      const resolve = waiters.get(msg.id);
      if (resolve) {
        waiters.delete(msg.id);
        resolve(msg);
      }
    }
  });

  function sendAndWait(msg) {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error(`Timeout waiting for id ${msg.id}`)), 4000);
      waiters.set(msg.id, (reply) => {
        clearTimeout(timer);
        resolve(reply);
      });
      proc.stdin.write(`${JSON.stringify(msg)}\n`);
    });
  }

  try {
    const initRes = await sendAndWait({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} });
    assert.equal(initRes.result.serverInfo.name, 'mock-mcp');

    const listRes = await sendAndWait({ jsonrpc: '2.0', id: 2, method: 'tools/list' });
    assert.deepEqual(
      listRes.result.tools.map((t) => t.name),
      ['read_file']
    );

    // Allowed tool call with secret in response -> redacted!
    const readRes = await sendAndWait({
      jsonrpc: '2.0',
      id: 3,
      method: 'tools/call',
      params: { name: 'read_file', arguments: { path: './README.md' } },
    });
    assert.equal(
      readRes.result.content[0].text,
      'File ./README.md: token=[REDACTED:GITHUB_TOKEN]'
    );

    // Denied tool -> blocked with -32001 before reaching upstream
    const deleteRes = await sendAndWait({
      jsonrpc: '2.0',
      id: 4,
      method: 'tools/call',
      params: { name: 'delete_file', arguments: { path: './README.md' } },
    });
    assert.equal(deleteRes.error.code, -32001);
    assert.match(deleteRes.error.message, /Policy denied tool "delete_file"/);

    // Path traversal -> blocked
    const envRes = await sendAndWait({
      jsonrpc: '2.0',
      id: 5,
      method: 'tools/call',
      params: { name: 'read_file', arguments: { path: '.env' } },
    });
    assert.equal(envRes.error.code, -32001);
    assert.match(envRes.error.data.rule, /paths\.deny/);
    assert.match(envRes.error.message, /blocked by path deny rule/);

    // resources/read -> DB password redacted
    const resRead = await sendAndWait({
      jsonrpc: '2.0',
      id: 6,
      method: 'resources/read',
      params: { uri: 'db://config' },
    });
    assert.equal(
      resRead.result.contents[0].text,
      'postgres://admin:[REDACTED:DB_PASSWORD]@db.example.com:5432/app'
    );
  } finally {
    proc.stdin.end();
    await new Promise((resolve) => proc.once('exit', resolve));
  }

  const records = readAuditLogs(auditPath);
  assert.equal(records.length, 4);
  assert.equal(records[0].decision, 'allow');
  assert.equal(records[0].redactions[0].type, 'GITHUB_TOKEN');
  assert.equal(records[1].decision, 'deny');
  assert.equal(records[2].decision, 'deny');
  assert.equal(records[3].redactions[0].type, 'DATABASE_URL_PASSWORD');

  fs.rmSync(tmpDir, { recursive: true, force: true });
});
