import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { Writable } from 'node:stream';
import { AuditLogger } from '../src/audit.js';
import { runCli } from '../src/cli.js';

function makeBufferStream() {
  let text = '';
  const stream = new Writable({
    write(chunk, _enc, cb) {
      text += chunk.toString();
      cb();
    },
  });
  return { stream, getText: () => text };
}

test('CLI init, check, logs, and wrap work end-to-end', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-guard-cli-'));

  // 1. init --preset strict
  const outInit = makeBufferStream();
  const errInit = makeBufferStream();
  const codeInit = await runCli(['init', '--preset', 'strict'], {
    cwd: tmpDir,
    stdout: outInit.stream,
    stderr: errInit.stream,
  });
  assert.equal(codeInit, 0);
  assert.ok(fs.existsSync(path.join(tmpDir, 'mcp-guard.json')));

  // 2. check
  const outCheck = makeBufferStream();
  const errCheck = makeBufferStream();
  const codeCheck = await runCli(['check'], {
    cwd: tmpDir,
    stdout: outCheck.stream,
    stderr: errCheck.stream,
  });
  assert.equal(codeCheck, 0);
  assert.match(outCheck.getText(), /Policy OK/);

  // 3. logs --json
  const logger = new AuditLogger({ cwd: tmpDir });
  logger.log({ method: 'tools/call', tool: 'read_file', decision: 'allow', durationMs: 12 });
  logger.log({
    method: 'tools/call',
    tool: 'run_shell',
    decision: 'deny',
    reason: 'blocked',
    durationMs: 0,
  });

  const outLogs = makeBufferStream();
  const errLogs = makeBufferStream();
  const codeLogs = await runCli(['logs', '--denied-only', '--json'], {
    cwd: tmpDir,
    stdout: outLogs.stream,
    stderr: errLogs.stream,
  });
  assert.equal(codeLogs, 0);
  const parsedLogs = JSON.parse(outLogs.getText());
  assert.equal(parsedLogs.records.length, 1);
  assert.equal(parsedLogs.records[0].tool, 'run_shell');

  // 4. wrap
  const outWrap = makeBufferStream();
  const errWrap = makeBufferStream();
  const codeWrap = await runCli(
    ['wrap', '--name', 'filesystem', '--', 'npx', '-y', '@modelcontextprotocol/server-filesystem', '.'],
    { cwd: tmpDir, stdout: outWrap.stream, stderr: errWrap.stream }
  );
  assert.equal(codeWrap, 0);
  const wrapped = JSON.parse(outWrap.getText());
  assert.equal(wrapped.mcpServers.filesystem.command, 'npx');
  assert.deepEqual(wrapped.mcpServers.filesystem.args, [
    '-y',
    'mcp-guard',
    'proxy',
    '--',
    'npx',
    '-y',
    '@modelcontextprotocol/server-filesystem',
    '.',
  ]);

  fs.rmSync(tmpDir, { recursive: true, force: true });
});
