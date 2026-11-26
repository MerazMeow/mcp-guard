import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {
  createRateLimiter,
  evaluateToolCall,
  getPresetPolicy,
  isToolVisible,
  normalizePolicy,
  validatePolicy,
} from '../src/policy.js';

test('presets generate valid policies with expected security posture', () => {
  const standard = getPresetPolicy('standard');
  const strict = getPresetPolicy('strict');
  const readonly = getPresetPolicy('readonly');

  assert.equal(validatePolicy(standard).valid, true);
  assert.equal(validatePolicy(strict).valid, true);
  assert.equal(validatePolicy(readonly).valid, true);

  assert.deepEqual(strict.paths.allow, ['.']);
  assert.equal(strict.redaction.redactRequests, true);
  assert.ok(readonly.tools.deny.includes('write_*'));
  assert.ok(readonly.tools.deny.includes('delete_*'));
});

test('validatePolicy catches invalid mode, regexes, and numeric bounds', () => {
  const bad = validatePolicy({
    mode: 'yolo',
    args: {
      blockedPatterns: [{ name: 'bad', pattern: '[unclosed' }],
      maxPayloadBytes: -5,
    },
    rateLimit: { maxCallsPerMinute: -1 },
    redaction: { customPatterns: [{ name: 'bad2', pattern: '(unclosed' }] },
  });

  assert.equal(bad.valid, false);
  assert.equal(bad.errors.length, 5);
});

test('tool allow/deny globs and visibility filtering work together', () => {
  const policy = normalizePolicy({
    tools: {
      allow: ['read_*', 'list_*'],
      deny: ['read_secrets'],
    },
  });

  assert.equal(isToolVisible(policy, 'read_file'), true);
  assert.equal(isToolVisible(policy, 'read_secrets'), false);
  assert.equal(isToolVisible(policy, 'delete_file'), false);

  assert.equal(evaluateToolCall(policy, { toolName: 'read_file' }).decision, 'allow');
  assert.equal(evaluateToolCall(policy, { toolName: 'read_secrets' }).decision, 'deny');
  assert.equal(evaluateToolCall(policy, { toolName: 'delete_file' }).decision, 'deny');
});

test('path checks block .env, ~/.ssh, relative traversal, and file:// URIs', () => {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-guard-path-'));
  const policy = normalizePolicy({
    paths: {
      allow: ['.'],
      deny: ['~/.ssh', '**/.env', '**/.env.*'],
    },
  });

  const ok = evaluateToolCall(policy, {
    toolName: 'read_file',
    args: { path: './src/index.js' },
    cwd,
  });
  assert.equal(ok.decision, 'allow');

  const envBlocked = evaluateToolCall(policy, {
    toolName: 'read_file',
    args: { nested: { file_path: '.env.production' } },
    cwd,
  });
  assert.equal(envBlocked.decision, 'deny');
  assert.match(envBlocked.rule, /paths\.deny/);

  const sshBlocked = evaluateToolCall(policy, {
    toolName: 'read_file',
    args: { path: '~/.ssh/id_rsa' },
    cwd,
  });
  assert.equal(sshBlocked.decision, 'deny');

  const traversalBlocked = evaluateToolCall(policy, {
    toolName: 'read_file',
    args: { path: '../../etc/passwd' },
    cwd,
  });
  assert.equal(traversalBlocked.decision, 'deny');

  const fileUriBlocked = evaluateToolCall(policy, {
    toolName: 'read_file',
    args: { uri: 'file:///etc/hosts' },
    cwd,
  });
  assert.equal(fileUriBlocked.decision, 'deny');

  fs.rmSync(cwd, { recursive: true, force: true });
});

test('blockedPatterns, maxPayloadBytes, rateLimit, and audit mode behave properly', () => {
  const strict = getPresetPolicy('strict');
  const blockedCmd = evaluateToolCall(strict, {
    toolName: 'run_shell',
    args: { command: 'rm -rf /tmp/foo' },
  });
  assert.equal(blockedCmd.decision, 'deny');
  assert.equal(blockedCmd.rule, 'args.blockedPatterns:rm_rf');

  const auditPolicy = normalizePolicy({ ...strict, mode: 'audit' });
  const wouldBlock = evaluateToolCall(auditPolicy, {
    toolName: 'run_shell',
    args: { command: 'sudo reboot' },
  });
  assert.equal(wouldBlock.decision, 'would_block');

  const sizeLimited = normalizePolicy({ args: { maxPayloadBytes: 20 } });
  assert.equal(
    evaluateToolCall(sizeLimited, {
      toolName: 'write_note',
      args: { text: 'this payload is way longer than twenty bytes' },
    }).decision,
    'deny'
  );

  const limiter = createRateLimiter(2);
  const ratePolicy = normalizePolicy({ rateLimit: { maxCallsPerMinute: 2 } });
  assert.equal(evaluateToolCall(ratePolicy, { toolName: 'ping', rateLimiter: limiter }).decision, 'allow');
  assert.equal(evaluateToolCall(ratePolicy, { toolName: 'ping', rateLimiter: limiter }).decision, 'allow');
  assert.equal(evaluateToolCall(ratePolicy, { toolName: 'ping', rateLimiter: limiter }).decision, 'deny');
});
