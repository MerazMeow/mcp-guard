import assert from 'node:assert/strict';
import test from 'node:test';
import { redactPayload } from '../src/redactor.js';

test('redactPayload masks built-in secret formats across nested structures', () => {
  // Build synthetic test tokens dynamically so static secret scanners do not flag test fixtures.
  const payload = {
    github: ['ghp', '1234567890abcdefghij1234567890abcd'].join('_'),
    aws: ['AKIA', 'IOSFODNN7EXAMPLE'].join(''),
    openai: ['sk', 'proj', 'abcdefghijklmnopqrstuvwxyz123456'].join('-'),
    anthropic: ['sk', 'ant', 'api03', 'abcdefghijklmnopqrstuvwxyz123456'].join('-'),
    stripe: ['sk', 'live', '51AbCdEfGhIjKlMnOpQrStUvWx'].join('_'),
    slack: ['xoxb', '1234567890', '1234567890', 'abcdefghijkl'].join('-'),
    google: ['AIza', 'SyDaGmWKa4JsXZ-HjGw7ISLn_3namBGt666'].join(''),
    jwt: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U',
    bearer: 'Bearer superSecretTokenValue123456789',
    db: 'postgres://user:mySecretPass123@localhost:5432/mydb',
    envLine: 'API_KEY="my_super_secret_value_12345"',
    nested: [
      ['-----BEGIN RSA PRIVATE ', 'KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE ', 'KEY-----'].join(''),
    ],
    safeText: 'hello world 42',
  };

  const { value, redactions, totalRedactions } = redactPayload(payload);

  assert.equal(value.github, '[REDACTED:GITHUB_TOKEN]');
  assert.equal(value.aws, '[REDACTED:AWS_ACCESS_KEY]');
  assert.equal(value.openai, '[REDACTED:OPENAI_KEY]');
  assert.equal(value.anthropic, '[REDACTED:ANTHROPIC_KEY]');
  assert.equal(value.stripe, '[REDACTED:STRIPE_KEY]');
  assert.equal(value.slack, '[REDACTED:SLACK_TOKEN]');
  assert.equal(value.google, '[REDACTED:GOOGLE_API_KEY]');
  assert.equal(value.jwt, '[REDACTED:JWT_TOKEN]');
  assert.equal(value.bearer, 'Bearer [REDACTED:BEARER_TOKEN]');
  assert.equal(value.db, 'postgres://user:[REDACTED:DB_PASSWORD]@localhost:5432/mydb');
  assert.equal(value.envLine, 'API_KEY="[REDACTED:SECRET]"');
  assert.equal(value.nested[0], '[REDACTED:PRIVATE_KEY]');
  assert.equal(value.safeText, 'hello world 42');
  assert.ok(totalRedactions >= 12);
  assert.ok(redactions.some((r) => r.type === 'GITHUB_TOKEN'));
});

test('redactPayload supports customPatterns, disabledDetectors, and circular objects', () => {
  const circular = { note: 'INTERNAL-998877', aws: ['AKIA', 'IOSFODNN7EXAMPLE'].join('') };
  circular.self = circular;

  const { value } = redactPayload(circular, {
    disabledDetectors: ['AWS_ACCESS_KEY'],
    customPatterns: [{ name: 'INTERNAL_ID', pattern: 'INTERNAL-\\d+' }],
  });

  assert.equal(value.note, '[REDACTED:INTERNAL_ID]');
  assert.equal(value.aws, 'AKIAIOSFODNN7EXAMPLE');
  assert.equal(value.self, '[Circular]');
});
