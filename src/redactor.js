/**
 * Built-in high-precision secret detectors.
 * Each detector uses either a replacement string or replacer function so surrounding syntax is preserved.
 */
export const BUILTIN_DETECTORS = [
  {
    name: 'PRIVATE_KEY',
    regex: /-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY-----/g,
    replace: () => '[REDACTED:PRIVATE_KEY]',
  },
  {
    name: 'AWS_ACCESS_KEY',
    regex: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g,
    replace: () => '[REDACTED:AWS_ACCESS_KEY]',
  },
  {
    name: 'GITHUB_TOKEN',
    regex: /\b(?:gh[pousr]_[A-Za-z0-9_]{20,255}|github_pat_[A-Za-z0-9_]{20,255})\b/g,
    replace: () => '[REDACTED:GITHUB_TOKEN]',
  },
  {
    name: 'ANTHROPIC_KEY',
    regex: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g,
    replace: () => '[REDACTED:ANTHROPIC_KEY]',
  },
  {
    name: 'OPENAI_KEY',
    regex: /\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}\b/g,
    replace: () => '[REDACTED:OPENAI_KEY]',
  },
  {
    name: 'STRIPE_KEY',
    regex: /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b/g,
    replace: () => '[REDACTED:STRIPE_KEY]',
  },
  {
    name: 'SLACK_TOKEN',
    regex: /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/g,
    replace: () => '[REDACTED:SLACK_TOKEN]',
  },
  {
    name: 'GOOGLE_API_KEY',
    regex: /\bAIza[0-9A-Za-z_-]{35}\b/g,
    replace: () => '[REDACTED:GOOGLE_API_KEY]',
  },
  {
    name: 'JWT_TOKEN',
    regex: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,
    replace: () => '[REDACTED:JWT_TOKEN]',
  },
  {
    name: 'BEARER_TOKEN',
    regex: /\b(Bearer\s+)([A-Za-z0-9._~+/-]{16,}=*)/gi,
    replace: (_match, prefix) => `${prefix}[REDACTED:BEARER_TOKEN]`,
  },
  {
    name: 'DATABASE_URL_PASSWORD',
    regex: /\b((?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp):\/\/[^:\s/@]+:)([^@\s/]+)(@)/gi,
    replace: (_match, prefix, _secret, at) => `${prefix}[REDACTED:DB_PASSWORD]${at}`,
  },
  {
    name: 'SECRET_ASSIGNMENT',
    regex: /\b((?:password|passwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|private[_-]?key)\s*[:=]\s*["']?)([A-Za-z0-9._~+/=-]{8,})(["']?)/gi,
    replace: (_match, prefix, _secret, suffix) => `${prefix}[REDACTED:SECRET]${suffix}`,
  },
];

function buildDetectors(redactionConfig = {}) {
  const disabled = new Set(redactionConfig.disabledDetectors ?? []);
  const active = BUILTIN_DETECTORS.filter((d) => !disabled.has(d.name));

  for (const custom of redactionConfig.customPatterns ?? []) {
    if (!custom?.pattern) continue;
    const name = custom.name ?? 'CUSTOM_SECRET';
    const rawFlags = custom.flags ?? 'g';
    const flags = rawFlags.includes('g') ? rawFlags : `${rawFlags}g`;
    active.push({
      name,
      regex: new RegExp(custom.pattern, flags),
      replace: () => `[REDACTED:${name}]`,
    });
  }

  return active;
}

/**
 * Redacts secrets from a single string, returning the sanitized string and match counts.
 */
export function redactString(input, detectors) {
  let output = input;
  const counts = new Map();

  for (const detector of detectors) {
    detector.regex.lastIndex = 0;
    let matches = 0;
    output = output.replace(detector.regex, (...args) => {
      matches += 1;
      return detector.replace(...args);
    });
    if (matches > 0) {
      counts.set(detector.name, (counts.get(detector.name) ?? 0) + matches);
    }
  }

  return { output, counts };
}

/**
 * Recursively redacts secrets across strings, arrays, and plain objects.
 * Returns { value, redactions: [{ type, count }], totalRedactions }.
 */
export function redactPayload(payload, redactionConfig = {}) {
  if (redactionConfig.enabled === false) {
    return { value: payload, redactions: [], totalRedactions: 0 };
  }

  const detectors = buildDetectors(redactionConfig);
  const totals = new Map();
  const seen = new WeakSet();

  function walk(node) {
    if (typeof node === 'string') {
      const { output, counts } = redactString(node, detectors);
      for (const [k, v] of counts.entries()) {
        totals.set(k, (totals.get(k) ?? 0) + v);
      }
      return output;
    }

    if (!node || typeof node !== 'object') {
      return node;
    }

    if (seen.has(node)) {
      return '[Circular]';
    }
    seen.add(node);

    if (Array.isArray(node)) {
      return node.map((item) => walk(item));
    }

    const copy = {};
    for (const [k, v] of Object.entries(node)) {
      copy[k] = walk(v);
    }
    return copy;
  }

  const value = walk(payload);
  const redactions = Array.from(totals.entries()).map(([type, count]) => ({ type, count }));
  const totalRedactions = redactions.reduce((acc, r) => acc + r.count, 0);

  return { value, redactions, totalRedactions };
}
