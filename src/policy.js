import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

export const DEFAULT_ENFORCED_PATH_ARGS = [
  'path',
  'file',
  'filepath',
  'file_path',
  'dir',
  'directory',
  'target',
  'source',
  'src',
  'dest',
  'destination',
  'uri',
  'cwd',
  'root',
];

export const DEFAULT_DENIED_PATHS = [
  '~/.ssh',
  '~/.aws',
  '~/.gnupg',
  '~/.kube',
  '/etc/shadow',
  '/etc/passwd',
  '**/.env',
  '**/.env.*',
  '**/*.pem',
  '**/*.key',
];

/**
 * Base default policy used when no mcp-guard.json exists.
 */
export const DEFAULT_POLICY = {
  version: 1,
  mode: 'enforce',
  hideDeniedTools: true,
  tools: {
    allow: ['*'],
    deny: [],
  },
  paths: {
    allow: [],
    deny: DEFAULT_DENIED_PATHS,
    enforceOnArgs: DEFAULT_ENFORCED_PATH_ARGS,
  },
  args: {
    blockedPatterns: [],
    maxPayloadBytes: 1048576,
  },
  rateLimit: {
    maxCallsPerMinute: 120,
  },
  redaction: {
    enabled: true,
    redactRequests: false,
    redactResponses: true,
    disabledDetectors: [],
    customPatterns: [],
  },
  audit: {
    enabled: true,
    file: '.mcp-guard/audit.jsonl',
    logArguments: true,
  },
};

const STRICT_BLOCKED_PATTERNS = [
  { name: 'rm_rf', pattern: 'rm\\s+-[a-zA-Z]*r[a-zA-Z]*f', flags: 'i' },
  { name: 'curl_pipe_shell', pattern: '(?:curl|wget)\\s+[^|]+\\|\\s*(?:sh|bash|zsh)', flags: 'i' },
  { name: 'sudo_usage', pattern: '(?:^|\\s)sudo\\s+', flags: 'i' },
];

const READONLY_DENIED_TOOLS = [
  'write_*',
  'create_*',
  'update_*',
  'delete_*',
  'remove_*',
  'edit_*',
  'patch_*',
  'move_*',
  'rename_*',
  'mkdir*',
  'run_*',
  'exec*',
  'shell*',
  'bash*',
  'put_*',
  'post_*',
  'drop_*',
];

/**
 * Returns a starter policy configuration for a named preset.
 * @param {'standard' | 'strict' | 'readonly'} preset
 */
export function getPresetPolicy(preset = 'standard') {
  const base = structuredClone(DEFAULT_POLICY);

  if (preset === 'standard') {
    return base;
  }

  if (preset === 'strict') {
    base.paths.allow = ['.'];
    base.args.blockedPatterns = structuredClone(STRICT_BLOCKED_PATTERNS);
    base.rateLimit.maxCallsPerMinute = 60;
    base.redaction.redactRequests = true;
    return base;
  }

  if (preset === 'readonly') {
    base.tools.deny = [...READONLY_DENIED_TOOLS];
    base.paths.allow = ['.'];
    base.args.blockedPatterns = structuredClone(STRICT_BLOCKED_PATTERNS);
    base.rateLimit.maxCallsPerMinute = 60;
    base.redaction.redactRequests = true;
    return base;
  }

  throw new Error(`Unknown preset "${preset}". Expected: standard, strict, or readonly.`);
}

/**
 * Deep-merges user-supplied policy fields with DEFAULT_POLICY.
 * @param {Record<string, any>} userPolicy
 */
export function normalizePolicy(userPolicy = {}) {
  const base = structuredClone(DEFAULT_POLICY);
  const input = userPolicy && typeof userPolicy === 'object' ? userPolicy : {};

  return {
    version: input.version ?? base.version,
    mode: input.mode ?? base.mode,
    hideDeniedTools: input.hideDeniedTools ?? base.hideDeniedTools,
    tools: {
      allow: Array.isArray(input.tools?.allow) ? input.tools.allow : base.tools.allow,
      deny: Array.isArray(input.tools?.deny) ? input.tools.deny : base.tools.deny,
    },
    paths: {
      allow: Array.isArray(input.paths?.allow) ? input.paths.allow : base.paths.allow,
      deny: Array.isArray(input.paths?.deny) ? input.paths.deny : base.paths.deny,
      enforceOnArgs: Array.isArray(input.paths?.enforceOnArgs)
        ? input.paths.enforceOnArgs
        : base.paths.enforceOnArgs,
    },
    args: {
      blockedPatterns: Array.isArray(input.args?.blockedPatterns)
        ? input.args.blockedPatterns
        : base.args.blockedPatterns,
      maxPayloadBytes:
        input.args?.maxPayloadBytes !== undefined
          ? input.args.maxPayloadBytes
          : base.args.maxPayloadBytes,
    },
    rateLimit: {
      maxCallsPerMinute:
        input.rateLimit?.maxCallsPerMinute !== undefined
          ? input.rateLimit.maxCallsPerMinute
          : base.rateLimit.maxCallsPerMinute,
    },
    redaction: {
      enabled: input.redaction?.enabled ?? base.redaction.enabled,
      redactRequests: input.redaction?.redactRequests ?? base.redaction.redactRequests,
      redactResponses: input.redaction?.redactResponses ?? base.redaction.redactResponses,
      disabledDetectors: Array.isArray(input.redaction?.disabledDetectors)
        ? input.redaction.disabledDetectors
        : base.redaction.disabledDetectors,
      customPatterns: Array.isArray(input.redaction?.customPatterns)
        ? input.redaction.customPatterns
        : base.redaction.customPatterns,
    },
    audit: {
      enabled: input.audit?.enabled ?? base.audit.enabled,
      file: input.audit?.file ?? base.audit.file,
      logArguments: input.audit?.logArguments ?? base.audit.logArguments,
    },
  };
}

/**
 * Loads and normalizes a policy from disk, or returns DEFAULT_POLICY if no path is given
 * and default mcp-guard.json does not exist.
 * @param {string | undefined} policyPath
 * @param {string} cwd
 */
export function loadPolicy(policyPath, cwd = process.cwd()) {
  const resolved = policyPath
    ? path.resolve(cwd, policyPath)
    : path.resolve(cwd, 'mcp-guard.json');

  if (!fs.existsSync(resolved)) {
    if (policyPath) {
      throw new Error(`Policy file not found: ${resolved}`);
    }
    return { policy: normalizePolicy({}), policyPath: null };
  }

  const raw = fs.readFileSync(resolved, 'utf8');
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    throw new Error(`Invalid JSON in policy file ${resolved}: ${err.message}`);
  }

  return { policy: normalizePolicy(parsed), policyPath: resolved };
}

/**
 * Validates a policy object for schema errors and invalid regular expressions.
 * @param {Record<string, any>} rawPolicy
 */
export function validatePolicy(rawPolicy) {
  const errors = [];
  const warnings = [];

  if (!rawPolicy || typeof rawPolicy !== 'object' || Array.isArray(rawPolicy)) {
    return { valid: false, errors: ['Policy must be a JSON object.'], warnings };
  }

  if (rawPolicy.mode !== undefined && !['enforce', 'audit'].includes(rawPolicy.mode)) {
    errors.push(`Invalid "mode": "${rawPolicy.mode}". Expected "enforce" or "audit".`);
  }

  const normalized = normalizePolicy(rawPolicy);

  for (const [idx, item] of normalized.args.blockedPatterns.entries()) {
    const patternStr = typeof item === 'string' ? item : item?.pattern;
    const flags = typeof item === 'string' ? 'i' : (item?.flags ?? 'i');
    if (!patternStr || typeof patternStr !== 'string') {
      errors.push(`args.blockedPatterns[${idx}] must be a pattern string or { name, pattern }.`);
      continue;
    }
    try {
      new RegExp(patternStr, flags);
    } catch (err) {
      errors.push(`Invalid regex in args.blockedPatterns[${idx}]: ${err.message}`);
    }
  }

  for (const [idx, item] of normalized.redaction.customPatterns.entries()) {
    if (!item?.pattern || typeof item.pattern !== 'string') {
      errors.push(`redaction.customPatterns[${idx}] requires a "pattern" string.`);
      continue;
    }
    try {
      new RegExp(item.pattern, item.flags ?? 'g');
    } catch (err) {
      errors.push(`Invalid regex in redaction.customPatterns[${idx}]: ${err.message}`);
    }
  }

  if (
    normalized.rateLimit.maxCallsPerMinute !== null &&
    (typeof normalized.rateLimit.maxCallsPerMinute !== 'number' ||
      normalized.rateLimit.maxCallsPerMinute < 0)
  ) {
    errors.push('rateLimit.maxCallsPerMinute must be a non-negative number or null.');
  }

  if (
    normalized.args.maxPayloadBytes !== null &&
    (typeof normalized.args.maxPayloadBytes !== 'number' || normalized.args.maxPayloadBytes <= 0)
  ) {
    errors.push('args.maxPayloadBytes must be a positive number or null.');
  }

  if (normalized.mode === 'audit') {
    warnings.push('Policy is in "audit" mode: violations are logged but will NOT be blocked.');
  }

  if (normalized.tools.allow.length === 0) {
    warnings.push('tools.allow is empty: all tool calls will be denied.');
  }

  return { valid: errors.length === 0, errors, warnings };
}

/**
 * Matches a tool name against a wildcard pattern (* and ?).
 */
export function matchToolGlob(pattern, toolName) {
  if (pattern === '*') return true;
  const regexStr = pattern.replace(/([*?]|[.+^${}()|[\]\\])/g, (tok) => {
    if (tok === '*') return '.*';
    if (tok === '?') return '.';
    return `\\${tok}`;
  });
  return new RegExp(`^${regexStr}$`).test(toolName);
}

/**
 * Expands leading ~, strips file:// URIs, and resolves relative paths against cwd.
 */
export function normalizePathValue(rawValue, cwd = process.cwd()) {
  let value = rawValue.trim();

  if (value.startsWith('file://')) {
    try {
      value = new URL(value).pathname;
    } catch {
      value = value.slice('file://'.length);
    }
  }

  if (value === '~') {
    value = os.homedir();
  } else if (value.startsWith('~/') || value.startsWith('~\\')) {
    value = path.join(os.homedir(), value.slice(2));
  }

  const resolved = path.resolve(cwd, value);

  // Resolve symlinks when target exists so symlink escapes cannot bypass directory checks.
  try {
    if (fs.existsSync(resolved)) {
      return fs.realpathSync(resolved);
    }
  } catch {
    // Fall back to lexical resolution if stat/realpath is restricted.
  }

  return resolved;
}

function toPosix(p) {
  return p.split(path.sep).join('/');
}

function isPathInside(parentPath, childPath) {
  const normParent = path.resolve(parentPath);
  const normChild = path.resolve(childPath);
  if (normParent === normChild) return true;
  const prefix = normParent.endsWith(path.sep) ? normParent : normParent + path.sep;
  return normChild.startsWith(prefix);
}

function matchPathRule(rulePattern, targetPath, cwd) {
  const hasGlob = /[*?]/.test(rulePattern);

  if (!hasGlob) {
    const resolvedRule = normalizePathValue(rulePattern, cwd);
    return isPathInside(resolvedRule, targetPath);
  }

  // Handle patterns like "**/.env" or "~/.ssh/*"
  let expandedRule = rulePattern;
  if (expandedRule === '~' || expandedRule.startsWith('~/')) {
    expandedRule = path.join(os.homedir(), expandedRule.slice(2));
  } else if (!expandedRule.startsWith('**/') && !path.isAbsolute(expandedRule)) {
    expandedRule = path.resolve(cwd, expandedRule);
  }

  const posixRule = toPosix(expandedRule);
  const posixTarget = toPosix(targetPath);

  const regexBody = posixRule.replace(/(\*\*\/|\*\*|\*|\?|[.+^${}()|[\]\\])/g, (tok) => {
    if (tok === '**/') return '(?:.*/)?';
    if (tok === '**') return '.*';
    if (tok === '*') return '[^/]*';
    if (tok === '?') return '[^/]';
    return `\\${tok}`;
  });

  const regex = new RegExp(`^${regexBody}$`);
  return regex.test(posixTarget);
}

function collectPathCandidates(obj, enforceKeysSet, out = []) {
  if (!obj || typeof obj !== 'object') return out;

  if (Array.isArray(obj)) {
    for (const item of obj) {
      collectPathCandidates(item, enforceKeysSet, out);
    }
    return out;
  }

  for (const [key, val] of Object.entries(obj)) {
    const lowerKey = key.toLowerCase();
    if (enforceKeysSet.has(lowerKey)) {
      if (typeof val === 'string' && val.trim().length > 0) {
        out.push({ arg: key, value: val });
      } else if (Array.isArray(val)) {
        for (const entry of val) {
          if (typeof entry === 'string' && entry.trim().length > 0) {
            out.push({ arg: key, value: entry });
          }
        }
      }
    } else if (val && typeof val === 'object') {
      collectPathCandidates(val, enforceKeysSet, out);
    }
  }

  return out;
}

function collectStringValues(obj, out = []) {
  if (typeof obj === 'string') {
    out.push(obj);
    return out;
  }
  if (!obj || typeof obj !== 'object') return out;
  if (Array.isArray(obj)) {
    for (const item of obj) collectStringValues(item, out);
    return out;
  }
  for (const val of Object.values(obj)) {
    collectStringValues(val, out);
  }
  return out;
}

/**
 * Evaluates whether a tool is permitted to appear in tools/list.
 */
export function isToolVisible(policy, toolName) {
  if (!policy.hideDeniedTools) return true;
  if (policy.tools.deny.some((pat) => matchToolGlob(pat, toolName))) {
    return false;
  }
  if (!policy.tools.allow.some((pat) => matchToolGlob(pat, toolName))) {
    return false;
  }
  return true;
}

/**
 * Creates a sliding-window per-minute rate limiter.
 */
export function createRateLimiter(maxCallsPerMinute) {
  const timestamps = [];

  return {
    check(now = Date.now()) {
      if (!maxCallsPerMinute || maxCallsPerMinute <= 0) {
        return { allowed: true, remaining: Infinity };
      }
      const cutoff = now - 60_000;
      while (timestamps.length > 0 && timestamps[0] <= cutoff) {
        timestamps.shift();
      }
      if (timestamps.length >= maxCallsPerMinute) {
        return { allowed: false, remaining: 0 };
      }
      timestamps.push(now);
      return { allowed: true, remaining: maxCallsPerMinute - timestamps.length };
    },
  };
}

/**
 * Evaluates a single tools/call invocation against the active policy.
 * Returns { decision: 'allow' | 'deny' | 'would_block', reason, rule }.
 */
export function evaluateToolCall(policy, { toolName, args = {}, cwd = process.cwd(), rateLimiter }) {
  const violate = (reason, rule) => {
    if (policy.mode === 'audit') {
      return { decision: 'would_block', reason, rule };
    }
    return { decision: 'deny', reason, rule };
  };

  // 1. Rate limit check
  if (rateLimiter && !rateLimiter.check().allowed) {
    return violate(
      `Rate limit exceeded (${policy.rateLimit.maxCallsPerMinute} calls/min)`,
      'rateLimit.maxCallsPerMinute'
    );
  }

  // 2. Payload size check
  if (policy.args.maxPayloadBytes) {
    const bytes = Buffer.byteLength(JSON.stringify(args ?? {}), 'utf8');
    if (bytes > policy.args.maxPayloadBytes) {
      return violate(
        `Argument payload size (${bytes} bytes) exceeds limit (${policy.args.maxPayloadBytes} bytes)`,
        'args.maxPayloadBytes'
      );
    }
  }

  // 3. Tool deny / allow checks
  const deniedToolPat = policy.tools.deny.find((pat) => matchToolGlob(pat, toolName));
  if (deniedToolPat) {
    return violate(`Tool "${toolName}" matched deny rule "${deniedToolPat}"`, `tools.deny:${deniedToolPat}`);
  }

  const allowedToolPat = policy.tools.allow.some((pat) => matchToolGlob(pat, toolName));
  if (!allowedToolPat) {
    return violate(`Tool "${toolName}" is not in tools.allow`, 'tools.allow');
  }

  // 4. Path allow/deny checks
  const enforceKeys = new Set(policy.paths.enforceOnArgs.map((k) => k.toLowerCase()));
  const pathCandidates = collectPathCandidates(args, enforceKeys);

  for (const candidate of pathCandidates) {
    const resolvedPath = normalizePathValue(candidate.value, cwd);

    const matchedDeny = policy.paths.deny.find((rule) => matchPathRule(rule, resolvedPath, cwd));
    if (matchedDeny) {
      return violate(
        `Argument "${candidate.arg}" resolves to "${resolvedPath}", blocked by path deny rule "${matchedDeny}"`,
        `paths.deny:${matchedDeny}`
      );
    }

    if (policy.paths.allow.length > 0) {
      const isAllowed = policy.paths.allow.some((rule) => matchPathRule(rule, resolvedPath, cwd));
      if (!isAllowed) {
        return violate(
          `Argument "${candidate.arg}" resolves to "${resolvedPath}", outside allowed paths`,
          'paths.allow'
        );
      }
    }
  }

  // 5. Blocked argument regex patterns
  if (policy.args.blockedPatterns.length > 0) {
    const strings = collectStringValues(args);
    for (const entry of policy.args.blockedPatterns) {
      const name = typeof entry === 'string' ? entry : (entry.name ?? entry.pattern);
      const pattern = typeof entry === 'string' ? entry : entry.pattern;
      const flags = typeof entry === 'string' ? 'i' : (entry.flags ?? 'i');
      const regex = new RegExp(pattern, flags);

      for (const str of strings) {
        if (regex.test(str)) {
          return violate(
            `Argument matched blocked pattern "${name}"`,
            `args.blockedPatterns:${name}`
          );
        }
      }
    }
  }

  return { decision: 'allow', reason: null, rule: null };
}
