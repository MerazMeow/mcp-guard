import { spawn } from 'node:child_process';
import crypto from 'node:crypto';
import { AuditLogger } from './audit.js';
import { createRateLimiter, evaluateToolCall, isToolVisible, normalizePolicy } from './policy.js';
import { redactPayload } from './redactor.js';

function makeIdKey(id) {
  return `${typeof id}:${String(id)}`;
}

function mergeRedactions(a = [], b = []) {
  const map = new Map();
  for (const item of [...a, ...b]) {
    map.set(item.type, (map.get(item.type) ?? 0) + item.count);
  }
  return Array.from(map.entries()).map(([type, count]) => ({ type, count }));
}

/**
 * Creates a stateful MCP Guard inspection session over JSON-RPC 2.0 messages.
 * Decoupled from stdio streams so it can be unit-tested or embedded directly.
 */
export function createGuardSession(options = {}) {
  const policy = normalizePolicy(options.policy);
  const cwd = options.cwd ?? process.cwd();
  const sessionId = options.sessionId ?? crypto.randomUUID().slice(0, 8);
  const rateLimiter = createRateLimiter(policy.rateLimit.maxCallsPerMinute);
  const auditLogger =
    options.auditLogger ??
    new AuditLogger({
      enabled: policy.audit.enabled,
      file: policy.audit.file,
      cwd,
      logArguments: policy.audit.logArguments,
      redaction: policy.redaction,
    });

  const pendingRequests = new Map();

  function handleClientMessage(msg) {
    if (!msg || typeof msg !== 'object') {
      return { forward: msg, replyToClient: null };
    }

    const hasId = msg.id !== undefined && msg.id !== null;

    if (msg.method === 'tools/call') {
      const toolName = msg.params?.name ?? '';
      const rawArgs = msg.params?.arguments ?? {};
      const evaluation = evaluateToolCall(policy, {
        toolName,
        args: rawArgs,
        cwd,
        rateLimiter,
      });

      if (evaluation.decision === 'deny') {
        auditLogger.log({
          sessionId,
          method: 'tools/call',
          tool: toolName,
          decision: 'deny',
          reason: evaluation.reason,
          rule: evaluation.rule,
          redactions: [],
          durationMs: 0,
          rawArgs,
        });

        const replyToClient = hasId
          ? {
              jsonrpc: '2.0',
              id: msg.id,
              error: {
                code: -32001,
                message: `[mcp-guard] Policy denied tool "${toolName}": ${evaluation.reason}`,
                data: {
                  rule: evaluation.rule,
                  tool: toolName,
                },
              },
            }
          : null;

        return { forward: null, replyToClient };
      }

      let forwardedMsg = msg;
      let requestRedactions = [];

      if (policy.redaction.enabled && policy.redaction.redactRequests && msg.params?.arguments) {
        const redacted = redactPayload(msg.params.arguments, policy.redaction);
        requestRedactions = redacted.redactions;
        forwardedMsg = {
          ...msg,
          params: {
            ...msg.params,
            arguments: redacted.value,
          },
        };
      }

      if (hasId) {
        pendingRequests.set(makeIdKey(msg.id), {
          method: 'tools/call',
          tool: toolName,
          decision: evaluation.decision,
          reason: evaluation.reason,
          rule: evaluation.rule,
          requestRedactions,
          rawArgs,
          startedAt: Date.now(),
        });
      } else {
        auditLogger.log({
          sessionId,
          method: 'tools/call',
          tool: toolName,
          decision: evaluation.decision,
          reason: evaluation.reason,
          rule: evaluation.rule,
          redactions: requestRedactions,
          durationMs: 0,
          rawArgs,
        });
      }

      return { forward: forwardedMsg, replyToClient: null };
    }

    if (hasId && (msg.method === 'tools/list' || msg.method === 'resources/read')) {
      pendingRequests.set(makeIdKey(msg.id), {
        method: msg.method,
        tool: msg.method === 'resources/read' ? (msg.params?.uri ?? 'resource') : undefined,
        decision: 'allow',
        reason: null,
        rule: null,
        requestRedactions: [],
        rawArgs: msg.method === 'resources/read' ? msg.params : undefined,
        startedAt: Date.now(),
      });
    }

    return { forward: msg, replyToClient: null };
  }

  function handleUpstreamMessage(msg) {
    if (!msg || typeof msg !== 'object') {
      return msg;
    }

    const hasId = msg.id !== undefined && msg.id !== null;
    if (!hasId) {
      return msg;
    }

    const key = makeIdKey(msg.id);
    const pending = pendingRequests.get(key);
    if (!pending) {
      return msg;
    }
    pendingRequests.delete(key);

    const durationMs = Date.now() - pending.startedAt;

    if (
      pending.method === 'tools/list' &&
      policy.mode !== 'audit' &&
      Array.isArray(msg.result?.tools)
    ) {
      const filteredTools = msg.result.tools.filter((tool) => isToolVisible(policy, tool.name));
      return {
        ...msg,
        result: {
          ...msg.result,
          tools: filteredTools,
        },
      };
    }

    if (pending.method === 'tools/call' || pending.method === 'resources/read') {
      let outputMsg = msg;
      let responseRedactions = [];

      if (
        policy.redaction.enabled &&
        policy.redaction.redactResponses &&
        msg.result !== undefined
      ) {
        const redacted = redactPayload(msg.result, policy.redaction);
        responseRedactions = redacted.redactions;
        outputMsg = {
          ...msg,
          result: redacted.value,
        };
      }

      const redactions = mergeRedactions(pending.requestRedactions, responseRedactions);

      auditLogger.log({
        sessionId,
        method: pending.method,
        tool: pending.tool,
        decision: pending.decision,
        reason: pending.reason,
        rule: pending.rule,
        redactions,
        durationMs,
        isError: Boolean(msg.error || msg.result?.isError),
        rawArgs: pending.rawArgs,
      });

      return outputMsg;
    }

    return msg;
  }

  return {
    sessionId,
    policy,
    handleClientMessage,
    handleUpstreamMessage,
  };
}

/**
 * Helper that reads newline-delimited JSON messages from a readable stream.
 */
export function attachLineJsonReader(stream, onMessage, onInvalidLine) {
  let buffer = '';

  stream.setEncoding('utf8');
  stream.on('data', (chunk) => {
    buffer += chunk;
    let newlineIndex;
    while ((newlineIndex = buffer.indexOf('\n')) !== -1) {
      const rawLine = buffer.slice(0, newlineIndex).replace(/\r$/, '');
      buffer = buffer.slice(newlineIndex + 1);
      const trimmed = rawLine.trim();
      if (!trimmed) continue;
      try {
        onMessage(JSON.parse(trimmed));
      } catch (err) {
        if (onInvalidLine) onInvalidLine(rawLine, err);
      }
    }
  });

  stream.on('end', () => {
    const trimmed = buffer.trim();
    if (!trimmed) return;
    try {
      onMessage(JSON.parse(trimmed));
    } catch (err) {
      if (onInvalidLine) onInvalidLine(buffer, err);
    }
    buffer = '';
  });
}

function writeJsonLine(stream, payload) {
  if (!stream.writableEnded && !stream.destroyed) {
    stream.write(`${JSON.stringify(payload)}\n`);
  }
}

/**
 * Spawns an upstream MCP server over stdio and proxies JSON-RPC messages through mcp-guard.
 */
export function startStdioProxy({
  command,
  args = [],
  policy,
  cwd = process.cwd(),
  stdin = process.stdin,
  stdout = process.stdout,
  stderr = process.stderr,
  env = process.env,
}) {
  const session = createGuardSession({ policy, cwd });

  const child = spawn(command, args, {
    cwd,
    env,
    stdio: ['pipe', 'pipe', 'pipe'],
  });

  child.stderr.on('data', (chunk) => {
    stderr.write(chunk);
  });

  attachLineJsonReader(
    stdin,
    (msg) => {
      const { forward, replyToClient } = session.handleClientMessage(msg);
      if (replyToClient) {
        writeJsonLine(stdout, replyToClient);
      }
      if (forward) {
        writeJsonLine(child.stdin, forward);
      }
    },
    (rawLine) => {
      if (!child.stdin.writableEnded && !child.stdin.destroyed) {
        child.stdin.write(`${rawLine}\n`);
      }
    }
  );

  attachLineJsonReader(
    child.stdout,
    (msg) => {
      const processed = session.handleUpstreamMessage(msg);
      if (processed) {
        writeJsonLine(stdout, processed);
      }
    },
    (rawLine) => {
      if (!stdout.writableEnded && !stdout.destroyed) {
        stdout.write(`${rawLine}\n`);
      }
    }
  );

  stdin.on('end', () => {
    if (!child.stdin.writableEnded) {
      child.stdin.end();
    }
  });

  const forwardSignal = (signal) => {
    if (!child.killed) {
      child.kill(signal);
    }
  };

  process.once('SIGINT', () => forwardSignal('SIGINT'));
  process.once('SIGTERM', () => forwardSignal('SIGTERM'));

  return { child, session };
}
