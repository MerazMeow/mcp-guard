import fs from 'node:fs';
import path from 'node:path';
import { redactPayload } from './redactor.js';

/**
 * Creates a compact, redacted argument preview string safe for storing in audit logs.
 */
export function sanitizePreview(args, redactionConfig, maxLength = 500) {
  if (args === undefined) return undefined;
  const { value } = redactPayload(args, { ...redactionConfig, enabled: true });
  let serialized;
  try {
    serialized = JSON.stringify(value);
  } catch {
    serialized = String(value);
  }
  if (serialized.length > maxLength) {
    return `${serialized.slice(0, maxLength)}…`;
  }
  return serialized;
}

export class AuditLogger {
  /**
   * @param {{ enabled?: boolean, file?: string, cwd?: string, logArguments?: boolean, redaction?: object }} options
   */
  constructor(options = {}) {
    this.enabled = options.enabled !== false;
    this.cwd = options.cwd ?? process.cwd();
    this.filePath = path.resolve(this.cwd, options.file ?? '.mcp-guard/audit.jsonl');
    this.logArguments = options.logArguments !== false;
    this.redaction = options.redaction ?? {};
    this._dirReady = false;
  }

  log(event) {
    if (!this.enabled) return null;

    if (!this._dirReady) {
      fs.mkdirSync(path.dirname(this.filePath), { recursive: true });
      this._dirReady = true;
    }

    const record = {
      timestamp: new Date().toISOString(),
      ...event,
    };

    if (!this.logArguments) {
      delete record.argsPreview;
    } else if (event.rawArgs !== undefined) {
      record.argsPreview = sanitizePreview(event.rawArgs, this.redaction);
    }
    delete record.rawArgs;

    fs.appendFileSync(this.filePath, `${JSON.stringify(record)}\n`, 'utf8');
    return record;
  }
}

/**
 * Reads audit records from a JSONL file with optional filtering.
 */
export function readAuditLogs(filePath, options = {}) {
  const resolved = path.resolve(options.cwd ?? process.cwd(), filePath);
  if (!fs.existsSync(resolved)) {
    return [];
  }

  const lines = fs
    .readFileSync(resolved, 'utf8')
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean);

  let records = [];
  for (const line of lines) {
    try {
      records.push(JSON.parse(line));
    } catch {
      // Skip malformed partial lines.
    }
  }

  if (options.decision) {
    records = records.filter((r) => r.decision === options.decision);
  }

  if (options.deniedOnly) {
    records = records.filter((r) => r.decision === 'deny' || r.decision === 'would_block');
  }

  if (options.tool) {
    records = records.filter((r) => r.tool === options.tool);
  }

  if (options.tail && options.tail > 0) {
    records = records.slice(-options.tail);
  }

  return records;
}

/**
 * Computes summary metrics over audit records for CLI and UI dashboards.
 */
export function summarizeAuditLogs(records) {
  let total = 0;
  let allowed = 0;
  let denied = 0;
  let wouldBlock = 0;
  let redactedEvents = 0;
  let totalSecretsRedacted = 0;
  let latencySum = 0;
  let latencyCount = 0;
  const toolCounts = new Map();

  for (const r of records) {
    total += 1;
    if (r.decision === 'allow') allowed += 1;
    else if (r.decision === 'deny') denied += 1;
    else if (r.decision === 'would_block') wouldBlock += 1;

    if (Array.isArray(r.redactions) && r.redactions.length > 0) {
      redactedEvents += 1;
      for (const red of r.redactions) {
        totalSecretsRedacted += red.count ?? 1;
      }
    }

    if (typeof r.durationMs === 'number') {
      latencySum += r.durationMs;
      latencyCount += 1;
    }

    if (r.tool) {
      toolCounts.set(r.tool, (toolCounts.get(r.tool) ?? 0) + 1);
    }
  }

  const topTools = Array.from(toolCounts.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([tool, count]) => ({ tool, count }));

  return {
    total,
    allowed,
    denied,
    wouldBlock,
    redactedEvents,
    totalSecretsRedacted,
    avgLatencyMs: latencyCount > 0 ? Math.round(latencySum / latencyCount) : 0,
    topTools,
  };
}
