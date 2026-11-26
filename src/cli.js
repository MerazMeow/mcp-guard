import fs from 'node:fs';
import path from 'node:path';
import { readAuditLogs, summarizeAuditLogs } from './audit.js';
import { getPresetPolicy, loadPolicy, validatePolicy } from './policy.js';
import { startStdioProxy } from './proxy.js';
import { createUiServer } from './ui.js';

export const HELP_TEXT = `mcp-guard — Local security firewall, secret redactor & audit inspector for MCP servers

Usage:
  mcp-guard proxy [options] -- <server-command> [args...]
  mcp-guard init  [--preset standard|strict|readonly] [--out mcp-guard.json] [--force]
  mcp-guard check [--policy mcp-guard.json]
  mcp-guard logs  [--file .mcp-guard/audit.jsonl] [--tail 25] [--denied-only] [--tool <name>] [--json]
  mcp-guard wrap  [--name <server-name>] [--policy mcp-guard.json] -- <server-command> [args...]
  mcp-guard ui    [--file .mcp-guard/audit.jsonl] [--policy mcp-guard.json] [--port 4317]

Options:
  --policy <path>       Path to policy JSON file (defaults to ./mcp-guard.json if present)
  --mode <mode>         Override policy mode: enforce | audit
  --audit-file <path>   Override audit JSONL output path
  --no-audit            Disable audit logging for this run
  -h, --help            Show help
  -v, --version         Show version
`;

function splitCommandArgs(argv) {
  const dashIndex = argv.indexOf('--');
  if (dashIndex === -1) {
    return { guardArgs: argv, upstreamArgs: [] };
  }
  return {
    guardArgs: argv.slice(0, dashIndex),
    upstreamArgs: argv.slice(dashIndex + 1),
  };
}

function parseFlags(args) {
  const flags = {};
  const positional = [];

  for (let i = 0; i < args.length; i += 1) {
    const token = args[i];
    if (token === '-h' || token === '--help') {
      flags.help = true;
    } else if (token === '-v' || token === '--version') {
      flags.version = true;
    } else if (token === '--force') {
      flags.force = true;
    } else if (token === '--no-audit') {
      flags.noAudit = true;
    } else if (token === '--denied-only') {
      flags.deniedOnly = true;
    } else if (token === '--json') {
      flags.json = true;
    } else if (token.startsWith('--')) {
      const eqIdx = token.indexOf('=');
      if (eqIdx !== -1) {
        flags[token.slice(2, eqIdx)] = token.slice(eqIdx + 1);
      } else {
        const key = token.slice(2);
        const next = args[i + 1];
        if (next !== undefined && !next.startsWith('-')) {
          flags[key] = next;
          i += 1;
        } else {
          flags[key] = true;
        }
      }
    } else {
      positional.push(token);
    }
  }

  return { flags, positional };
}

export function formatWrapConfig({ name = 'guarded-server', policyPath, upstreamArgs }) {
  const proxyArgs = ['-y', '@merazmeow/mcp-guard', 'proxy'];
  if (policyPath) {
    proxyArgs.push('--policy', policyPath);
  }
  proxyArgs.push('--', ...upstreamArgs);

  return {
    mcpServers: {
      [name]: {
        command: 'npx',
        args: proxyArgs,
      },
    },
  };
}

export async function runCli(
  argv,
  {
    cwd = process.cwd(),
    stdout = process.stdout,
    stderr = process.stderr,
    packageVersion = '0.1.0',
  } = {}
) {
  const { guardArgs, upstreamArgs } = splitCommandArgs(argv);
  const { flags, positional } = parseFlags(guardArgs);

  if (flags.version) {
    stdout.write(`${packageVersion}\n`);
    return 0;
  }

  if (flags.help || (positional.length === 0 && upstreamArgs.length === 0)) {
    stdout.write(HELP_TEXT);
    return 0;
  }

  // Shorthand: `mcp-guard -- <cmd> ...` implies `proxy`
  const subcommand = positional[0] ?? (upstreamArgs.length > 0 ? 'proxy' : '');

  if (subcommand === 'init') {
    const preset = flags.preset ?? 'standard';
    const outPath = path.resolve(cwd, flags.out ?? 'mcp-guard.json');
    if (fs.existsSync(outPath) && !flags.force) {
      stderr.write(`Error: ${outPath} already exists. Use --force to overwrite.\n`);
      return 1;
    }
    const policy = getPresetPolicy(preset);
    fs.mkdirSync(path.dirname(outPath), { recursive: true });
    fs.writeFileSync(outPath, `${JSON.stringify(policy, null, 2)}\n`, 'utf8');
    stdout.write(`Created ${outPath} (preset: ${preset})\n`);
    return 0;
  }

  if (subcommand === 'check') {
    const targetPath = path.resolve(cwd, flags.policy ?? 'mcp-guard.json');
    if (!fs.existsSync(targetPath)) {
      stderr.write(`Error: Policy file not found at ${targetPath}\n`);
      return 1;
    }
    let raw;
    try {
      raw = JSON.parse(fs.readFileSync(targetPath, 'utf8'));
    } catch (err) {
      stderr.write(`Error: Invalid JSON in ${targetPath}: ${err.message}\n`);
      return 1;
    }
    const result = validatePolicy(raw);
    for (const w of result.warnings) {
      stdout.write(`Warning: ${w}\n`);
    }
    for (const e of result.errors) {
      stderr.write(`Error: ${e}\n`);
    }
    if (!result.valid) {
      return 1;
    }
    stdout.write(`Policy OK: ${targetPath}\n`);
    return 0;
  }

  if (subcommand === 'logs') {
    const { policy } = loadPolicy(flags.policy, cwd);
    const file = flags.file ?? policy.audit.file;
    const tail = flags.tail ? Number(flags.tail) : 25;
    const records = readAuditLogs(file, {
      cwd,
      tail,
      deniedOnly: Boolean(flags.deniedOnly),
      tool: typeof flags.tool === 'string' ? flags.tool : undefined,
    });
    const summary = summarizeAuditLogs(records);

    if (flags.json) {
      stdout.write(`${JSON.stringify({ summary, records }, null, 2)}\n`);
      return 0;
    }

    stdout.write(
      `Audit Summary: total=${summary.total} allowed=${summary.allowed} denied=${summary.denied} would_block=${summary.wouldBlock} secrets_redacted=${summary.totalSecretsRedacted} avg_latency=${summary.avgLatencyMs}ms\n`
    );

    if (records.length === 0) {
      stdout.write('No matching audit records.\n');
      return 0;
    }

    for (const r of records) {
      const redText =
        Array.isArray(r.redactions) && r.redactions.length > 0
          ? ` redacted=[${r.redactions.map((x) => `${x.type}:${x.count}`).join(',')}]`
          : '';
      const reasonText = r.reason ? ` (${r.reason})` : '';
      const durText = typeof r.durationMs === 'number' ? ` ${r.durationMs}ms` : '';
      stdout.write(
        `${r.timestamp} [${r.decision}] ${r.tool || r.method}${durText}${redText}${reasonText}\n`
      );
    }
    return 0;
  }

  if (subcommand === 'wrap') {
    if (upstreamArgs.length === 0) {
      stderr.write('Error: Provide an upstream command after "--", e.g. mcp-guard wrap -- npx server\n');
      return 1;
    }
    const config = formatWrapConfig({
      name: typeof flags.name === 'string' ? flags.name : 'guarded-server',
      policyPath: typeof flags.policy === 'string' ? flags.policy : undefined,
      upstreamArgs,
    });
    stdout.write(`${JSON.stringify(config, null, 2)}\n`);
    return 0;
  }

  if (subcommand === 'ui') {
    const port = flags.port ? Number(flags.port) : 4317;
    const server = createUiServer({
      auditFile: typeof flags.file === 'string' ? flags.file : undefined,
      policyPath: typeof flags.policy === 'string' ? flags.policy : undefined,
      cwd,
    });

    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(port, '127.0.0.1', resolve);
    });

    const addr = server.address();
    const actualPort = typeof addr === 'object' && addr ? addr.port : port;
    stdout.write(`mcp-guard inspector listening on http://127.0.0.1:${actualPort}\n`);

    await new Promise((resolve) => {
      const stop = () => server.close(() => resolve());
      process.once('SIGINT', stop);
      process.once('SIGTERM', stop);
    });
    return 0;
  }

  if (subcommand === 'proxy') {
    if (upstreamArgs.length === 0) {
      stderr.write('Error: Missing upstream MCP command. Example: mcp-guard proxy -- npx my-mcp-server\n');
      return 1;
    }

    const { policy } = loadPolicy(flags.policy, cwd);
    if (flags.mode === 'enforce' || flags.mode === 'audit') {
      policy.mode = flags.mode;
    } else if (flags.mode !== undefined) {
      stderr.write(`Error: Invalid --mode "${flags.mode}". Expected "enforce" or "audit".\n`);
      return 1;
    }

    if (typeof flags['audit-file'] === 'string') {
      policy.audit.file = flags['audit-file'];
    }
    if (flags.noAudit) {
      policy.audit.enabled = false;
    }

    const [command, ...cmdArgs] = upstreamArgs;
    const { child } = startStdioProxy({
      command,
      args: cmdArgs,
      policy,
      cwd,
    });

    const exitCode = await new Promise((resolve) => {
      child.on('error', (err) => {
        stderr.write(`[mcp-guard] Failed to start upstream "${command}": ${err.message}\n`);
        resolve(1);
      });
      child.on('exit', (code, signal) => {
        if (signal) resolve(1);
        else resolve(code ?? 0);
      });
    });

    return exitCode;
  }

  stderr.write(`Unknown command "${subcommand}". Run "mcp-guard --help" for usage.\n`);
  return 1;
}
