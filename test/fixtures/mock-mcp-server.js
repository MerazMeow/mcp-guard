import readline from 'node:readline';

const rl = readline.createInterface({
  input: process.stdin,
  crlfDelay: Infinity,
});

function send(msg) {
  process.stdout.write(`${JSON.stringify(msg)}\n`);
}

rl.on('line', (line) => {
  const trimmed = line.trim();
  if (!trimmed) return;
  const req = JSON.parse(trimmed);

  if (req.method === 'initialize') {
    send({
      jsonrpc: '2.0',
      id: req.id,
      result: {
        protocolVersion: '2025-03-26',
        serverInfo: { name: 'mock-mcp', version: '1.0.0' },
        capabilities: { tools: {}, resources: {} },
      },
    });
    return;
  }

  if (req.method === 'tools/list') {
    send({
      jsonrpc: '2.0',
      id: req.id,
      result: {
        tools: [
          { name: 'read_file', description: 'Read a file' },
          { name: 'delete_file', description: 'Delete a file' },
          { name: 'run_shell', description: 'Execute a shell command' },
        ],
      },
    });
    return;
  }

  if (req.method === 'tools/call') {
    const { name, arguments: args = {} } = req.params ?? {};

    if (name === 'read_file') {
      send({
        jsonrpc: '2.0',
        id: req.id,
        result: {
          content: [
            {
              type: 'text',
              text: `File ${args.path}: token=${['ghp', '1234567890abcdefghij1234567890abcd'].join('_')}`,
            },
          ],
        },
      });
      return;
    }

    if (name === 'delete_file' || name === 'run_shell') {
      send({
        jsonrpc: '2.0',
        id: req.id,
        result: {
          content: [{ type: 'text', text: `Executed ${name}` }],
        },
      });
      return;
    }
  }

  if (req.method === 'resources/read') {
    send({
      jsonrpc: '2.0',
      id: req.id,
      result: {
        contents: [
          {
            uri: req.params?.uri,
            text: 'postgres://admin:SuperSecretPass99@db.example.com:5432/app',
          },
        ],
      },
    });
    return;
  }

  if (req.id !== undefined) {
    send({
      jsonrpc: '2.0',
      id: req.id,
      error: { code: -32601, message: `Method not found: ${req.method}` },
    });
  }
});
