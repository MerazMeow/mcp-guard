#!/usr/bin/env node
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { runCli } from '../src/cli.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const pkgPath = path.resolve(__dirname, '../package.json');
const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));

const exitCode = await runCli(process.argv.slice(2), {
  packageVersion: pkg.version,
});
process.exit(exitCode);
