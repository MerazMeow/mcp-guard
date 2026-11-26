# Contributing to mcp-guard

Thanks for helping improve `mcp-guard`! Because `mcp-guard` is a security-focused tool, keeping it **zero-dependency** and well-tested is a core priority.

## Local Setup

Requires Node.js >= 20:

```bash
git clone https://github.com/MerazMeow/mcp-guard.git
cd mcp-guard
npm test
```

## Guidelines

1. **Zero runtime dependencies**: Please do not add packages to `dependencies` in `package.json`. Use Node.js built-in modules (`node:fs`, `node:path`, `node:http`, `node:test`, etc.).
2. **Test coverage**: Add unit or E2E tests in `test/` for any new policy rule, redactor detector, or CLI flag.
3. **Avoid false-positive secret detectors**: New built-in detectors in `src/redactor.js` should have clear prefixes or high-specificity patterns so normal code/text isn't corrupted.
4. **Never log unredacted secrets**: Any new audit fields must pass through redaction before hitting disk.
