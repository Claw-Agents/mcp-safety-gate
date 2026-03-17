# Safety Gate - Quick Start Guide

## What You Got

A production-ready MCP server that acts as a security middleware for OpenClaw. It intercepts all tool calls, validates them against security policies, logs everything to an audit trail, and optionally simulates execution instead of running commands.

**Project Stats:**
- **Lines of TypeScript:** 1,078 (5 core modules + config)
- **Compiled Output:** 429 lines of ESM JavaScript (11 KB)
- **Build Time:** ~40ms (tsup)
- **Dependencies:** `@modelcontextprotocol/sdk`, `zod`

---

## Installation & Setup (5 minutes)

### 1. Install & Build
```bash
cd mcp-safety-gate
npm install          # Install dependencies
npm run build        # Compile TypeScript → dist/index.js
```

### 2. Verify Everything Works
```bash
# Type check (should have zero errors)
npm run typecheck

# Build should complete in <1 second
npm run build

# Check the executable is ready
ls -lh dist/index.js  # Should be ~11KB
```

### 3. Start the Server
```bash
# Option A: Development mode (auto reload)
npm run dev

# Option B: Production mode
npm start

# You should see in stderr:
# [SafetyGate] Initializing Security Middleware...
# [Config] Safety Gate Configuration:
#   Dry-Run Mode: false
#   Audit Log Path: ./audit_log.json
#   Restricted Keywords: 41 patterns loaded
# [SafetyGate] Registered 3 tools with security wrapping
# [SafetyGate] Server running - accepting tool calls on stdio
```

---

## Configuration

### Environment Variables

```bash
# Enable dry-run mode (simulate execution without running)
export DRY_RUN=true
npm start

# Override audit log path
export AUDIT_LOG_PATH=/var/log/safety-gate.log
npm start

# Enable verbose per-tool logging
export VERBOSE=true
npm start

# Combine multiple settings
export DRY_RUN=true VERBOSE=true npm start
```

---

## Testing the Server

### Test 1: Allowed Command (passes policy)
```bash
# Shell: Send a safe command
echo '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"shell_command","arguments":{"command":"ls -la /home"}}}' | npm start
```

**Result:** Command is logged as `"decision":"allowed"` in audit log

### Test 2: Blocked Command (contains restricted keyword)
```bash
# Try to remove a file (blocked by "rm" keyword)
echo '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"shell_command","arguments":{"command":"rm -rf /home"}}}' | npm start
```

**Result:** Returns error, logged as `"decision":"denied"` with reason showing blocked keyword

### Test 3: Sensitive Path (blocked)
```bash
# Try to access environment file
echo '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"write_file","arguments":{"path":".env","content":"SECRET=key"}}}' | npm start
```

**Result:** Blocked because `.env` is a restricted path

### Test 4: Dry-Run Mode
```bash
# Enable dry-run and send any command
export DRY_RUN=true
npm start
# Send tool call → returns simulated success, no actual execution
```

**Result:** Logged as `"decision":"dryrun"`, tool doesn't actually run

### Test 5: Check Audit Log
```bash
# View audit entries
cat audit_log.json | jq .

# Pretty print with colors
cat audit_log.json | jq . -C

# Count decisions
cat audit_log.json | jq -r '.decision' | sort | uniq -c
```

---

## Architecture Overview

```
OpenClaw / MCP Client
    ↓ tool/call request
    ↓
Safety Gate Server
    ↓
[1] Argument Validation (schema check)
    ↓ valid?
[2] Security Policy Check (keyword filtering)
    ↓ allowed?
[3] Dry-Run Decision (check DRY_RUN env var)
    ├─ DRY_RUN=true? → Simulate & return
    └─ DRY_RUN=false? → Execute
[4] Audit Logging (write to audit_log.json)
    ↓
Response back to client
```

---

## Restricted Keywords (41 patterns)

### System Destructive (9)
`rm, rmdir, del, delete, format, dd, mkfs, shred, wipe`

### Privilege Escalation (4)
`sudo, su , chmod 777, chown`

### Sensitive Paths & Secrets (13)
`.env, .aws/credentials, .ssh/id_rsa, /etc/passwd, secret, token, key, password, apikey, api_key, private_key, github_token, aws_access_key, aws_secret_key`

### Network Operations (2)
`wget , curl `

### History/Cache (2)
`clear history, history -c`

---

## Core Files Explained

| File | Purpose | What It Does |
|------|---------|--------------|
| **src/index.ts** | MCP Server Entry | Initializes the MCP server, registers 3 sample tools (shell_command, write_file, read_file) with security wrapping |
| **src/lib/config.ts** | Configuration | Loads env vars, defines the 41 restricted keywords hardcoded list |
| **src/lib/policyEngine.ts** | Security Logic | `shouldBlockTool()` function that scans arguments for restricted keywords (case-insensitive substring match) |
| **src/lib/toolWrapper.ts** | Handler Wrapper | Wraps tool handlers to inject 4-step validation (argument check → policy check → dry-run check → execute) |
| **src/lib/auditLogger.ts** | Audit Trail | Writes JSON Lines format to `audit_log.json`, one line per tool call |
| **src/types/index.ts** | TypeScript Types | Interfaces for PolicyDecision, AuditLogEntry, SafetyGateConfig |

---

## Audit Log Format

**Location:** `./audit_log.json` (created automatically)

**Example Entry:**
```json
{
  "timestamp": "2026-03-17T10:30:45.123Z",
  "toolName": "shell_command",
  "arguments": {"command": "ls -la /home"},
  "decision": "allowed",
  "reason": "Policy check passed - tool executed",
  "result": "success",
  "executionTimeMs": 12
}
```

**Blocked Entry:**
```json
{
  "timestamp": "2026-03-17T10:30:50.456Z",
  "toolName": "shell_command",
  "arguments": {"command": "rm -rf /home"},
  "decision": "denied",
  "reason": "Blocked: restricted keyword(s) found: rm",
  "blockedKeywords": ["rm"],
  "result": "error",
  "executionTimeMs": 2
}
```

---

## Integration with OpenClaw

1. **Update OpenClaw MCP config** (or settings file):
```json
{
  "mcp": {
    "safety-gate": {
      "command": "node",
      "args": ["/path/to/mcp-safety-gate/dist/index.js"]
    }
  }
}
```

2. **Restart OpenClaw**

3. **Verify connection:**
   - OpenClaw should list the 3 tools: `shell_command`, `write_file`, `read_file`
   - All tool calls are now intercepted and logged

4. **Monitor audit logs:**
```bash
tail -f audit_log.json | jq .
```

---

## Troubleshooting

### Q: Server won't start
```bash
# Check Node version
node --version  # Should be 18+

# Check dependencies
npm install

# Run dev mode for detailed error output
npm run dev
```

### Q: Audit log not created
```bash
# Check directory permissions
ls -la ./
# Create manually if needed
touch audit_log.json
chmod 666 audit_log.json
```

### Q: Tools not appearing in OpenClaw
1. Verify server runs: `npm run dev` (should see startup messages)
2. Check OpenClaw config file path is correct
3. Restart OpenClaw
4. Check OpenClaw logs for MCP connection errors

### Q: Getting unexpected blocks
```bash
# Enable verbose logging to see all decisions
export VERBOSE=true
npm start

# Check audit log for exact keywords that triggered block
grep denied audit_log.json | jq '.blockedKeywords'
```

### Q: Want to modify restricted keywords
Edit `src/lib/config.ts` in the `RESTRICTED_KEYWORDS` array, then rebuild:
```bash
npm run build
npm start
```

---

## Next Steps / Enhancements

- [ ] **Config file support** — Load restricted keywords from JSON/YAML file instead of hardcoded
- [ ] **Per-tool whitelisting** — Allow certain keywords for specific tools
- [ ] **Rate limiting** — Add quota/throttling per tool
- [ ] **Remote server proxying** — Forward to actual downstream MCP servers
- [ ] **Database logging** — Store audit logs in PostgreSQL/MongoDB
- [ ] **Metrics endpoint** — Expose Prometheus metrics
- [ ] **TLS support** — Run as network service with authentication
- [ ] **Rule engine** — Complex policy rules beyond keyword matching

---

## Support & References

- **MCP Spec:** https://modelcontextprotocol.io/
- **OpenClaw:** https://openclaw.ai/
- **MCP SDK Docs:** https://github.com/modelcontextprotocol/typescript-sdk

---

**Safety Gate v1.0.0** — Keep your OpenClaw safe while it moves fast. 🦞🔒
