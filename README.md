# Safety Gate - MCP Security Middleware

A TypeScript-based Model Context Protocol (MCP) server that acts as a security middleware for OpenClaw. It intercepts tool execution requests, applies security policies, and maintains audit logs.

## Features

- **🔒 Instruction Filtering**: Validates tool arguments against a list of restricted keywords (e.g., `rm`, `sudo`, `.env`, etc.)
- **🏃 Dry-Run Mode**: Optional simulation mode that logs intended actions without executing them
- **📝 Audit Logging**: Automatically logs all intercepted tool calls to a local JSON Lines file with timestamps and metadata
- **📋 MCP Compliant**: Follows the official Model Context Protocol specification using `@modelcontextprotocol/sdk`

## Installation

### Prerequisites
- **Node.js** 18.0.0 or later
- **npm** 9.0.0 or later

### Setup

```bash
# Clone or navigate to the project directory
cd mcp-safety-gate

# Install dependencies
npm install

# Build the TypeScript source
npm run build

# Verify the build
ls -la dist/
```

## Configuration

Configuration is managed via environment variables:

### Environment Variables

| Variable | Description | Default | Example |
|----------|-------------|---------|---------|
| `DRY_RUN` | Enable simulation mode (no actual execution) | `false` | `DRY_RUN=true` |
| `AUDIT_LOG_PATH` | Path to the audit log file | `./audit_log.json` | `AUDIT_LOG_PATH=/var/log/safety-gate.log` |
| `VERBOSE` | Enable verbose logging to console | `false` | `VERBOSE=true` |

### Example: Starting in Dry-Run Mode

```bash
export DRY_RUN=true
npm start
```

## Running the Server

### Development Mode (with hot reload)

```bash
npm run dev
```

### Production Mode

```bash
npm run build
npm start
```

The server will start on **stdio** (standard input/output) and accept MCP tool calls.

## Restricicted Keywords

The server blocks tool calls containing these patterns (case-insensitive substring matching):

### System Destructive Operations
- `rm`, `rmdir`, `del`, `delete`, `format`, `dd`, `mkfs`, `shred`, `wipe`

### Privilege Escalation
- `sudo`, `su `, `chmod 777`, `chown`

### Sensitive Paths & Secrets
- `.env`, `.aws/credentials`, `.ssh/id_rsa`, `/etc/passwd`
- `secret`, `token`, `key`, `password`, `apikey`, `api_key`, `private_key`
- `github_token`, `aws_access_key`, `aws_secret_key`

### Network Operations
- `wget `, `curl ` (for downloads to sensitive paths)

### History & Cache Clearing
- `clear history`, `history -c`

## Tools

The server provides three intercepted tools:

### 1. `shell_command`

Execute a shell command with security checks.

**Input:**
```json
{
  "command": "ls -la /home"
}
```

**Response (Allowed):**
```json
{
  "content": [{"type": "text", "text": "[MOCK] Shell command executed: ls -la /home\n..."}],
  "isError": false
}
```

**Response (Blocked):**
```json
{
  "content": [{"type": "text", "text": "Security Policy Violation: Blocked: restricted keyword(s) found: rm"}],
  "isError": true
}
```

### 2. `write_file`

Write content to a file with security checks.

**Input:**
```json
{
  "path": "/home/user/document.txt",
  "content": "Hello, World!"
}
```

### 3. `read_file`

Read content from a file (generally allowed by default).

**Input:**
```json
{
  "path": "/home/user/document.txt"
}
```

## Audit Logging

All tool calls are logged to `./audit_log.json` in **JSON Lines** format (one JSON object per line).

### Audit Log Entry Format

```json
{
  "timestamp": "2026-03-17T10:30:45.123Z",
  "toolName": "shell_command",
  "arguments": {"command": "ls -la"},
  "decision": "allowed",
  "reason": "Policy check passed - tool executed",
  "result": "success",
  "executionTimeMs": 42
}
```

### Log Entry Fields

| Field | Description | Values |
|-------|-------------|--------|
| `timestamp` | ISO 8601 timestamp of the call | e.g., `"2026-03-17T10:30:45.123Z"` |
| `toolName` | Name of the intercepted tool | `"shell_command"`, `"write_file"`, `"read_file"` |
| `arguments` | Raw arguments passed to the tool | JSON object |
| `decision` | Security decision | `"allowed"`, `"denied"`, `"dryrun"` |
| `reason` | Human-readable explanation | e.g., `"Policy check passed"` |
| `blockedKeywords` | Keywords that triggered the block (if denied) | Array of strings |
| `result` | Execution result | `"success"`, `"error"`, `"pending"` |
| `executionTimeMs` | Execution time in milliseconds | number |

### Reading the Audit Log

**View recent entries:**
```bash
tail -f audit_log.json
```

**Parse and pretty-print:**
```bash
cat audit_log.json | jq .
```

**Count decisions:**
```bash
cat audit_log.json | jq -r '.decision' | sort | uniq -c
```

## Dry-Run Mode

When `DRY_RUN=true`, the server simulates tool execution without actually running commands.

### Example: Dry-Run Session

```bash
export DRY_RUN=true
npm start
```

**Tool Call:**
```json
{"tool": "shell_command", "arguments": {"command": "rm -rf /home"}}
```

**Response:**
```json
{
  "content": [
    {"type": "text", "text": "**DRY-RUN** Blocked - 'rm' keyword found in arguments"}
  ],
  "isError": true
}
```

Note: Blocked calls are still blocked in Dry-Run mode. Allowed calls return simulated success:

```json
{"tool": "shell_command", "arguments": {"command": "ls -la"}}
```

**Response:**
```json
{
  "content": [
    {"type": "text", "text": "Dry-Run: Tool 'shell_command' would execute with provided arguments (not actually run)"}
  ],
  "isError": false
}
```

## Integration with OpenClaw

To use Safety Gate with OpenClaw:

1. **Build the server:**
   ```bash
   npm run build
   ```

2. **Add to OpenClaw MCP servers** (in OpenClaw config):
   ```json
   {
     "name": "Safety Gate",
     "command": "node",
     "args": ["/path/to/dist/index.js"]
   }
   ```

3. **Verify connection:** Check OpenClaw logs for successful registration

4. **View audit logs:** Monitor `./audit_log.json` for activity

## Development

### Build Typescript

```bash
npm run build
```

### Type Check

```bash
npm run typecheck
```

### Development Watch Mode

```bash
npm run dev
```

## Project Structure

```
mcp-safety-gate/
├── src/
│   ├── index.ts                   # MCP server entry point
│   ├── lib/
│   │   ├── config.ts              # Configuration management
│   │   ├── policyEngine.ts        # Security policy logic
│   │   ├── auditLogger.ts         # Audit logging
│   │   └── toolWrapper.ts         # Handler wrapping factory
│   └── types/
│       └── index.ts               # TypeScript interfaces
├── dist/                          # Compiled JavaScript (generated)
├── package.json
├── tsconfig.json
├── README.md
└── audit_log.json                 # Audit logs (created at runtime)
```

## Architecture

### Security Middleware Flow

```
OpenClaw Client
      ↓
  MCP Request (tool_call)
      ↓
  Safety Gate Server
      ↓
  [1] Argument Validation
      ├─ Valid? → [2]
      └─ Invalid? → Return Error
      ↓
  [2] Security Policy Check
      ├─ Keyword Match? → Log & Return Error
      ├─ Pass? → [3]
      └─ Logs: Decision, Keywords
      ↓
  [3] Dry-Run Check
      ├─ DRY_RUN=true? → Simulate & Return
      ├─ DRY_RUN=false? → [4]
      └─ Logs: "dryrun" decision
      ↓
  [4] Execute Tool
      ├─ Success? → Log & Return Result
      └─ Error? → Log & Return Error
      ↓
  Audit Log (./audit_log.json)
```

## Logging

### Console Output (stderr)

Server lifecycle logs are printed to stderr:
```
[SafetyGate] Initializing Security Middleware...
[Config] Safety Gate Configuration:
  Dry-Run Mode: false
  Audit Log Path: ./audit_log.json
  ...
[SafetyGate] Registered 3 tools with security wrapping
[SafetyGate] Server running - accepting tool calls on stdio
```

### Verbose Mode

Enable `VERBOSE=true` to see per-tool-call logging:
```bash
VERBOSE=true npm start
```

## Examples

### Example 1: Allowed Command

```bash
export DRY_RUN=false
npm start
```

Tool call: `shell_command` with `{"command": "whoami"}`

**Audit Log:**
```json
{"timestamp":"2026-03-17T10:30:45.123Z","toolName":"shell_command","arguments":{"command":"whoami"},"decision":"allowed","reason":"Policy check passed - tool executed","result":"success","executionTimeMs":12}
```

### Example 2: Blocked Command

Tool call: `shell_command` with `{"command": "rm -rf /home"}`

**Response:**
```json
{"content":[{"type":"text","text":"Security Policy Violation: Blocked: restricted keyword(s) found: rm"}],"isError":true}
```

**Audit Log:**
```json
{"timestamp":"2026-03-17T10:30:50.456Z","toolName":"shell_command","arguments":{"command":"rm -rf /home"},"decision":"denied","reason":"Blocked: restricted keyword(s) found: rm","blockedKeywords":["rm"],"result":"error","executionTimeMs":2}
```

### Example 3: Sensitive Path Protection

Tool call: `write_file` with `{"path": ".env", "content": "API_KEY=secret"}`

**Response:** Blocked (`.env` is restricted)

**Audit Log:**
```json
{"timestamp":"2026-03-17T10:31:00.789Z","toolName":"write_file","arguments":{"path":".env","content":"API_KEY=secret"},"decision":"denied","reason":"Blocked: restricted keyword(s) found: .env","blockedKeywords":[".env"],"result":"error","executionTimeMs":1}
```

## Troubleshooting

### Server won't start

```bash
# Check Node.js version
node --version  # Should be >= 18.0.0

# Check dependencies are installed
npm install

# Check for build errors
npm run typecheck
```

### Audit log not creating

```bash
# Check directory permissions
ls -la ./
touch ./audit_log.json  # Manually create
chmod 666 ./audit_log.json
```

### Tools not appearing in OpenClaw

1. Verify server starts: `npm run dev`
2. Check OpenClaw MCP server config path is correct
3. Review OpenClaw logs for connection errors
4. Restart OpenClaw after changing MCP configuration

### Unexpected blocks

1. Enable verbose logging: `VERBOSE=true npm run dev`
2. Check audit log for exact blocked keywords
3. Review tool arguments for case-insensitive matches
4. Adjust restricted keywords list if needed

## Future Enhancements

- [ ] Configurable restricted keywords via JSON config file
- [ ] Per-tool whitelisting rules
- [ ] Rate limiting & quota enforcement
- [ ] TLS/authentication for remote server mode
- [ ] Database-backed audit logging
- [ ] Metrics/monitoring endpoints
- [ ] Integration with external logging services (AWS, DataDog, etc.)

## License

MIT

## Support

For issues, questions, or contributions, please refer to the GitHub repository.

---

**Safety Gate** - *Keep your OpenClaw safe while it moves fast.*
