# Safety Gate - MCP Security Middleware

![CI](https://github.com/obfuscAIte/mcp-safety-gate/actions/workflows/ci.yml/badge.svg)

A TypeScript-based Model Context Protocol (MCP) server that acts as a security middleware for OpenClaw. It intercepts tool execution requests, applies security policies, and maintains audit logs.

## Why this is useful

Safety Gate is for the awkward middle ground between “just let the agent run tools” and “shut everything off.” It gives you:

- safer local file and shell execution
- structured policy control
- review gates for higher-risk actions
- persisted approvals with metadata
- auditability

## Features

- **🔒 Instruction Filtering**: Validates tool arguments against a list of restricted keywords (e.g., `rm`, `sudo`, `.env`, etc.)
- **📁 Path Sandboxing**: Restricts file reads and writes to configured safe roots
- **🖥️ Safe Shell Execution**: Executes only allowlisted shell commands, rejects shell metacharacters, validates path-like arguments, and enforces per-command argument validators
- **🧭 Structured Policy Engine**: Supports per-tool allow/deny/review rules for keywords, paths, and command names
- **✋ Explicit Approval Workflow**: Review-required requests are persisted with request IDs and can be approved, rejected, listed, and executed later
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
| `ALLOWED_PATHS` | Comma-separated safe root directories for file access and path-like shell args | current working directory | `ALLOWED_PATHS=/workspace,/tmp/scratch` |
| `SHELL_ALLOWED_COMMANDS` | Comma-separated allowlist for shell execution | `pwd,ls,cat,head,tail,wc,find,grep,which,echo` | `SHELL_ALLOWED_COMMANDS=pwd,ls,cat` |
| `MAX_FILE_READ_BYTES` | Maximum bytes returned by `read_file` or shell output buffer | `1048576` | `MAX_FILE_READ_BYTES=262144` |
| `MAX_FILE_WRITE_BYTES` | Maximum bytes accepted by `write_file` | `262144` | `MAX_FILE_WRITE_BYTES=65536` |
| `SHELL_COMMAND_TIMEOUT_MS` | Timeout for allowlisted shell commands | `5000` | `SHELL_COMMAND_TIMEOUT_MS=2000` |
| `POLICY_FILE` | Optional path to a JSON policy file overriding the built-in default policy. Invalid files fail fast at startup. | built-in default policy | `POLICY_FILE=./policy/safety-gate.policy.json` |
| `APPROVAL_STORE_PATH` | JSON file used to persist approval requests | `./approval-requests.json` | `APPROVAL_STORE_PATH=./data/approval-requests.json` |
| `APPROVAL_TTL_SECONDS` | How long an approved request remains executable before expiring | `3600` | `APPROVAL_TTL_SECONDS=900` |
| `APPROVER_AUTH_MODE` | Approver identity mode: `off` or `token` | `off` | `APPROVER_AUTH_MODE=token` |
| `APPROVER_AUTH_FILE` | JSON file describing valid approvers and which env vars contain their tokens | disabled | `APPROVER_AUTH_FILE=./approvers/example.approvers.json` |

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

The server provides three intercepted tools plus approval-management tools:

### 1. `shell_command`

Execute an allowlisted shell command with security checks.

Safety Gate rejects shell metacharacters such as `&&`, `|`, `;`, redirections, command substitution, and backslashes. It also rejects commands that are not in the configured allowlist.

Even if a command is allowlisted, it still passes through the structured policy engine first. That allows you to mark some patterns as **deny** and others as **review required**.

It also now applies per-command validators. Examples:
- `cat`, `head`, `tail`, `wc` require explicit path arguments
- `grep` rejects recursive flags and requires explicit file paths
- `find` rejects `-exec`, `-delete`, `-ok`, and `-okdir`
- `echo` enforces a payload size limit

**Input:**
```json
{
  "command": "ls -la /home"
}
```

**Response (Allowed):**
```json
{
  "content": [{"type": "text", "text": "Command: ls -la ./docs\nExit: 0\nSTDOUT:\n...\nSTDERR: <empty>"}],
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

Writes are only allowed inside `ALLOWED_PATHS`, and parent directories are created automatically when needed.

**Input:**
```json
{
  "path": "/home/user/document.txt",
  "content": "Hello, World!"
}
```

### 3. `read_file`

Read content from a file with path sandboxing and size limits.

### 4. `list_approval_requests`

List approval requests tracked by Safety Gate.

### 5. `get_approval_request`

Get a more detailed view of a single approval request, including target summary, write preview (when available), and full arguments.

### 6. `approve_request`

Approve a pending request by ID. Supports optional approval metadata such as `approver` and `notes`.

### 7. `reject_request`

Reject a pending request by ID. Supports optional `approver`, `rejectionReason`, and `notes` metadata.

### 8. `execute_approved_request`

Execute a previously approved request by ID.

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

## Policy Model

Safety Gate now supports a structured policy model with three effects:

- `allow` — execution proceeds
- `deny` — execution is blocked immediately
- `review` — execution is paused, persisted as an approval request, and surfaced as requiring explicit review

Rules are evaluated in order, first match wins.

Example policy file:

```json
{
  "version": 1,
  "rules": [
    {
      "id": "deny-env-writes",
      "effect": "deny",
      "reason": "Environment file writes are denied",
      "tools": ["write_file"],
      "match": {
        "pathSubstrings": [".env"]
      }
    },
    {
      "id": "review-package-json",
      "effect": "review",
      "reason": "package.json writes require review",
      "tools": ["write_file"],
      "match": {
        "pathSubstrings": ["package.json"]
      }
    }
  ]
}
```

Supported matchers:
- `keywords` — case-insensitive substring match across string arguments
- `pathSubstrings` — case-insensitive substring match against the `path` argument
- `pathRegexes` — regex match against normalized `path`
- `pathBasenames` — basename match such as `package.json`
- `pathExtensions` — extension match such as `.pem`
- `commandNames` — command-name match for `shell_command`
- `commandArgsRegexes` — regex match against shell command arguments (excluding the command name)

Policy files are schema-validated at startup. Invalid rules fail fast instead of silently falling back to odd runtime behavior.

## Approval Workflow

When a rule returns `review`, Safety Gate now:
1. creates a persisted approval request with a unique ID
2. returns `Review Required` plus that request ID
3. waits for an operator to approve or reject it
4. stores optional approval metadata (`approver`, `notes`, `rejectionReason`)
5. can require authenticated approver identity when `APPROVER_AUTH_MODE=token`
6. expires approvals after `APPROVAL_TTL_SECONDS`
7. allows a single later execution via `execute_approved_request`

Typical flow:

1. tool call hits a `review` rule
2. `list_approval_requests` shows the pending request
3. `approve_request` or `reject_request` resolves it
4. `execute_approved_request` runs the approved action

## Approver Identity / Auth Model

Safety Gate now supports an optional token-based approver identity model.

### Mode

- `APPROVER_AUTH_MODE=off` — approval metadata is accepted but not authenticated
- `APPROVER_AUTH_MODE=token` — approval and execution actions require authenticated identities:
  - `approve_request` / `reject_request` require `approver` + `authToken`
  - `execute_approved_request` requires `executor` + `authToken`

### Approver config file

Example:

```json
{
  "version": 1,
  "approvers": [
    { "id": "liv", "tokenEnv": "APPROVER_TOKEN_LIV" },
    { "id": "boris", "tokenEnv": "APPROVER_TOKEN_BORIS" }
  ]
}
```

Then provide the actual secrets through environment variables, for example:

```bash
export APPROVER_AUTH_MODE=token
export APPROVER_AUTH_FILE=./approvers/example.approvers.json
export APPROVER_TOKEN_LIV="replace-me"
export APPROVER_TOKEN_BORIS="replace-me-too"
```

This keeps approver identity configuration in a file while keeping the actual secrets out of source control.

## Approval Expiry / Replay Protection

Approved requests are now intentionally short-lived and single-use:

- `APPROVAL_TTL_SECONDS` controls how long an approval remains valid
- if executor auth is enabled, `execute_approved_request` also requires authenticated identity
- once executed, the request moves to `executed` and cannot be replayed
- if execution is attempted after the TTL window, the request moves to `expired`

This prevents stale approvals from being used much later and blocks repeat execution of the same approved action.

## Example Policy Files

The `policies/` directory includes ready-to-use examples:

- `policies/dev-balanced.policy.json`
  - reasonable default for local development
  - reviews important project files and sensitive reads

- `policies/ci-friendly.policy.json`
  - allows routine CI-style work
  - reviews workflow/release-related changes
  - denies secret access

- `policies/strict-lockdown.policy.json`
  - disables shell execution entirely
  - reviews high-impact config changes
  - tightly restricts sensitive paths

The `approvers/` directory also includes:

- `approvers/example.approvers.json`
  - sample token-based approver identity config
  - maps approver ids to environment variable names that hold their secrets

Use one by setting:

```bash
export POLICY_FILE=./policies/dev-balanced.policy.json
```

For OpenClaw wiring and end-to-end verification, see:

- [`docs/OPENCLAW_INTEGRATION.md`](./docs/OPENCLAW_INTEGRATION.md)
- [`docs/RELEASE_CHECKLIST.md`](./docs/RELEASE_CHECKLIST.md)

## Testing

```bash
npm run typecheck
npm test
npm run build
npm run integration:harness
```

Current test coverage includes:
- safe file read/write inside allowed roots
- rejection of out-of-bounds paths
- allowlisted shell execution
- rejection of disallowed commands and shell metacharacters
- per-command shell validator behavior for `grep`, `find`, and file-oriented commands
- structured deny/review policy decisions
- wrapper behavior for review-required requests
- persisted approval request creation and approval transitions
- approval metadata for approvals and rejections
- policy schema validation for valid and invalid policy files
- validation of all example policy files in `policies/`
- end-to-end MCP stdio integration via `scripts/integrationHarness.ts`

## Future Enhancements

- [ ] Configurable restricted keywords via JSON config file
- [ ] Per-tool whitelisting rules
- [ ] Approval workflow for risky but potentially valid actions
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
