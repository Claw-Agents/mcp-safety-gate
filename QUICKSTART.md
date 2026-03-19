# Safety Gate - Quick Start

This is the fastest path to running Safety Gate locally and wiring it into OpenClaw.

## 1. Install and build

```bash
cd mcp-safety-gate
npm install
npm run typecheck
npm test
npm run build
```

## 2. Pick a policy

Start with:

```bash
./policies/dev-balanced.policy.json
```

Other bundled options:
- `./policies/ci-friendly.policy.json`
- `./policies/strict-lockdown.policy.json`

## 3. Set runtime paths

```bash
export ALLOWED_PATHS=/Users/you/projects/demo-repo
export POLICY_FILE=/absolute/path/to/mcp-safety-gate/policies/dev-balanced.policy.json
export AUDIT_LOG_PATH=/absolute/path/to/mcp-safety-gate/runtime/audit-log.jsonl
export APPROVAL_STORE_PATH=/absolute/path/to/mcp-safety-gate/runtime/approval-requests.json
```

## 4. Start the server

```bash
node ./dist/index.js
```

You should see startup logs and then the server will wait on stdio.

## 5. Wire it into OpenClaw

Use the Safety Gate server as a stdio MCP backend with:

- command: `node`
- args: `[/absolute/path/to/mcp-safety-gate/dist/index.js]`
- env:
  - `ALLOWED_PATHS`
  - `POLICY_FILE`
  - `AUDIT_LOG_PATH`
  - `APPROVAL_STORE_PATH`

For a fuller walkthrough, see:

- [`docs/OPENCLAW_INTEGRATION.md`](./docs/OPENCLAW_INTEGRATION.md)

## 6. Verify the important paths

- safe read-only command → should be **allowed**
- write to `package.json` under `dev-balanced` → should be **review required**
- use:
  - `list_approval_requests`
  - `approve_request`
  - `execute_approved_request`

## 7. What Safety Gate does now

- real safe file read/write within allowed roots
- allowlisted shell execution with timeout and metacharacter rejection
- structured policy engine
- explicit approval workflow
- approval metadata (`approver`, `notes`, `rejectionReason`)
- audit logging
- schema-validated policy files

## 8. Recommended first production-ish posture

- one repo in `ALLOWED_PATHS`
- `dev-balanced.policy.json`
- audit and approval files outside the repo
- absolute paths everywhere
- narrow shell allowlist
