# OpenClaw Integration Guide

This guide shows how to run **Safety Gate** as a stdio MCP server that OpenClaw can launch, then how to verify the review / approval flow end to end.

## What this gives you

Safety Gate sits in front of file and shell actions and adds:

- path sandboxing
- structured allow / deny / review policy rules
- persisted approval requests
- explicit approve / reject / execute flow
- audit logging

## 1. Build the server

From the repo root:

```bash
npm install
npm run build
```

The server entrypoint will be:

```bash
./dist/index.js
```

## 2. Pick a policy

Start with one of the bundled examples:

- `./policies/dev-balanced.policy.json`
- `./policies/ci-friendly.policy.json`
- `./policies/strict-lockdown.policy.json`

For most local development, use:

```bash
./policies/dev-balanced.policy.json
```

## 3. Choose safe roots and storage paths

Decide which directories Safety Gate is allowed to touch.

Example:

```bash
export ALLOWED_PATHS=/Users/you/projects/demo-repo
export POLICY_FILE=/absolute/path/to/mcp-safety-gate/policies/dev-balanced.policy.json
export AUDIT_LOG_PATH=/absolute/path/to/mcp-safety-gate/runtime/audit-log.jsonl
export APPROVAL_STORE_PATH=/absolute/path/to/mcp-safety-gate/runtime/approval-requests.json
```

Recommended practice:

- keep `ALLOWED_PATHS` narrow
- keep audit and approval files outside the target repo if possible
- use absolute paths in OpenClaw config

## 4. Test the server standalone first

Before wiring it into OpenClaw, make sure the process starts cleanly:

```bash
ALLOWED_PATHS=/Users/you/projects/demo-repo \
POLICY_FILE=/absolute/path/to/mcp-safety-gate/policies/dev-balanced.policy.json \
AUDIT_LOG_PATH=/absolute/path/to/mcp-safety-gate/runtime/audit-log.jsonl \
APPROVAL_STORE_PATH=/absolute/path/to/mcp-safety-gate/runtime/approval-requests.json \
node ./dist/index.js
```

You should see startup logs and then the process should wait on stdio.

## 5. Configure OpenClaw to launch the MCP server

OpenClaw’s exact MCP configuration surface may vary by version and install mode, but the important part is the **stdio command + args + env**.

Use the Safety Gate server as a stdio MCP backend with this payload shape:

```json
{
  "command": "node",
  "args": ["/absolute/path/to/mcp-safety-gate/dist/index.js"],
  "env": {
    "ALLOWED_PATHS": "/Users/you/projects/demo-repo",
    "POLICY_FILE": "/absolute/path/to/mcp-safety-gate/policies/dev-balanced.policy.json",
    "AUDIT_LOG_PATH": "/absolute/path/to/mcp-safety-gate/runtime/audit-log.jsonl",
    "APPROVAL_STORE_PATH": "/absolute/path/to/mcp-safety-gate/runtime/approval-requests.json",
    "SHELL_ALLOWED_COMMANDS": "pwd,ls,cat,head,tail,wc,find,grep,which,echo",
    "MAX_FILE_READ_BYTES": "1048576",
    "MAX_FILE_WRITE_BYTES": "262144",
    "SHELL_COMMAND_TIMEOUT_MS": "5000"
  }
}
```

If your OpenClaw config uses an `mcpServers`, `mcp`, plugin entry, or another gateway-level MCP section, place the payload there according to your version’s config format.

### Example config sketch

This example is intentionally schematic — adapt the surrounding key names to your OpenClaw version:

```json
{
  "mcpServers": {
    "safety-gate": {
      "command": "node",
      "args": ["/absolute/path/to/mcp-safety-gate/dist/index.js"],
      "env": {
        "ALLOWED_PATHS": "/Users/you/projects/demo-repo",
        "POLICY_FILE": "/absolute/path/to/mcp-safety-gate/policies/dev-balanced.policy.json",
        "AUDIT_LOG_PATH": "/absolute/path/to/mcp-safety-gate/runtime/audit-log.jsonl",
        "APPROVAL_STORE_PATH": "/absolute/path/to/mcp-safety-gate/runtime/approval-requests.json"
      }
    }
  }
}
```

## 6. End-to-end verification flow

Once OpenClaw can see the MCP server, verify each path.

### Allowed action

Ask OpenClaw to run a safe read-only command such as:

- `pwd`
- `ls`
- `cat ./README.md`

Expected result:
- command succeeds
- audit log records `decision: "allowed"`

### Review-required action

Ask OpenClaw to write a file covered by a review rule, such as `package.json` when using the bundled `dev-balanced` policy.

Expected result:
- Safety Gate returns `Review Required`
- response includes an approval request ID
- approval request is written to `approval-requests.json`

### Approval flow

Use the approval-management tools:

1. `list_approval_requests`
2. `approve_request`
3. `execute_approved_request`

Expected result:
- request moves from `pending` → `approved` → `executed`
- metadata such as `approver` and `notes` persists

## 7. Recommended starting posture

If you are just getting started with OpenClaw integration:

- policy: `dev-balanced.policy.json`
- shell allowlist: keep default
- allowed paths: one repo only
- approval store: repo-adjacent runtime folder
- audit log: separate JSONL file

## 8. Troubleshooting

### OpenClaw does not see the server

Check:
- the path to `dist/index.js`
- that `npm run build` was run
- that the configured command is `node`
- that all env paths are absolute

### Policy file causes startup failure

That is expected for malformed policy files now.

Validate:
- JSON syntax is correct
- every rule has `id`, `effect`, `reason`, `tools`, and at least one matcher

### Requests are always denied or reviewed

Check:
- active `POLICY_FILE`
- `ALLOWED_PATHS`
- whether the target file matches `pathSubstrings`
- whether shell commands match a deny rule before execution

### Review requests appear but never execute

Check:
- request status is `approved`
- you used `execute_approved_request`
- the original action still passes runtime safety checks like path sandboxing and shell allowlist

## 9. Integration harness

This repo also includes an end-to-end MCP stdio harness:

```bash
npm run integration:harness
```

What it verifies:
- the built server launches over stdio
- required tools are exposed
- safe reads succeed
- review-required writes create an approval request
- approval metadata can be attached
- approved requests can be executed successfully

## 10. Suggested next integration work

Once this is working, good follow-ups are:

- a repo-specific policy file checked into infra
- OpenClaw-specific setup examples for your exact config format
- approval notifications / operator UX
- stronger per-command validators for shell execution
