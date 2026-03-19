# PR Notes

## Summary

This PR turns `mcp-safety-gate` from an early prototype into a more complete OpenClaw-focused MCP security middleware with:

- real safe file read/write
- allowlisted shell execution
- structured allow/deny/review policy rules
- persisted approval workflow
- approval metadata
- schema-validated policy files
- bundled example policies
- OpenClaw integration docs
- end-to-end MCP integration harness
- GitHub Actions CI

## Major changes

### Real execution path
- replaced mocked `shell_command`, `write_file`, and `read_file` behavior with real implementations
- added path sandboxing and byte limits
- added shell timeout handling and metacharacter rejection

### Structured policy engine
- introduced per-tool ordered rules
- supports `allow`, `deny`, and `review`
- added schema validation for policy files

### Approval workflow
- persisted review requests to a JSON store
- added MCP tools for:
  - `list_approval_requests`
  - `approve_request`
  - `reject_request`
  - `execute_approved_request`
- added metadata support for approver / notes / rejection reason

### Shell hardening
- added per-command validators
- rejects unsafe `find` and recursive `grep`
- requires explicit file paths for file-oriented commands

### Docs and examples
- updated README and QUICKSTART
- added `docs/OPENCLAW_INTEGRATION.md`
- added `docs/RELEASE_CHECKLIST.md`
- added example policies under `policies/`

### Testing and CI
- added unit/policy tests
- added end-to-end MCP stdio integration harness
- added GitHub Actions CI workflow

## Validation

Ran successfully:

```bash
npm run typecheck
npm test
npm run integration:harness
```

## Suggested reviewer focus

- policy defaults and example policies
- shell validator strictness vs usability
- approval workflow UX
- OpenClaw integration guidance
