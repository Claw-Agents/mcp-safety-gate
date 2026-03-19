# Release Checklist

Use this before cutting a public release or tagging an internal milestone.

## Quality gates

- [ ] `npm ci`
- [ ] `npm run typecheck`
- [ ] `npm test`
- [ ] `npm run build`
- [ ] `npm run integration:harness`

## Functional checks

- [ ] Verify at least one bundled policy file still fits the intended posture
- [ ] Verify approval workflow still creates, approves, rejects, and executes requests correctly
- [ ] Verify audit log and approval store paths are documented and working
- [ ] Verify OpenClaw integration docs still match the current runtime behavior

## Docs

- [ ] README reflects current features
- [ ] QUICKSTART is still accurate
- [ ] `docs/OPENCLAW_INTEGRATION.md` is current
- [ ] example policy files in `policies/` are still valid and useful

## Release hygiene

- [ ] Review commits since last release
- [ ] Decide whether policy examples need changes
- [ ] Confirm no local-only paths or secrets leaked into docs/examples
- [ ] Tag or publish with a short release summary
