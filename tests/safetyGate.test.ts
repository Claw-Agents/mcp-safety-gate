import test from 'node:test';
import assert from 'node:assert/strict';
import os from 'os';
import path from 'path';
import { promises as fs } from 'fs';
import { executeShellCommand, readFileSafely, writeFileSafely } from '../src/lib/realTools.js';
import { evaluateToolPolicy } from '../src/lib/policyEngine.js';
import { validatePolicy } from '../src/lib/policySchema.js';
import { wrapToolHandler } from '../src/lib/toolWrapper.js';
import {
  getApprovalRequest,
  listApprovalRequests,
  updateApprovalRequestStatus,
} from '../src/lib/approvalStore.js';
import { SafetyGateConfig } from '../src/types/index.js';

async function withTempDir(run: (dir: string, config: SafetyGateConfig) => Promise<void>): Promise<void> {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'safety-gate-'));
  const config: SafetyGateConfig = {
    dryRun: false,
    restrictedKeywords: ['rm', 'sudo', '.env'],
    auditLogPath: path.join(dir, 'audit.jsonl'),
    verbose: false,
    allowedPaths: [dir],
    shellAllowedCommands: ['pwd', 'ls', 'cat', 'echo'],
    maxFileReadBytes: 1024 * 1024,
    maxFileWriteBytes: 1024 * 1024,
    shellCommandTimeoutMs: 3_000,
    approvalStorePath: path.join(dir, 'approval-requests.json'),
    policy: {
      version: 1,
      rules: [
        {
          id: 'deny-env-writes',
          effect: 'deny',
          reason: 'Environment file writes are denied',
          tools: ['write_file'],
          match: {
            pathSubstrings: ['.env'],
          },
        },
        {
          id: 'review-package-json',
          effect: 'review',
          reason: 'package.json writes require review',
          tools: ['write_file'],
          match: {
            pathSubstrings: ['package.json'],
          },
        },
      ],
    },
  };

  try {
    await run(dir, config);
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
}

test('write_file and read_file operate inside allowed roots', async () => {
  await withTempDir(async (dir, config) => {
    const filePath = path.join(dir, 'notes', 'hello.txt');
    const writeResult = await writeFileSafely(filePath, 'hello world', config);
    assert.equal(writeResult.isError, false);

    const readResult = await readFileSafely(filePath, config);
    assert.equal(readResult.isError, false);
    assert.match((readResult.content?.[0] as { text: string }).text, /hello world/);
  });
});

test('read_file rejects paths outside allowed roots', async () => {
  await withTempDir(async (_dir, config) => {
    const result = await readFileSafely('/etc/hosts', config);
    assert.equal(result.isError, true);
    assert.match((result.content?.[0] as { text: string }).text, /outside allowed roots/);
  });
});

test('shell_command executes allowlisted commands', async () => {
  await withTempDir(async (_dir, config) => {
    const result = await executeShellCommand('echo hello', config);
    assert.equal(result.isError, false);
    assert.match((result.content?.[0] as { text: string }).text, /hello/);
  });
});

test('shell_command rejects non-allowlisted commands and shell metacharacters', async () => {
  await withTempDir(async (_dir, config) => {
    const blockedCommand = await executeShellCommand('uname -a', config);
    assert.equal(blockedCommand.isError, true);
    assert.match((blockedCommand.content?.[0] as { text: string }).text, /not in the allowed shell command list/);

    const metacharacters = await executeShellCommand('echo hi && pwd', config);
    assert.equal(metacharacters.isError, true);
    assert.match((metacharacters.content?.[0] as { text: string }).text, /metacharacters/);
  });
});

test('structured policy can deny or require review before execution', async () => {
  await withTempDir(async (_dir, config) => {
    const denied = evaluateToolPolicy('write_file', { path: '.env', content: 'x' }, config.policy);
    assert.equal(denied.effect, 'deny');
    assert.equal(denied.ruleId, 'deny-env-writes');

    const review = evaluateToolPolicy(
      'write_file',
      { path: 'package.json', content: '{}' },
      config.policy
    );
    assert.equal(review.effect, 'review');
    assert.equal(review.ruleId, 'review-package-json');
  });
});

test('tool wrapper creates approval request and returns review required without executing handler', async () => {
  await withTempDir(async (_dir, config) => {
    let executed = false;
    const handler = wrapToolHandler(
      {
        name: 'write_file',
        description: 'Write content safely',
      },
      async () => {
        executed = true;
        return {
          content: [{ type: 'text', text: 'should not happen' }],
          isError: false,
        };
      },
      config
    );

    const result = await handler({ path: 'package.json', content: '{}' });
    assert.equal(result.isError, true);
    assert.equal(executed, false);
    const responseText = (result.content?.[0] as { text: string }).text;
    assert.match(responseText, /Review Required/);
    assert.match(responseText, /Approval Request ID:/);

    const pending = await listApprovalRequests(config.approvalStorePath, 'pending');
    assert.equal(pending.length, 1);
    assert.equal(pending[0]?.toolName, 'write_file');
  });
});

test('approval store can approve and fetch requests', async () => {
  await withTempDir(async (_dir, config) => {
    const handler = wrapToolHandler(
      {
        name: 'write_file',
        description: 'Write content safely',
      },
      async () => ({
        content: [{ type: 'text', text: 'ok' }],
        isError: false,
      }),
      config
    );

    await handler({ path: 'package.json', content: '{}' });
    const [pending] = await listApprovalRequests(config.approvalStorePath, 'pending');
    assert.ok(pending);

    const approved = await updateApprovalRequestStatus(
      config.approvalStorePath,
      pending.id,
      'approved',
      {
        approver: 'Liv',
        notes: 'Looks safe enough',
      }
    );
    assert.equal(approved.status, 'approved');
    assert.equal(approved.metadata?.approver, 'Liv');
    assert.equal(approved.metadata?.notes, 'Looks safe enough');

    const loaded = await getApprovalRequest(config.approvalStorePath, pending.id);
    assert.equal(loaded?.status, 'approved');
    assert.equal(loaded?.metadata?.approver, 'Liv');
  });
});

test('policy schema validation accepts valid policies', () => {
  const parsed = validatePolicy({
    version: 1,
    rules: [
      {
        id: 'review-package-json',
        effect: 'review',
        reason: 'package.json writes require review',
        tools: ['write_file'],
        match: {
          pathSubstrings: ['package.json'],
        },
      },
    ],
  });

  assert.equal(parsed.rules[0]?.id, 'review-package-json');
});

test('policy schema validation rejects malformed policies', () => {
  assert.throws(
    () =>
      validatePolicy({
        version: 1,
        rules: [
          {
            id: 'bad-rule',
            effect: 'review',
            reason: 'Missing matchers should fail',
            tools: ['write_file'],
            match: {},
          },
        ],
      }),
    /at least one matcher/
  );
});

test('approval metadata supports rejection details', async () => {
  await withTempDir(async (_dir, config) => {
    const handler = wrapToolHandler(
      {
        name: 'write_file',
        description: 'Write content safely',
      },
      async () => ({
        content: [{ type: 'text', text: 'ok' }],
        isError: false,
      }),
      config
    );

    await handler({ path: 'package.json', content: '{}' });
    const [pending] = await listApprovalRequests(config.approvalStorePath, 'pending');
    assert.ok(pending);

    const rejected = await updateApprovalRequestStatus(
      config.approvalStorePath,
      pending.id,
      'rejected',
      {
        approver: 'Liv',
        rejectionReason: 'Needs more review',
        notes: 'Come back with tests first',
      }
    );

    assert.equal(rejected.metadata?.approver, 'Liv');
    assert.equal(rejected.metadata?.rejectionReason, 'Needs more review');
    assert.equal(rejected.metadata?.notes, 'Come back with tests first');
  });
});
