import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import { promises as fs } from 'node:fs';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';

function textFromResult(result: any): string {
  const content = result?.content ?? [];
  return content
    .filter((item: any) => item?.type === 'text')
    .map((item: any) => item.text)
    .join('\n');
}

async function main(): Promise<void> {
  const tempRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'safety-gate-integration-'));
  const repoRoot = path.join(tempRoot, 'repo');
  const runtimeRoot = path.join(tempRoot, 'runtime');
  const repoPackageJson = path.join(repoRoot, 'package.json');
  const readmePath = path.join(repoRoot, 'README.md');
  const policyFile = path.resolve('policies/dev-balanced.policy.json');

  await fs.mkdir(repoRoot, { recursive: true });
  await fs.mkdir(runtimeRoot, { recursive: true });
  await fs.writeFile(readmePath, '# Demo Repo\n', 'utf-8');
  await fs.writeFile(repoPackageJson, '{"name":"demo"}\n', 'utf-8');

  const transport = new StdioClientTransport({
    command: 'node',
    args: [path.resolve('dist/index.js')],
    cwd: path.resolve('.'),
    stderr: 'pipe',
    env: {
      ALLOWED_PATHS: repoRoot,
      POLICY_FILE: policyFile,
      AUDIT_LOG_PATH: path.join(runtimeRoot, 'audit-log.jsonl'),
      APPROVAL_STORE_PATH: path.join(runtimeRoot, 'approval-requests.json'),
    },
  });

  const stderrLines: string[] = [];
  transport.stderr?.on('data', chunk => {
    stderrLines.push(String(chunk));
  });

  const client = new Client({ name: 'SafetyGateIntegrationHarness', version: '1.0.0' });

  try {
    await client.connect(transport);

    const toolsResult = await client.listTools();
    const toolNames = toolsResult.tools.map(tool => tool.name).sort();
    for (const required of [
      'shell_command',
      'write_file',
      'read_file',
      'list_approval_requests',
      'approve_request',
      'reject_request',
      'execute_approved_request',
    ]) {
      assert.ok(toolNames.includes(required), `Missing tool: ${required}`);
    }

    const readResult = await client.callTool({
      name: 'read_file',
      arguments: { path: readmePath },
    });
    assert.equal(readResult.isError, false);
    assert.match(textFromResult(readResult), /Demo Repo/);

    const reviewResult = await client.callTool({
      name: 'write_file',
      arguments: {
        path: repoPackageJson,
        content: '{"name":"demo","version":"1.0.0"}\n',
      },
    });
    assert.equal(reviewResult.isError, true);
    const reviewText = textFromResult(reviewResult);
    assert.match(reviewText, /Review Required/);
    const requestId = reviewText.match(/Approval Request ID: ([a-f0-9-]+)/i)?.[1];
    assert.ok(requestId, 'Expected approval request ID in review response');

    const pendingList = await client.callTool({
      name: 'list_approval_requests',
      arguments: { status: 'pending' },
    });
    assert.match(textFromResult(pendingList), new RegExp(String(requestId)));

    const approveResult = await client.callTool({
      name: 'approve_request',
      arguments: {
        requestId,
        approver: 'integration-harness',
        notes: 'approved during end-to-end test',
      },
    });
    assert.equal(approveResult.isError, false);

    const executeResult = await client.callTool({
      name: 'execute_approved_request',
      arguments: { requestId },
    });
    assert.equal(executeResult.isError, false);

    const updatedPackageJson = await fs.readFile(repoPackageJson, 'utf-8');
    assert.match(updatedPackageJson, /1.0.0/);

    const executedList = await client.callTool({
      name: 'list_approval_requests',
      arguments: { status: 'executed' },
    });
    const executedText = textFromResult(executedList);
    assert.match(executedText, /integration-harness/);
    assert.match(executedText, /approved during end-to-end test/);

    console.log('Integration harness passed.');
    console.log(`Temp root: ${tempRoot}`);
  } finally {
    await client.close();
    await transport.close();
    if (stderrLines.length > 0) {
      console.error('[integration-harness] server stderr sample:');
      console.error(stderrLines.join('').slice(0, 2000));
    }
  }
}

main().catch(error => {
  console.error('Integration harness failed:');
  console.error(error);
  process.exit(1);
});
