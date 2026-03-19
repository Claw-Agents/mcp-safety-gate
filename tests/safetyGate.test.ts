import test from 'node:test';
import assert from 'node:assert/strict';
import os from 'os';
import path from 'path';
import { promises as fs } from 'fs';
import { executeShellCommand, readFileSafely, writeFileSafely } from '../src/lib/realTools.js';
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
