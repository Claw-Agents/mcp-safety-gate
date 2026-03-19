/**
 * Real tool implementations for Safety Gate
 */

import { promises as fs } from 'fs';
import { execFile } from 'child_process';
import { promisify } from 'util';
import { CallToolResult } from '@modelcontextprotocol/sdk/types.js';
import { SafetyGateConfig } from '../types/index.js';
import { assertPathAllowed, ensureParentDirectory } from './fsPolicy.js';

const execFileAsync = promisify(execFile);
const SHELL_META_PATTERN = /[|&;><`$\\]/;

function ok(text: string): CallToolResult {
  return {
    content: [{ type: 'text', text }],
    isError: false,
  };
}

function err(text: string): CallToolResult {
  return {
    content: [{ type: 'text', text }],
    isError: true,
  };
}

function tokenizeCommand(command: string): string[] {
  const trimmed = command.trim();
  if (!trimmed) {
    throw new Error('Command cannot be empty');
  }

  if (SHELL_META_PATTERN.test(trimmed)) {
    throw new Error('Shell metacharacters are not allowed');
  }

  const tokens = trimmed.match(/"[^"]*"|'[^']*'|\S+/g) ?? [];
  return tokens.map(token => token.replace(/^['"]|['"]$/g, ''));
}

function assertAllowedCommand(commandName: string, config: SafetyGateConfig): void {
  if (!config.shellAllowedCommands.includes(commandName.toLowerCase())) {
    throw new Error(
      `Command '${commandName}' is not in the allowed shell command list: ${config.shellAllowedCommands.join(', ')}`
    );
  }
}

function assertSafePathTokens(tokens: string[], config: SafetyGateConfig): void {
  for (const token of tokens) {
    if (token.startsWith('-')) {
      continue;
    }

    const looksLikePath = token.startsWith('/') || token.startsWith('./') || token.startsWith('../') || token.includes('/');
    if (looksLikePath) {
      assertPathAllowed(token, config.allowedPaths);
    }
  }
}

export async function executeShellCommand(
  command: string,
  config: SafetyGateConfig
): Promise<CallToolResult> {
  try {
    const tokens = tokenizeCommand(command);
    const [commandName, ...args] = tokens;

    if (!commandName) {
      throw new Error('Command cannot be empty');
    }

    assertAllowedCommand(commandName, config);
    assertSafePathTokens(args, config);

    const { stdout, stderr } = await execFileAsync(commandName, args, {
      cwd: config.allowedPaths[0],
      timeout: config.shellCommandTimeoutMs,
      maxBuffer: config.maxFileReadBytes,
    });

    const output = [
      `Command: ${command}`,
      `Exit: 0`,
      stdout ? `STDOUT:\n${stdout}` : 'STDOUT: <empty>',
      stderr ? `STDERR:\n${stderr}` : 'STDERR: <empty>',
    ].join('\n');

    return ok(output);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return err(`Shell command rejected or failed: ${message}`);
  }
}

export async function writeFileSafely(
  targetPath: string,
  content: string,
  config: SafetyGateConfig
): Promise<CallToolResult> {
  try {
    const resolvedPath = assertPathAllowed(targetPath, config.allowedPaths);
    const byteLength = Buffer.byteLength(content, 'utf-8');

    if (byteLength > config.maxFileWriteBytes) {
      throw new Error(
        `Content exceeds MAX_FILE_WRITE_BYTES (${config.maxFileWriteBytes} bytes)`
      );
    }

    await ensureParentDirectory(resolvedPath);
    await fs.writeFile(resolvedPath, content, 'utf-8');

    return ok(`File written: ${resolvedPath}\nBytes written: ${byteLength}`);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return err(`Write failed: ${message}`);
  }
}

export async function readFileSafely(
  targetPath: string,
  config: SafetyGateConfig
): Promise<CallToolResult> {
  try {
    const resolvedPath = assertPathAllowed(targetPath, config.allowedPaths);
    const stats = await fs.stat(resolvedPath);

    if (stats.size > config.maxFileReadBytes) {
      throw new Error(`File exceeds MAX_FILE_READ_BYTES (${config.maxFileReadBytes} bytes)`);
    }

    const content = await fs.readFile(resolvedPath, 'utf-8');
    return ok(`File read: ${resolvedPath}\nContent:\n${content}`);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return err(`Read failed: ${message}`);
  }
}
