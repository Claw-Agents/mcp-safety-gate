/**
 * Configuration module for Safety Gate
 */

import path from 'path';
import { SafetyGateConfig } from '../types/index.js';

// Hardcoded restricted keywords list
const RESTRICTED_KEYWORDS = [
  // System destructive operations
  'rm',
  'rmdir',
  'del',
  'delete',
  'format',
  'dd',
  'mkfs',
  'shred',
  'wipe',

  // Privilege escalation
  'sudo',
  'su ',
  'chmod 777',
  'chown',

  // Sensitive file paths and patterns
  '.env',
  '.aws/credentials',
  '.ssh/id_rsa',
  '/etc/passwd',
  'secret',
  'token',
  'key',
  'password',
  'apikey',
  'api_key',
  'private_key',
  'github_token',
  'aws_access_key',
  'aws_secret_key',

  // Network dangerous operations
  'wget ',
  'curl ',

  // History/cache clearing
  'clear history',
  'history -c',
];

const DEFAULT_SHELL_ALLOWED_COMMANDS = [
  'pwd',
  'ls',
  'cat',
  'head',
  'tail',
  'wc',
  'find',
  'grep',
  'which',
  'echo',
];

function parseListEnv(value: string | undefined, fallback: string[]): string[] {
  if (!value || value.trim().length === 0) {
    return fallback;
  }

  return value
    .split(',')
    .map(part => part.trim())
    .filter(Boolean);
}

function parseNumberEnv(value: string | undefined, fallback: number): number {
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

/**
 * Load configuration from environment variables
 */
export function loadConfig(): SafetyGateConfig {
  const dryRun = process.env.DRY_RUN === 'true';
  const verbose = process.env.VERBOSE === 'true';
  const auditLogPath = process.env.AUDIT_LOG_PATH || './audit_log.json';
  const allowedPaths = parseListEnv(process.env.ALLOWED_PATHS, [process.cwd()]).map(entry =>
    path.resolve(entry)
  );
  const shellAllowedCommands = parseListEnv(
    process.env.SHELL_ALLOWED_COMMANDS,
    DEFAULT_SHELL_ALLOWED_COMMANDS
  ).map(command => command.toLowerCase());

  return {
    dryRun,
    restrictedKeywords: RESTRICTED_KEYWORDS,
    auditLogPath,
    verbose,
    allowedPaths,
    shellAllowedCommands,
    maxFileReadBytes: parseNumberEnv(process.env.MAX_FILE_READ_BYTES, 1024 * 1024),
    maxFileWriteBytes: parseNumberEnv(process.env.MAX_FILE_WRITE_BYTES, 256 * 1024),
    shellCommandTimeoutMs: parseNumberEnv(process.env.SHELL_COMMAND_TIMEOUT_MS, 5_000),
  };
}

/**
 * Log configuration on startup
 */
export function logConfigOnStartup(config: SafetyGateConfig): void {
  console.log('[Config] Safety Gate Configuration:');
  console.log(`  Dry-Run Mode: ${config.dryRun}`);
  console.log(`  Audit Log Path: ${config.auditLogPath}`);
  console.log(`  Allowed Paths: ${config.allowedPaths.join(', ')}`);
  console.log(`  Shell Allowed Commands: ${config.shellAllowedCommands.join(', ')}`);
  console.log(`  Max File Read Bytes: ${config.maxFileReadBytes}`);
  console.log(`  Max File Write Bytes: ${config.maxFileWriteBytes}`);
  console.log(`  Shell Command Timeout (ms): ${config.shellCommandTimeoutMs}`);
  console.log(`  Restricted Keywords: ${config.restrictedKeywords.length} patterns loaded`);
  console.log(`  Verbose Logging: ${config.verbose}`);
}
