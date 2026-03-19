/**
 * Configuration module for Safety Gate
 */

import path from 'path';
import { promises as fs } from 'fs';
import { PolicyRule, SafetyGateConfig, SafetyGatePolicy } from '../types/index.js';
import { validatePolicy } from './policySchema.js';
import { loadApproverAuth } from './approverAuth.js';

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

const DEFAULT_POLICY_RULES: PolicyRule[] = [
  {
    id: 'deny-dangerous-shell-keywords',
    effect: 'deny',
    reason: 'Dangerous shell keywords are denied',
    tools: ['shell_command'],
    match: {
      keywords: RESTRICTED_KEYWORDS,
    },
  },
  {
    id: 'deny-sensitive-write-keywords',
    effect: 'deny',
    reason: 'Sensitive secrets and credential writes are denied',
    tools: ['write_file'],
    match: {
      keywords: [
        '.env',
        '.aws/credentials',
        '.ssh/id_rsa',
        'private_key',
        'github_token',
        'aws_access_key',
        'aws_secret_key',
      ],
    },
  },
  {
    id: 'review-sensitive-read-keywords',
    effect: 'review',
    reason: 'Sensitive reads require explicit review',
    tools: ['read_file'],
    match: {
      keywords: ['.env', '.aws/credentials', '.ssh/id_rsa', 'private_key'],
    },
  },
  {
    id: 'review-high-impact-project-files',
    effect: 'review',
    reason: 'Writes to high-impact project files require explicit review',
    tools: ['write_file'],
    match: {
      pathSubstrings: ['package.json', 'tsconfig.json', 'Dockerfile', '.github/workflows/'],
    },
  },
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

async function loadPolicy(policyFilePath?: string): Promise<SafetyGatePolicy> {
  if (!policyFilePath) {
    return validatePolicy({
      version: 1,
      rules: DEFAULT_POLICY_RULES,
    });
  }

  const resolvedPolicyPath = path.resolve(policyFilePath);
  const content = await fs.readFile(resolvedPolicyPath, 'utf-8');
  const parsed = JSON.parse(content) as SafetyGatePolicy;

  try {
    return validatePolicy(parsed);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`Invalid policy file at ${resolvedPolicyPath}: ${message}`);
  }
}

/**
 * Load configuration from environment variables
 */
export async function loadConfig(): Promise<SafetyGateConfig> {
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
  const policyFilePath = process.env.POLICY_FILE
    ? path.resolve(process.env.POLICY_FILE)
    : undefined;
  const approverAuthMode =
    process.env.APPROVER_AUTH_MODE === 'token' ? 'token' : 'off';
  const approverAuthFilePath = process.env.APPROVER_AUTH_FILE
    ? path.resolve(process.env.APPROVER_AUTH_FILE)
    : undefined;

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
    policy: await loadPolicy(policyFilePath),
    policyFilePath,
    approvalStorePath: path.resolve(process.env.APPROVAL_STORE_PATH || './approval-requests.json'),
    approverAuthMode,
    approverAuthFilePath,
    approverAuth: await loadApproverAuth(approverAuthMode, approverAuthFilePath),
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
  console.log(`  Policy File: ${config.policyFilePath ?? '<built-in default>'}`);
  console.log(`  Policy Rules: ${config.policy.rules.length}`);
  console.log(`  Approval Store: ${config.approvalStorePath}`);
  console.log(`  Approver Auth Mode: ${config.approverAuthMode}`);
  console.log(`  Approver Auth File: ${config.approverAuthFilePath ?? '<disabled>'}`);
  console.log(`  Restricted Keywords: ${config.restrictedKeywords.length} patterns loaded`);
  console.log(`  Verbose Logging: ${config.verbose}`);
}
