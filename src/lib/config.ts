/**
 * Configuration module for Safety Gate
 */

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

/**
 * Load configuration from environment variables
 */
export function loadConfig(): SafetyGateConfig {
  const dryRun = process.env.DRY_RUN === 'true';
  const verbose = process.env.VERBOSE === 'true';
  const auditLogPath = process.env.AUDIT_LOG_PATH || './audit_log.json';

  return {
    dryRun,
    restrictedKeywords: RESTRICTED_KEYWORDS,
    auditLogPath,
    verbose,
  };
}

/**
 * Log configuration on startup
 */
export function logConfigOnStartup(config: SafetyGateConfig): void {
  console.log('[Config] Safety Gate Configuration:');
  console.log(`  Dry-Run Mode: ${config.dryRun}`);
  console.log(`  Audit Log Path: ${config.auditLogPath}`);
  console.log(`  Restricted Keywords: ${config.restrictedKeywords.length} patterns loaded`);
  console.log(`  Verbose Logging: ${config.verbose}`);
}
