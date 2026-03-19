/**
 * Audit Logger for Safety Gate
 * Logs all intercepted tool calls to a local JSON Lines file
 */

import { promises as fs } from 'fs';
import { AuditLogEntry } from '../types/index.js';

/**
 * Ensure audit log file exists
 */
async function ensureAuditLogExists(auditLogPath: string): Promise<void> {
  try {
    await fs.access(auditLogPath);
  } catch {
    // File doesn't exist, create it
    await fs.writeFile(auditLogPath, '', 'utf-8');
  }
}

/**
 * Log a tool call to the audit log
 * Uses JSON Lines format (one JSON object per line)
 */
export async function logToolCall(
  entry: AuditLogEntry,
  auditLogPath: string,
  verbose: boolean = false
): Promise<void> {
  try {
    // Ensure file exists
    await ensureAuditLogExists(auditLogPath);

    // Write JSON line
    const jsonLine = JSON.stringify(entry) + '\n';
    await fs.appendFile(auditLogPath, jsonLine, 'utf-8');

    if (verbose) {
      console.log(
        `[AuditLog] ${entry.toolName} - ${entry.decision}: ${entry.reason}`
      );
    }
  } catch (error) {
    console.error('[AuditLog] Failed to write audit log:', error);
    // Don't throw - log failures should not crash the server
  }
}

/**
 * Read and parse all entries from the audit log
 * Useful for testing and monitoring
 */
export async function readAuditLog(auditLogPath: string): Promise<AuditLogEntry[]> {
  try {
    const content = await fs.readFile(auditLogPath, 'utf-8');
    const lines = content.trim().split('\n').filter(line => line.length > 0);
    return lines.map(line => JSON.parse(line) as AuditLogEntry);
  } catch (error) {
    console.error('[AuditLog] Failed to read audit log:', error);
    return [];
  }
}

/**
 * Get summary statistics from audit log
 */
export async function getAuditLogStats(auditLogPath: string): Promise<{
  totalCalls: number;
  allowed: number;
  denied: number;
  dryrun: number;
  review: number;
}> {
  const entries = await readAuditLog(auditLogPath);

  const stats = {
    totalCalls: entries.length,
    allowed: entries.filter(e => e.decision === 'allowed').length,
    denied: entries.filter(e => e.decision === 'denied').length,
    dryrun: entries.filter(e => e.decision === 'dryrun').length,
    review: entries.filter(e => e.decision === 'review').length,
  };

  return stats;
}
