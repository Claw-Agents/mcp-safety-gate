/**
 * Type definitions for Safety Gate MCP Server
 */

export interface PolicyDecision {
  allowed: boolean;
  reason: string;
  blockedKeywords?: string[];
}

export interface AuditLogEntry {
  timestamp: string;
  toolName: string;
  arguments: Record<string, unknown>;
  decision: 'allowed' | 'denied' | 'dryrun';
  reason: string;
  result?: 'success' | 'error' | 'pending';
  blockedKeywords?: string[];
  executionTimeMs?: number;
}

export interface ToolHandlerContext {
  toolName: string;
  arguments: Record<string, unknown>;
  startTime: number;
}

export interface SafetyGateConfig {
  dryRun: boolean;
  restrictedKeywords: string[];
  auditLogPath: string;
  verbose: boolean;
  allowedPaths: string[];
  shellAllowedCommands: string[];
  maxFileReadBytes: number;
  maxFileWriteBytes: number;
  shellCommandTimeoutMs: number;
}
