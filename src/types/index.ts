/**
 * Type definitions for Safety Gate MCP Server
 */

export type PolicyEffect = 'allow' | 'deny' | 'review';

export interface PolicyRule {
  id: string;
  effect: PolicyEffect;
  reason: string;
  tools: string[];
  match: {
    keywords?: string[];
    pathSubstrings?: string[];
    commandNames?: string[];
  };
}

export interface SafetyGatePolicy {
  version: number;
  rules: PolicyRule[];
}

export interface PolicyDecision {
  allowed: boolean;
  effect: PolicyEffect;
  reason: string;
  blockedKeywords?: string[];
  ruleId?: string;
}

export interface AuditLogEntry {
  timestamp: string;
  toolName: string;
  arguments: Record<string, unknown>;
  decision: 'allowed' | 'denied' | 'dryrun' | 'review';
  reason: string;
  result?: 'success' | 'error' | 'pending';
  blockedKeywords?: string[];
  executionTimeMs?: number;
  ruleId?: string;
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
  policy: SafetyGatePolicy;
  policyFilePath?: string;
}
