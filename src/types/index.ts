/**
 * Type definitions for Safety Gate MCP Server
 */

export type PolicyEffect = 'allow' | 'deny' | 'review';
export type ApprovalStatus = 'pending' | 'approved' | 'rejected' | 'executed';
export type ApproverAuthMode = 'off' | 'token';

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

export interface ApproverConfigEntry {
  id: string;
  tokenEnv: string;
}

export interface ApproverAuthConfig {
  version: number;
  approvers: ApproverConfigEntry[];
}

export interface ApprovalRequestMetadata {
  approver?: string;
  notes?: string;
  rejectionReason?: string;
  authenticated?: boolean;
}

export interface ApprovalRequest {
  id: string;
  toolName: string;
  arguments: Record<string, unknown>;
  reason: string;
  ruleId?: string;
  status: ApprovalStatus;
  createdAt: string;
  resolvedAt?: string;
  metadata?: ApprovalRequestMetadata;
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
  approvalRequestId?: string;
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
  approvalStorePath: string;
  approverAuthMode: ApproverAuthMode;
  approverAuthFilePath?: string;
  approverAuth?: ApproverAuthConfig;
}
