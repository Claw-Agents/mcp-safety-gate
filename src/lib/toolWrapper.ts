/**
 * Tool Handler Wrapper
 * Wraps MCP tool handlers with security checks and audit logging
 */

import { CallToolResult } from '@modelcontextprotocol/sdk/types.js';
import { evaluateToolPolicy, validateToolArguments } from './policyEngine.js';
import { logToolCall } from './auditLogger.js';
import { createApprovalRequest } from './approvalStore.js';
import { sanitizeAuditArguments } from './auditHelpers.js';
import { buildWriteFilePreview } from './writePreview.js';
import { SafetyGateConfig } from '../types/index.js';

export type ToolMetadata = {
  name: string;
  description: string;
};

export type ToolHandler = () => Promise<CallToolResult>;

/**
 * Wrap a tool handler with security checks and audit logging
 */
export function wrapToolHandler(
  toolMetadata: ToolMetadata,
  originalHandler: ToolHandler,
  config: SafetyGateConfig
): (args: Record<string, unknown>) => Promise<CallToolResult> {
  return async (arguments_: Record<string, unknown>): Promise<CallToolResult> => {
    const startTime = Date.now();
    const toolName = toolMetadata.name;
    const sanitizedArguments = sanitizeAuditArguments(arguments_);

    // Step 1: Validate arguments structure
    const validationDecision = validateToolArguments(toolName, arguments_);
    if (!validationDecision.allowed) {
      const executionTimeMs = Date.now() - startTime;
      await logToolCall(
        {
          timestamp: new Date().toISOString(),
          toolName,
          arguments: sanitizedArguments,
          decision: 'denied',
          reason: validationDecision.reason,
          result: 'error',
          executionTimeMs,
          ruleId: validationDecision.ruleId,
        },
        config.auditLogPath,
        config.verbose
      );

      return {
        content: [
          {
            type: 'text',
            text: `Validation Error: ${validationDecision.reason}`,
          },
        ],
        isError: true,
      };
    }

    // Step 2: Check structured policy
    const policyDecision = evaluateToolPolicy(toolName, arguments_, config.policy);

    if (policyDecision.effect === 'deny') {
      const executionTimeMs = Date.now() - startTime;
      await logToolCall(
        {
          timestamp: new Date().toISOString(),
          toolName,
          arguments: sanitizedArguments,
          decision: 'denied',
          reason: policyDecision.reason,
          blockedKeywords: policyDecision.blockedKeywords,
          result: 'error',
          executionTimeMs,
          ruleId: policyDecision.ruleId,
        },
        config.auditLogPath,
        config.verbose
      );

      return {
        content: [
          {
            type: 'text',
            text: `Security Policy Violation: ${policyDecision.reason}`,
          },
        ],
        isError: true,
      };
    }

    if (policyDecision.effect === 'review') {
      const preview =
        toolName === 'write_file' &&
        typeof arguments_.path === 'string' &&
        typeof arguments_.content === 'string'
          ? await buildWriteFilePreview(arguments_.path, arguments_.content, config.allowedPaths)
          : undefined;

      const approvalRequest = await createApprovalRequest(config.approvalStorePath, {
        toolName,
        arguments: arguments_,
        reason: policyDecision.reason,
        ruleId: policyDecision.ruleId,
        metadata: preview ? { preview } : undefined,
      });

      const executionTimeMs = Date.now() - startTime;
      await logToolCall(
        {
          timestamp: new Date().toISOString(),
          toolName,
          arguments: sanitizedArguments,
          decision: 'review',
          reason: policyDecision.reason,
          blockedKeywords: policyDecision.blockedKeywords,
          result: 'pending',
          executionTimeMs,
          ruleId: policyDecision.ruleId,
          approvalRequestId: approvalRequest.id,
          lifecycleStage: 'review-created',
        },
        config.auditLogPath,
        config.verbose
      );

      return {
        content: [
          {
            type: 'text',
            text: `Review Required: ${policyDecision.reason}\nApproval Request ID: ${approvalRequest.id}`,
          },
        ],
        isError: true,
      };
    }

    // Step 3: Dry-run mode check
    if (config.dryRun) {
      const executionTimeMs = Date.now() - startTime;
      await logToolCall(
        {
          timestamp: new Date().toISOString(),
          toolName,
          arguments: sanitizedArguments,
          decision: 'dryrun',
          reason: 'Dry-Run Mode: Tool execution simulated, not actually run',
          result: 'success',
          executionTimeMs,
        },
        config.auditLogPath,
        config.verbose
      );

      return {
        content: [
          {
            type: 'text',
            text: `Dry-Run: Tool '${toolName}' would execute with provided arguments (not actually run)`,
          },
        ],
        isError: false,
      };
    }

    // Step 4: Execute the tool (normal path)
    try {
      const result = await originalHandler();
      const executionTimeMs = Date.now() - startTime;

      await logToolCall(
        {
          timestamp: new Date().toISOString(),
          toolName,
          arguments: sanitizedArguments,
          decision: 'allowed',
          reason: 'Policy check passed - tool executed',
          result: result.isError ? 'error' : 'success',
          executionTimeMs,
        },
        config.auditLogPath,
        config.verbose
      );

      return result;
    } catch (error) {
      const executionTimeMs = Date.now() - startTime;
      const errorMessage = error instanceof Error ? error.message : String(error);

      await logToolCall(
        {
          timestamp: new Date().toISOString(),
          toolName,
          arguments: sanitizedArguments,
          decision: 'allowed',
          reason: `Tool execution error: ${errorMessage}`,
          result: 'error',
          executionTimeMs,
        },
        config.auditLogPath,
        config.verbose
      );

      return {
        content: [
          {
            type: 'text',
            text: `Tool execution error: ${errorMessage}`,
          },
        ],
        isError: true,
      };
    }
  };
}
