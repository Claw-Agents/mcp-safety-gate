#!/usr/bin/env node

/**
 * Safety Gate - MCP Security Middleware Server
 * Intercepts tool execution requests and applies security policies
 */

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { CallToolResult } from '@modelcontextprotocol/sdk/types.js';
import { z } from 'zod';
import { loadConfig, logConfigOnStartup } from './lib/config.js';
import { wrapToolHandler } from './lib/toolWrapper.js';
import { logToolCall } from './lib/auditLogger.js';
import { sanitizeAuditArguments } from './lib/auditHelpers.js';
import {
  executeShellCommand,
  readFileSafely,
  writeFileSafely,
} from './lib/realTools.js';
import {
  getApprovalRequest,
  listApprovalRequests,
  updateApprovalRequestStatus,
} from './lib/approvalStore.js';
import { authenticateApprover } from './lib/approverAuth.js';
import { ApprovalStatus, SafetyGateConfig } from './types/index.js';

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

async function auditLifecycleEvent(
  config: SafetyGateConfig,
  toolName: string,
  arguments_: Record<string, unknown>,
  options: {
    decision: 'allowed' | 'denied';
    reason: string;
    result: 'success' | 'error';
    lifecycleStage: 'approved' | 'rejected' | 'executed' | 'expired';
    approvalRequestId?: string;
    actor?: string;
    actorAuthenticated?: boolean;
  }
): Promise<void> {
  await logToolCall(
    {
      timestamp: new Date().toISOString(),
      toolName,
      arguments: sanitizeAuditArguments(arguments_),
      decision: options.decision,
      reason: options.reason,
      result: options.result,
      approvalRequestId: options.approvalRequestId,
      lifecycleStage: options.lifecycleStage,
      actor: options.actor,
      actorAuthenticated: options.actorAuthenticated,
    },
    config.auditLogPath,
    config.verbose
  );
}

async function dispatchToolExecution(
  toolName: string,
  args: Record<string, unknown>,
  config: SafetyGateConfig
): Promise<CallToolResult> {
  switch (toolName) {
    case 'shell_command':
      return executeShellCommand((args as { command: string }).command, config);
    case 'write_file': {
      const { path, content } = args as { path: string; content: string };
      return writeFileSafely(path, content, config);
    }
    case 'read_file':
      return readFileSafely((args as { path: string }).path, config);
    default:
      return err(`Unknown tool in approval execution: ${toolName}`);
  }
}

function isApprovalExpired(resolvedAt: string | undefined, ttlSeconds: number): boolean {
  if (!resolvedAt) {
    return false;
  }

  const resolvedMs = new Date(resolvedAt).getTime();
  const nowMs = Date.now();
  return nowMs - resolvedMs > ttlSeconds * 1000;
}

function summarizeApprovalTarget(item: { toolName: string; arguments: Record<string, unknown> }): string {
  switch (item.toolName) {
    case 'write_file':
    case 'read_file':
      return typeof item.arguments.path === 'string'
        ? `path=${item.arguments.path}`
        : 'path=<unknown>';
    case 'shell_command':
      return typeof item.arguments.command === 'string'
        ? `command=${item.arguments.command}`
        : 'command=<unknown>';
    default:
      return JSON.stringify(item.arguments);
  }
}

function formatApprovalRequestDetail(item: {
  id: string;
  status: string;
  toolName: string;
  reason: string;
  createdAt: string;
  resolvedAt?: string;
  arguments: Record<string, unknown>;
  metadata?: {
    approver?: string;
    authenticated?: boolean;
    notes?: string;
    rejectionReason?: string;
    preview?: string;
    executor?: string;
    executorAuthenticated?: boolean;
  };
}): string {
  return [
    `ID: ${item.id}`,
    `Status: ${item.status}`,
    `Tool: ${item.toolName}`,
    `Target: ${summarizeApprovalTarget(item)}`,
    `Reason: ${item.reason}`,
    `Created: ${item.createdAt}`,
    item.resolvedAt ? `Resolved: ${item.resolvedAt}` : undefined,
    item.metadata?.approver ? `Approver: ${item.metadata.approver}` : undefined,
    item.metadata?.authenticated !== undefined
      ? `Authenticated: ${item.metadata.authenticated}`
      : undefined,
    item.metadata?.notes ? `Notes: ${item.metadata.notes}` : undefined,
    item.metadata?.rejectionReason
      ? `Rejection Reason: ${item.metadata.rejectionReason}`
      : undefined,
    item.metadata?.preview ? `Preview:\n${item.metadata.preview}` : undefined,
    item.metadata?.executor ? `Executor: ${item.metadata.executor}` : undefined,
    item.metadata?.executorAuthenticated !== undefined
      ? `Executor Authenticated: ${item.metadata.executorAuthenticated}`
      : undefined,
    `Arguments: ${JSON.stringify(item.arguments, null, 2)}`,
  ]
    .filter(Boolean)
    .join('\n');
}

function formatApprovalRequests(
  status: ApprovalStatus | 'all',
  items: Awaited<ReturnType<typeof listApprovalRequests>>
): string {
  if (items.length === 0) {
    return `No approval requests found for status: ${status}`;
  }

  return items
    .map(item =>
      [
        `ID: ${item.id}`,
        `Status: ${item.status}`,
        `Tool: ${item.toolName}`,
        `Target: ${summarizeApprovalTarget(item)}`,
        `Reason: ${item.reason}`,
        item.metadata?.approver ? `Approver: ${item.metadata.approver}` : undefined,
        item.metadata?.authenticated !== undefined
          ? `Authenticated: ${item.metadata.authenticated}`
          : undefined,
        item.metadata?.executor ? `Executor: ${item.metadata.executor}` : undefined,
        item.metadata?.executorAuthenticated !== undefined
          ? `Executor Authenticated: ${item.metadata.executorAuthenticated}`
          : undefined,
        item.metadata?.notes ? `Notes: ${item.metadata.notes}` : undefined,
      ]
        .filter(Boolean)
        .join('\n')
    )
    .join('\n\n');
}

/**
 * Main server initialization
 */
async function main(): Promise<void> {
  const config = await loadConfig();

  // Log configuration on startup
  console.error('[SafetyGate] Initializing Security Middleware...');
  logConfigOnStartup(config);

  // Create MCP server
  const server = new McpServer({
    name: 'Safety Gate',
    version: '1.0.0',
  });

  // Tool 1: shell_command
  server.tool(
    'shell_command',
    'Execute an allowlisted shell command within configured safe roots',
    {
      command: z.string().describe('The shell command to execute'),
    } as any,
    async (args: any) => {
      const wrappedHandler = wrapToolHandler(
        {
          name: 'shell_command',
          description: 'Execute an allowlisted shell command within configured safe roots',
        },
        async () => executeShellCommand((args as { command: string }).command, config),
        config
      );
      return wrappedHandler(args);
    }
  );

  // Tool 2: write_file
  server.tool(
    'write_file',
    'Write content to a file within configured safe roots',
    {
      path: z.string().describe('The file path to write to'),
      content: z.string().describe('The content to write'),
    } as any,
    async (args: any) => {
      const wrappedHandler = wrapToolHandler(
        {
          name: 'write_file',
          description: 'Write content to a file within configured safe roots',
        },
        async () => {
          const { path, content } = args as { path: string; content: string };
          return writeFileSafely(path, content, config);
        },
        config
      );
      return wrappedHandler(args);
    }
  );

  // Tool 3: read_file
  server.tool(
    'read_file',
    'Read content from a file within configured safe roots',
    {
      path: z.string().describe('The file path to read from'),
    } as any,
    async (args: any) => {
      const wrappedHandler = wrapToolHandler(
        {
          name: 'read_file',
          description: 'Read content from a file within configured safe roots',
        },
        async () => {
          const { path } = args as { path: string };
          return readFileSafely(path, config);
        },
        config
      );
      return wrappedHandler(args);
    }
  );

  // Tool 4: list_approval_requests
  server.tool(
    'list_approval_requests',
    'List approval requests tracked by Safety Gate',
    {
      status: z.enum(['all', 'pending', 'approved', 'rejected', 'executed', 'expired']).optional(),
    } as any,
    async (args: any) => {
      const status = (args?.status ?? 'all') as ApprovalStatus | 'all';
      const requests = await listApprovalRequests(
        config.approvalStorePath,
        status === 'all' ? undefined : status
      );
      return ok(formatApprovalRequests(status, requests));
    }
  );

  // Tool 5: get_approval_request
  server.tool(
    'get_approval_request',
    'Get detailed information for a single approval request',
    {
      requestId: z.string().describe('Approval request ID to inspect'),
    } as any,
    async (args: any) => {
      const requestId = (args as { requestId: string }).requestId;
      const request = await getApprovalRequest(config.approvalStorePath, requestId);
      return request
        ? ok(formatApprovalRequestDetail(request))
        : err(`Approval request not found: ${requestId}`);
    }
  );

  // Tool 6: approve_request
  server.tool(
    'approve_request',
    'Approve a pending review request',
    {
      requestId: z.string().describe('Approval request ID to approve'),
      approver: z.string().optional().describe('Human or system approving the request'),
      authToken: z.string().optional().describe('Approver authentication token when auth mode is enabled'),
      notes: z.string().optional().describe('Optional approval notes'),
    } as any,
    async (args: any) => {
      try {
        const typedArgs = args as {
          requestId: string;
          approver?: string;
          authToken?: string;
          notes?: string;
        };
        const identity = authenticateApprover(typedArgs.approver, typedArgs.authToken, config);
        const request = await updateApprovalRequestStatus(
          config.approvalStorePath,
          typedArgs.requestId,
          'approved',
          {
            approver: identity.approver,
            authenticated: identity.authenticated,
            notes: typedArgs.notes,
          }
        );
        await auditLifecycleEvent(config, 'approve_request', typedArgs, {
          decision: 'allowed',
          reason: `Approval granted for request ${request.id}`,
          result: 'success',
          lifecycleStage: 'approved',
          approvalRequestId: request.id,
          actor: identity.approver,
          actorAuthenticated: identity.authenticated,
        });
        return ok(`Approved request ${request.id} for tool ${request.toolName}`);
      } catch (error) {
        return err(error instanceof Error ? error.message : String(error));
      }
    }
  );

  // Tool 7: reject_request
  server.tool(
    'reject_request',
    'Reject a pending review request',
    {
      requestId: z.string().describe('Approval request ID to reject'),
      approver: z.string().optional().describe('Human or system rejecting the request'),
      authToken: z.string().optional().describe('Approver authentication token when auth mode is enabled'),
      rejectionReason: z.string().optional().describe('Why the request was rejected'),
      notes: z.string().optional().describe('Optional rejection notes'),
    } as any,
    async (args: any) => {
      try {
        const typedArgs = args as {
          requestId: string;
          approver?: string;
          authToken?: string;
          rejectionReason?: string;
          notes?: string;
        };
        const identity = authenticateApprover(typedArgs.approver, typedArgs.authToken, config);
        const request = await updateApprovalRequestStatus(
          config.approvalStorePath,
          typedArgs.requestId,
          'rejected',
          {
            approver: identity.approver,
            authenticated: identity.authenticated,
            rejectionReason: typedArgs.rejectionReason,
            notes: typedArgs.notes,
          }
        );
        await auditLifecycleEvent(config, 'reject_request', typedArgs, {
          decision: 'allowed',
          reason: `Approval rejected for request ${request.id}`,
          result: 'success',
          lifecycleStage: 'rejected',
          approvalRequestId: request.id,
          actor: identity.approver,
          actorAuthenticated: identity.authenticated,
        });
        return ok(`Rejected request ${request.id} for tool ${request.toolName}`);
      } catch (error) {
        return err(error instanceof Error ? error.message : String(error));
      }
    }
  );

  // Tool 8: execute_approved_request
  server.tool(
    'execute_approved_request',
    'Execute a previously approved request',
    {
      requestId: z.string().describe('Approval request ID to execute'),
      executor: z.string().optional().describe('Executor identity for audit trail'),
      authToken: z.string().optional().describe('Executor authentication token when auth mode is enabled'),
    } as any,
    async (args: any) => {
      try {
        const typedArgs = args as {
          requestId: string;
          executor?: string;
          authToken?: string;
        };
        const requestId = typedArgs.requestId;
        const request = await getApprovalRequest(config.approvalStorePath, requestId);

        if (!request) {
          return err(`Approval request not found: ${requestId}`);
        }

        if (request.status !== 'approved') {
          await auditLifecycleEvent(config, 'execute_approved_request', typedArgs, {
            decision: 'denied',
            reason: `Execution blocked because request ${requestId} is in status ${request.status}`,
            result: 'error',
            lifecycleStage: request.status === 'expired' ? 'expired' : 'executed',
            approvalRequestId: requestId,
            actor: typedArgs.executor,
          });
          return err(`Approval request ${requestId} is not approved (current status: ${request.status})`);
        }

        const executorIdentity = authenticateApprover(typedArgs.executor, typedArgs.authToken, config);

        if (isApprovalExpired(request.resolvedAt, config.approvalTtlSeconds)) {
          await updateApprovalRequestStatus(config.approvalStorePath, requestId, 'expired', {
            approver: request.metadata?.approver,
            authenticated: request.metadata?.authenticated,
            notes: request.metadata?.notes,
            rejectionReason: request.metadata?.rejectionReason,
            executor: executorIdentity.approver,
            executorAuthenticated: executorIdentity.authenticated,
          });
          await auditLifecycleEvent(config, 'execute_approved_request', typedArgs, {
            decision: 'denied',
            reason: `Execution blocked because request ${requestId} expired`,
            result: 'error',
            lifecycleStage: 'expired',
            approvalRequestId: requestId,
            actor: executorIdentity.approver,
            actorAuthenticated: executorIdentity.authenticated,
          });
          return err(`Approval request ${requestId} has expired`);
        }

        const result = await dispatchToolExecution(request.toolName, request.arguments, config);
        await updateApprovalRequestStatus(config.approvalStorePath, requestId, 'executed', {
          approver: request.metadata?.approver,
          authenticated: request.metadata?.authenticated,
          notes: request.metadata?.notes,
          rejectionReason: request.metadata?.rejectionReason,
          executor: executorIdentity.approver,
          executorAuthenticated: executorIdentity.authenticated,
        });
        await auditLifecycleEvent(config, 'execute_approved_request', typedArgs, {
          decision: result.isError ? 'denied' : 'allowed',
          reason: result.isError
            ? `Execution failed for request ${requestId}`
            : `Execution completed for request ${requestId}`,
          result: result.isError ? 'error' : 'success',
          lifecycleStage: 'executed',
          approvalRequestId: requestId,
          actor: executorIdentity.approver,
          actorAuthenticated: executorIdentity.authenticated,
        });
        return result;
      } catch (error) {
        return err(error instanceof Error ? error.message : String(error));
      }
    }
  );

  console.error('[SafetyGate] Registered 8 tools with security wrapping and approvals');
  console.error('[SafetyGate] Starting stdio transport...');

  // Start the server
  const transport = new StdioServerTransport();
  await server.connect(transport);

  console.error('[SafetyGate] Server running - accepting tool calls on stdio');
}

// Run the server
main().catch(error => {
  console.error('[SafetyGate] Fatal error:', error);
  process.exit(1);
});
