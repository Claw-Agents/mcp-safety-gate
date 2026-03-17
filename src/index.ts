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

/**
 * Main server initialization
 */
async function main(): Promise<void> {
  const config = loadConfig();

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
    'Execute a shell command (intercepted by Safety Gate)',
    {
      command: z.string().describe('The shell command to execute'),
    } as any,
    async (args: any) => {
      const wrappedHandler = wrapToolHandler(
        {
          name: 'shell_command',
          description: 'Execute a shell command (intercepted by Safety Gate)',
        },
        async () => {
          const command = (args as { command: string }).command;
          return {
            content: [
              {
                type: 'text',
                text: `[MOCK] Shell command executed: ${command}\nstdout: (simulated output from: ${command})`,
              },
            ],
            isError: false,
          } as CallToolResult;
        },
        config
      );
      return wrappedHandler(args);
    }
  );

  // Tool 2: write_file
  server.tool(
    'write_file',
    'Write content to a file (intercepted by Safety Gate)',
    {
      path: z.string().describe('The file path to write to'),
      content: z.string().describe('The content to write'),
    } as any,
    async (args: any) => {
      const wrappedHandler = wrapToolHandler(
        {
          name: 'write_file',
          description: 'Write content to a file (intercepted by Safety Gate)',
        },
        async () => {
          const { path, content } = args as { path: string; content: string };
          return {
            content: [
              {
                type: 'text',
                text: `[MOCK] File written: ${path}\nBytes written: ${content.length}`,
              },
            ],
            isError: false,
          } as CallToolResult;
        },
        config
      );
      return wrappedHandler(args);
    }
  );

  // Tool 3: read_file
  server.tool(
    'read_file',
    'Read content from a file (intercepted by Safety Gate)',
    {
      path: z.string().describe('The file path to read from'),
    } as any,
    async (args: any) => {
      const wrappedHandler = wrapToolHandler(
        {
          name: 'read_file',
          description: 'Read content from a file (intercepted by Safety Gate)',
        },
        async () => {
          const { path } = args as { path: string };
          return {
            content: [
              {
                type: 'text',
                text: `[MOCK] File read: ${path}\nContent: (simulated file contents)`,
              },
            ],
            isError: false,
          } as CallToolResult;
        },
        config
      );
      return wrappedHandler(args);
    }
  );

  console.error('[SafetyGate] Registered 3 tools with security wrapping');
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
