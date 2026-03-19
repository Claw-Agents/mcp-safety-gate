#!/usr/bin/env node

/**
 * Safety Gate - MCP Security Middleware Server
 * Intercepts tool execution requests and applies security policies
 */

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import { loadConfig, logConfigOnStartup } from './lib/config.js';
import { wrapToolHandler } from './lib/toolWrapper.js';
import {
  executeShellCommand,
  readFileSafely,
  writeFileSafely,
} from './lib/realTools.js';

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
