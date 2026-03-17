#!/usr/bin/env node

// src/index.ts
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

// src/lib/config.ts
var RESTRICTED_KEYWORDS = [
  // System destructive operations
  "rm",
  "rmdir",
  "del",
  "delete",
  "format",
  "dd",
  "mkfs",
  "shred",
  "wipe",
  // Privilege escalation
  "sudo",
  "su ",
  "chmod 777",
  "chown",
  // Sensitive file paths and patterns
  ".env",
  ".aws/credentials",
  ".ssh/id_rsa",
  "/etc/passwd",
  "secret",
  "token",
  "key",
  "password",
  "apikey",
  "api_key",
  "private_key",
  "github_token",
  "aws_access_key",
  "aws_secret_key",
  // Network dangerous operations
  "wget ",
  "curl ",
  // History/cache clearing
  "clear history",
  "history -c"
];
function loadConfig() {
  const dryRun = process.env.DRY_RUN === "true";
  const verbose = process.env.VERBOSE === "true";
  const auditLogPath = process.env.AUDIT_LOG_PATH || "./audit_log.json";
  return {
    dryRun,
    restrictedKeywords: RESTRICTED_KEYWORDS,
    auditLogPath,
    verbose
  };
}
function logConfigOnStartup(config) {
  console.log("[Config] Safety Gate Configuration:");
  console.log(`  Dry-Run Mode: ${config.dryRun}`);
  console.log(`  Audit Log Path: ${config.auditLogPath}`);
  console.log(`  Restricted Keywords: ${config.restrictedKeywords.length} patterns loaded`);
  console.log(`  Verbose Logging: ${config.verbose}`);
}

// src/lib/policyEngine.ts
function flattenObjectToStrings(obj) {
  const strings = [];
  function traverse(current) {
    if (typeof current === "string") {
      strings.push(current);
    } else if (typeof current === "object" && current !== null) {
      if (Array.isArray(current)) {
        current.forEach(traverse);
      } else {
        Object.values(current).forEach(traverse);
      }
    }
  }
  traverse(obj);
  return strings;
}
function containsRestrictedKeyword(value, restrictedKeywords) {
  const lowerValue = value.toLowerCase();
  const foundKeywords = [];
  for (const keyword of restrictedKeywords) {
    if (lowerValue.includes(keyword.toLowerCase())) {
      foundKeywords.push(keyword);
    }
  }
  return {
    found: foundKeywords.length > 0,
    keywords: foundKeywords
  };
}
function shouldBlockTool(toolName, arguments_, restrictedKeywords) {
  const stringValues = flattenObjectToStrings(arguments_);
  const allBlockedKeywords = [];
  for (const value of stringValues) {
    const { found, keywords } = containsRestrictedKeyword(value, restrictedKeywords);
    if (found) {
      allBlockedKeywords.push(...keywords);
    }
  }
  const uniqueBlockedKeywords = Array.from(new Set(allBlockedKeywords)).sort();
  if (uniqueBlockedKeywords.length > 0) {
    return {
      allowed: false,
      reason: `Blocked: restricted keyword(s) found: ${uniqueBlockedKeywords.join(", ")}`,
      blockedKeywords: uniqueBlockedKeywords
    };
  }
  return {
    allowed: true,
    reason: "Policy check passed"
  };
}
function validateToolArguments(toolName, arguments_) {
  if (typeof arguments_ !== "object" || arguments_ === null) {
    return {
      allowed: false,
      reason: "Invalid arguments: must be an object"
    };
  }
  switch (toolName) {
    case "shell_command":
      if (!("command" in arguments_) || typeof arguments_.command !== "string") {
        return {
          allowed: false,
          reason: "Invalid arguments: shell_command requires 'command' string field"
        };
      }
      break;
    case "write_file":
      if (!("path" in arguments_) || typeof arguments_.path !== "string") {
        return {
          allowed: false,
          reason: "Invalid arguments: write_file requires 'path' string field"
        };
      }
      if (!("content" in arguments_) || typeof arguments_.content !== "string") {
        return {
          allowed: false,
          reason: "Invalid arguments: write_file requires 'content' string field"
        };
      }
      break;
    case "read_file":
      if (!("path" in arguments_) || typeof arguments_.path !== "string") {
        return {
          allowed: false,
          reason: "Invalid arguments: read_file requires 'path' string field"
        };
      }
      break;
  }
  return {
    allowed: true,
    reason: "Arguments validation passed"
  };
}

// src/lib/auditLogger.ts
import { promises as fs } from "fs";
async function ensureAuditLogExists(auditLogPath) {
  try {
    await fs.access(auditLogPath);
  } catch {
    await fs.writeFile(auditLogPath, "", "utf-8");
  }
}
async function logToolCall(entry, auditLogPath, verbose = false) {
  try {
    await ensureAuditLogExists(auditLogPath);
    const jsonLine = JSON.stringify(entry) + "\n";
    await fs.appendFile(auditLogPath, jsonLine, "utf-8");
    if (verbose) {
      console.log(
        `[AuditLog] ${entry.toolName} - ${entry.decision}: ${entry.reason}`
      );
    }
  } catch (error) {
    console.error("[AuditLog] Failed to write audit log:", error);
  }
}

// src/lib/toolWrapper.ts
function wrapToolHandler(toolMetadata, originalHandler, config) {
  return async (arguments_) => {
    const startTime = Date.now();
    const toolName = toolMetadata.name;
    const validationDecision = validateToolArguments(toolName, arguments_);
    if (!validationDecision.allowed) {
      const executionTimeMs = Date.now() - startTime;
      await logToolCall(
        {
          timestamp: (/* @__PURE__ */ new Date()).toISOString(),
          toolName,
          arguments: arguments_,
          decision: "denied",
          reason: validationDecision.reason,
          result: "error",
          executionTimeMs
        },
        config.auditLogPath,
        config.verbose
      );
      return {
        content: [
          {
            type: "text",
            text: `Validation Error: ${validationDecision.reason}`
          }
        ],
        isError: true
      };
    }
    const policyDecision = shouldBlockTool(
      toolName,
      arguments_,
      config.restrictedKeywords
    );
    if (!policyDecision.allowed) {
      const executionTimeMs = Date.now() - startTime;
      await logToolCall(
        {
          timestamp: (/* @__PURE__ */ new Date()).toISOString(),
          toolName,
          arguments: arguments_,
          decision: "denied",
          reason: policyDecision.reason,
          blockedKeywords: policyDecision.blockedKeywords,
          result: "error",
          executionTimeMs
        },
        config.auditLogPath,
        config.verbose
      );
      return {
        content: [
          {
            type: "text",
            text: `Security Policy Violation: ${policyDecision.reason}`
          }
        ],
        isError: true
      };
    }
    if (config.dryRun) {
      const executionTimeMs = Date.now() - startTime;
      await logToolCall(
        {
          timestamp: (/* @__PURE__ */ new Date()).toISOString(),
          toolName,
          arguments: arguments_,
          decision: "dryrun",
          reason: "Dry-Run Mode: Tool execution simulated, not actually executed",
          result: "success",
          executionTimeMs
        },
        config.auditLogPath,
        config.verbose
      );
      return {
        content: [
          {
            type: "text",
            text: `Dry-Run: Tool '${toolName}' would execute with provided arguments (not actually run)`
          }
        ],
        isError: false
      };
    }
    try {
      const result = await originalHandler();
      const executionTimeMs = Date.now() - startTime;
      await logToolCall(
        {
          timestamp: (/* @__PURE__ */ new Date()).toISOString(),
          toolName,
          arguments: arguments_,
          decision: "allowed",
          reason: "Policy check passed - tool executed",
          result: result.isError ? "error" : "success",
          executionTimeMs
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
          timestamp: (/* @__PURE__ */ new Date()).toISOString(),
          toolName,
          arguments: arguments_,
          decision: "allowed",
          reason: `Tool execution error: ${errorMessage}`,
          result: "error",
          executionTimeMs
        },
        config.auditLogPath,
        config.verbose
      );
      return {
        content: [
          {
            type: "text",
            text: `Tool execution error: ${errorMessage}`
          }
        ],
        isError: true
      };
    }
  };
}

// src/index.ts
async function main() {
  const config = loadConfig();
  console.error("[SafetyGate] Initializing Security Middleware...");
  logConfigOnStartup(config);
  const server = new McpServer({
    name: "Safety Gate",
    version: "1.0.0"
  });
  server.tool(
    "shell_command",
    "Execute a shell command (intercepted by Safety Gate)",
    {
      command: z.string().describe("The shell command to execute")
    },
    async (args) => {
      const wrappedHandler = wrapToolHandler(
        {
          name: "shell_command",
          description: "Execute a shell command (intercepted by Safety Gate)"
        },
        async () => {
          const command = args.command;
          return {
            content: [
              {
                type: "text",
                text: `[MOCK] Shell command executed: ${command}
stdout: (simulated output from: ${command})`
              }
            ],
            isError: false
          };
        },
        config
      );
      return wrappedHandler(args);
    }
  );
  server.tool(
    "write_file",
    "Write content to a file (intercepted by Safety Gate)",
    {
      path: z.string().describe("The file path to write to"),
      content: z.string().describe("The content to write")
    },
    async (args) => {
      const wrappedHandler = wrapToolHandler(
        {
          name: "write_file",
          description: "Write content to a file (intercepted by Safety Gate)"
        },
        async () => {
          const { path, content } = args;
          return {
            content: [
              {
                type: "text",
                text: `[MOCK] File written: ${path}
Bytes written: ${content.length}`
              }
            ],
            isError: false
          };
        },
        config
      );
      return wrappedHandler(args);
    }
  );
  server.tool(
    "read_file",
    "Read content from a file (intercepted by Safety Gate)",
    {
      path: z.string().describe("The file path to read from")
    },
    async (args) => {
      const wrappedHandler = wrapToolHandler(
        {
          name: "read_file",
          description: "Read content from a file (intercepted by Safety Gate)"
        },
        async () => {
          const { path } = args;
          return {
            content: [
              {
                type: "text",
                text: `[MOCK] File read: ${path}
Content: (simulated file contents)`
              }
            ],
            isError: false
          };
        },
        config
      );
      return wrappedHandler(args);
    }
  );
  console.error("[SafetyGate] Registered 3 tools with security wrapping");
  console.error("[SafetyGate] Starting stdio transport...");
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("[SafetyGate] Server running - accepting tool calls on stdio");
}
main().catch((error) => {
  console.error("[SafetyGate] Fatal error:", error);
  process.exit(1);
});
