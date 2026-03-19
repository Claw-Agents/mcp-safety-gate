#!/usr/bin/env node

// src/index.ts
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

// src/lib/config.ts
import path from "path";
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
var DEFAULT_SHELL_ALLOWED_COMMANDS = [
  "pwd",
  "ls",
  "cat",
  "head",
  "tail",
  "wc",
  "find",
  "grep",
  "which",
  "echo"
];
function parseListEnv(value, fallback) {
  if (!value || value.trim().length === 0) {
    return fallback;
  }
  return value.split(",").map((part) => part.trim()).filter(Boolean);
}
function parseNumberEnv(value, fallback) {
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}
function loadConfig() {
  const dryRun = process.env.DRY_RUN === "true";
  const verbose = process.env.VERBOSE === "true";
  const auditLogPath = process.env.AUDIT_LOG_PATH || "./audit_log.json";
  const allowedPaths = parseListEnv(process.env.ALLOWED_PATHS, [process.cwd()]).map(
    (entry) => path.resolve(entry)
  );
  const shellAllowedCommands = parseListEnv(
    process.env.SHELL_ALLOWED_COMMANDS,
    DEFAULT_SHELL_ALLOWED_COMMANDS
  ).map((command) => command.toLowerCase());
  return {
    dryRun,
    restrictedKeywords: RESTRICTED_KEYWORDS,
    auditLogPath,
    verbose,
    allowedPaths,
    shellAllowedCommands,
    maxFileReadBytes: parseNumberEnv(process.env.MAX_FILE_READ_BYTES, 1024 * 1024),
    maxFileWriteBytes: parseNumberEnv(process.env.MAX_FILE_WRITE_BYTES, 256 * 1024),
    shellCommandTimeoutMs: parseNumberEnv(process.env.SHELL_COMMAND_TIMEOUT_MS, 5e3)
  };
}
function logConfigOnStartup(config) {
  console.log("[Config] Safety Gate Configuration:");
  console.log(`  Dry-Run Mode: ${config.dryRun}`);
  console.log(`  Audit Log Path: ${config.auditLogPath}`);
  console.log(`  Allowed Paths: ${config.allowedPaths.join(", ")}`);
  console.log(`  Shell Allowed Commands: ${config.shellAllowedCommands.join(", ")}`);
  console.log(`  Max File Read Bytes: ${config.maxFileReadBytes}`);
  console.log(`  Max File Write Bytes: ${config.maxFileWriteBytes}`);
  console.log(`  Shell Command Timeout (ms): ${config.shellCommandTimeoutMs}`);
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

// src/lib/realTools.ts
import { promises as fs3 } from "fs";
import { execFile } from "child_process";
import { promisify } from "util";

// src/lib/fsPolicy.ts
import path2 from "path";
import { promises as fs2 } from "fs";
function isPathWithinAllowedRoots(targetPath, allowedRoots) {
  const resolvedTarget = path2.resolve(targetPath);
  return allowedRoots.some((root) => {
    const resolvedRoot = path2.resolve(root);
    const relative = path2.relative(resolvedRoot, resolvedTarget);
    return relative === "" || !relative.startsWith("..") && !path2.isAbsolute(relative);
  });
}
function assertPathAllowed(targetPath, allowedRoots) {
  const resolvedTarget = path2.resolve(targetPath);
  if (!isPathWithinAllowedRoots(resolvedTarget, allowedRoots)) {
    throw new Error(
      `Path is outside allowed roots: ${resolvedTarget}. Allowed roots: ${allowedRoots.join(", ")}`
    );
  }
  return resolvedTarget;
}
async function ensureParentDirectory(targetPath) {
  await fs2.mkdir(path2.dirname(targetPath), { recursive: true });
}

// src/lib/realTools.ts
var execFileAsync = promisify(execFile);
var SHELL_META_PATTERN = /[|&;><`$\\]/;
function ok(text) {
  return {
    content: [{ type: "text", text }],
    isError: false
  };
}
function err(text) {
  return {
    content: [{ type: "text", text }],
    isError: true
  };
}
function tokenizeCommand(command) {
  const trimmed = command.trim();
  if (!trimmed) {
    throw new Error("Command cannot be empty");
  }
  if (SHELL_META_PATTERN.test(trimmed)) {
    throw new Error("Shell metacharacters are not allowed");
  }
  const tokens = trimmed.match(/"[^"]*"|'[^']*'|\S+/g) ?? [];
  return tokens.map((token) => token.replace(/^['"]|['"]$/g, ""));
}
function assertAllowedCommand(commandName, config) {
  if (!config.shellAllowedCommands.includes(commandName.toLowerCase())) {
    throw new Error(
      `Command '${commandName}' is not in the allowed shell command list: ${config.shellAllowedCommands.join(", ")}`
    );
  }
}
function assertSafePathTokens(tokens, config) {
  for (const token of tokens) {
    if (token.startsWith("-")) {
      continue;
    }
    const looksLikePath = token.startsWith("/") || token.startsWith("./") || token.startsWith("../") || token.includes("/");
    if (looksLikePath) {
      assertPathAllowed(token, config.allowedPaths);
    }
  }
}
async function executeShellCommand(command, config) {
  try {
    const tokens = tokenizeCommand(command);
    const [commandName, ...args] = tokens;
    if (!commandName) {
      throw new Error("Command cannot be empty");
    }
    assertAllowedCommand(commandName, config);
    assertSafePathTokens(args, config);
    const { stdout, stderr } = await execFileAsync(commandName, args, {
      cwd: config.allowedPaths[0],
      timeout: config.shellCommandTimeoutMs,
      maxBuffer: config.maxFileReadBytes
    });
    const output = [
      `Command: ${command}`,
      `Exit: 0`,
      stdout ? `STDOUT:
${stdout}` : "STDOUT: <empty>",
      stderr ? `STDERR:
${stderr}` : "STDERR: <empty>"
    ].join("\n");
    return ok(output);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return err(`Shell command rejected or failed: ${message}`);
  }
}
async function writeFileSafely(targetPath, content, config) {
  try {
    const resolvedPath = assertPathAllowed(targetPath, config.allowedPaths);
    const byteLength = Buffer.byteLength(content, "utf-8");
    if (byteLength > config.maxFileWriteBytes) {
      throw new Error(
        `Content exceeds MAX_FILE_WRITE_BYTES (${config.maxFileWriteBytes} bytes)`
      );
    }
    await ensureParentDirectory(resolvedPath);
    await fs3.writeFile(resolvedPath, content, "utf-8");
    return ok(`File written: ${resolvedPath}
Bytes written: ${byteLength}`);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return err(`Write failed: ${message}`);
  }
}
async function readFileSafely(targetPath, config) {
  try {
    const resolvedPath = assertPathAllowed(targetPath, config.allowedPaths);
    const stats = await fs3.stat(resolvedPath);
    if (stats.size > config.maxFileReadBytes) {
      throw new Error(`File exceeds MAX_FILE_READ_BYTES (${config.maxFileReadBytes} bytes)`);
    }
    const content = await fs3.readFile(resolvedPath, "utf-8");
    return ok(`File read: ${resolvedPath}
Content:
${content}`);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return err(`Read failed: ${message}`);
  }
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
    "Execute an allowlisted shell command within configured safe roots",
    {
      command: z.string().describe("The shell command to execute")
    },
    async (args) => {
      const wrappedHandler = wrapToolHandler(
        {
          name: "shell_command",
          description: "Execute an allowlisted shell command within configured safe roots"
        },
        async () => executeShellCommand(args.command, config),
        config
      );
      return wrappedHandler(args);
    }
  );
  server.tool(
    "write_file",
    "Write content to a file within configured safe roots",
    {
      path: z.string().describe("The file path to write to"),
      content: z.string().describe("The content to write")
    },
    async (args) => {
      const wrappedHandler = wrapToolHandler(
        {
          name: "write_file",
          description: "Write content to a file within configured safe roots"
        },
        async () => {
          const { path: path3, content } = args;
          return writeFileSafely(path3, content, config);
        },
        config
      );
      return wrappedHandler(args);
    }
  );
  server.tool(
    "read_file",
    "Read content from a file within configured safe roots",
    {
      path: z.string().describe("The file path to read from")
    },
    async (args) => {
      const wrappedHandler = wrapToolHandler(
        {
          name: "read_file",
          description: "Read content from a file within configured safe roots"
        },
        async () => {
          const { path: path3 } = args;
          return readFileSafely(path3, config);
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
